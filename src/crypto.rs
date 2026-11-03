use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params, SharedKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub const MLKEM768_DK_LEN: usize = 2400;
pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const X25519_KEY_LEN: usize = 32;

pub const PRIVATE_KEY_LEN: usize = MLKEM768_DK_LEN + X25519_KEY_LEN; // 2432
pub const PUBLIC_KEY_LEN: usize = MLKEM768_EK_LEN + X25519_KEY_LEN; // 1216
pub const KEY_ID_LEN: usize = 32;

const PROTOCOL_VERSION: u8 = 0x01;
const HANDSHAKE_TIME_WINDOW_SECS: u64 = 300;
const AEAD_TAG_LEN: usize = 16;
const MAX_FRAME_PAYLOAD_LEN: usize = 64 * 1024;

pub type KeyId = [u8; KEY_ID_LEN];

#[derive(Clone)]
pub struct ClientKeyPair {
    dk: DecapsulationKey<MlKem768Params>,
    ek: EncapsulationKey<MlKem768Params>,
    x25519_sk: X25519StaticSecret,
    x25519_pk: X25519PublicKey,
    key_id: KeyId,
}

#[derive(Clone)]
pub struct AuthorizedPublicKey {
    ek: EncapsulationKey<MlKem768Params>,
    x25519_pk: X25519PublicKey,
    key_id: KeyId,
    raw_bytes: Vec<u8>,
}

impl std::fmt::Debug for ClientKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKeyPair")
            .field("key_id", &hex_short(&self.key_id))
            .finish()
    }
}

impl std::fmt::Debug for AuthorizedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedPublicKey")
            .field("key_id", &hex_short(&self.key_id))
            .finish()
    }
}

pub fn key_id_hex(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

fn hex_short(bytes: &[u8]) -> String {
    key_id_hex(bytes)
}

pub fn generate_keypair() -> (String, String) {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let x25519_sk = X25519StaticSecret::random_from_rng(&mut rng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    let mut priv_bytes = Vec::with_capacity(PRIVATE_KEY_LEN);
    priv_bytes.extend_from_slice(dk.as_bytes().as_slice());
    priv_bytes.extend_from_slice(&x25519_sk.to_bytes());

    let mut pub_bytes = Vec::with_capacity(PUBLIC_KEY_LEN);
    pub_bytes.extend_from_slice(ek.as_bytes().as_slice());
    pub_bytes.extend_from_slice(x25519_pk.as_bytes());

    (
        URL_SAFE_NO_PAD.encode(&priv_bytes),
        URL_SAFE_NO_PAD.encode(&pub_bytes),
    )
}

impl ClientKeyPair {
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let raw = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .context("invalid base64url encoding for mlkem768x25519 private key")?;
        if raw.len() != PRIVATE_KEY_LEN {
            bail!(
                "invalid mlkem768x25519 private key length: expected {}, got {}",
                PRIVATE_KEY_LEN,
                raw.len()
            );
        }

        let dk_slice = &raw[..MLKEM768_DK_LEN];
        let sk_slice = &raw[MLKEM768_DK_LEN..PRIVATE_KEY_LEN];

        let dk_encoded = Encoded::<DecapsulationKey<MlKem768Params>>::try_from(dk_slice)
            .map_err(|_| anyhow!("failed to parse ML-KEM-768 decapsulation key"))?;
        let dk = DecapsulationKey::<MlKem768Params>::from_bytes(&dk_encoded);
        let ek = dk.encapsulation_key().clone();

        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(sk_slice);
        let x25519_sk = X25519StaticSecret::from(sk_arr);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        let mut pub_bytes = Vec::with_capacity(PUBLIC_KEY_LEN);
        pub_bytes.extend_from_slice(ek.as_bytes().as_slice());
        pub_bytes.extend_from_slice(x25519_pk.as_bytes());

        let key_id: KeyId = Sha256::digest(&pub_bytes).into();

        Ok(Self {
            dk,
            ek,
            x25519_sk,
            x25519_pk,
            key_id,
        })
    }

    pub fn public_key_base64(&self) -> String {
        let mut pub_bytes = Vec::with_capacity(PUBLIC_KEY_LEN);
        pub_bytes.extend_from_slice(self.ek.as_bytes().as_slice());
        pub_bytes.extend_from_slice(self.x25519_pk.as_bytes());
        URL_SAFE_NO_PAD.encode(&pub_bytes)
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

impl AuthorizedPublicKey {
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let raw = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .context("invalid base64url encoding for mlkem768x25519 public key")?;
        if raw.len() != PUBLIC_KEY_LEN {
            bail!(
                "invalid mlkem768x25519 public key length: expected {}, got {}",
                PUBLIC_KEY_LEN,
                raw.len()
            );
        }

        let ek_slice = &raw[..MLKEM768_EK_LEN];
        let pk_slice = &raw[MLKEM768_EK_LEN..PUBLIC_KEY_LEN];

        let ek_encoded = Encoded::<EncapsulationKey<MlKem768Params>>::try_from(ek_slice)
            .map_err(|_| anyhow!("failed to parse ML-KEM-768 encapsulation key"))?;
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_encoded);

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(pk_slice);
        let x25519_pk = X25519PublicKey::from(pk_arr);

        let key_id: KeyId = Sha256::digest(&raw).into();

        Ok(Self {
            ek,
            x25519_pk,
            key_id,
            raw_bytes: raw,
        })
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.raw_bytes)
    }
}

#[derive(Clone, Default)]
pub struct ServerAuthorizer {
    keys: Arc<HashMap<KeyId, AuthorizedPublicKey>>,
}

impl ServerAuthorizer {
    pub fn new(encoded_keys: &[String]) -> Result<Self> {
        let mut map = HashMap::with_capacity(encoded_keys.len());
        for k in encoded_keys {
            let parsed = AuthorizedPublicKey::from_base64(k)?;
            map.insert(*parsed.key_id(), parsed);
        }
        Ok(Self {
            keys: Arc::new(map),
        })
    }

    pub fn get(&self, key_id: &KeyId) -> Option<&AuthorizedPublicKey> {
        self.keys.get(key_id)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Derive directional ChaCha20-Poly1305 keys and verify tokens using HKDF-SHA256
/// combining ML-KEM-768 shared secret, static-ephemeral X25519 shared secret,
/// and ephemeral-ephemeral X25519 shared secret (mlkem768x25519plus design).
fn derive_session_keys(
    ss_kem: &[u8],
    ss_static: &[u8],
    ss_eph: &[u8],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    key_id: &KeyId,
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let mut ikm = Vec::with_capacity(32 * 3);
    ikm.extend_from_slice(ss_kem);
    ikm.extend_from_slice(ss_static);
    ikm.extend_from_slice(ss_eph);

    let mut salt = Vec::with_capacity(32 * 3);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    salt.extend_from_slice(key_id);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut c2s_key = [0u8; 32];
    let mut s2c_key = [0u8; 32];
    let mut server_verify = [0u8; 32];
    let mut client_verify = [0u8; 32];

    hk.expand(b"rrp-mlkem768x25519plus-c2s-key", &mut c2s_key)
        .expect("hkdf expand c2s_key");
    hk.expand(b"rrp-mlkem768x25519plus-s2c-key", &mut s2c_key)
        .expect("hkdf expand s2c_key");
    hk.expand(b"rrp-mlkem768x25519plus-server-verify", &mut server_verify)
        .expect("hkdf expand server_verify");
    hk.expand(b"rrp-mlkem768x25519plus-client-verify", &mut client_verify)
        .expect("hkdf expand client_verify");

    (c2s_key, s2c_key, server_verify, client_verify)
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_padding() -> Vec<u8> {
    let mut rng = OsRng;
    let mut len_byte = [0u8; 1];
    rng.fill_bytes(&mut len_byte);
    // 16..=128 bytes of random obfuscation padding (mlkem768x25519plus style)
    let pad_len = 16 + (len_byte[0] as usize % 113);
    let mut pad = vec![0u8; pad_len];
    rng.fill_bytes(&mut pad);
    pad
}

fn make_nonce(seq: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    *Nonce::from_slice(&nonce)
}

/// Perform client-side mlkem768x25519plus post-quantum handshake over `stream`.
pub async fn client_handshake<S>(mut stream: S, keypair: &ClientKeyPair) -> Result<EncryptedStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut rng = OsRng;
    let client_eph_sk = EphemeralSecret::random_from_rng(&mut rng);
    let client_eph_pk = X25519PublicKey::from(&client_eph_sk);

    let mut client_nonce = [0u8; 32];
    rng.fill_bytes(&mut client_nonce);
    let timestamp = current_unix_secs();
    let pad = random_padding();

    // ClientHello:
    // version(1) || key_id(32) || client_eph_pk(32) || client_nonce(32) || timestamp(8) || pad_len(2) || pad
    let mut hello = BytesMut::with_capacity(1 + 32 + 32 + 32 + 8 + 2 + pad.len());
    hello.put_u8(PROTOCOL_VERSION);
    hello.put_slice(&keypair.key_id);
    hello.put_slice(client_eph_pk.as_bytes());
    hello.put_slice(&client_nonce);
    hello.put_u64(timestamp);
    hello.put_u16(pad.len() as u16);
    hello.put_slice(&pad);

    stream.write_all(&hello).await?;
    stream.flush().await?;

    // Read ServerHello header:
    // kem_ct(1088) || server_eph_pk(32) || server_nonce(32) || pad_len(2)
    let mut sh_fixed = [0u8; MLKEM768_CT_LEN + 32 + 32 + 2];
    stream
        .read_exact(&mut sh_fixed)
        .await
        .context("failed to read ServerHello")?;

    let ct_slice = &sh_fixed[..MLKEM768_CT_LEN];
    let server_eph_slice = &sh_fixed[MLKEM768_CT_LEN..MLKEM768_CT_LEN + 32];
    let server_nonce_slice = &sh_fixed[MLKEM768_CT_LEN + 32..MLKEM768_CT_LEN + 64];
    let sh_pad_len = u16::from_be_bytes([
        sh_fixed[MLKEM768_CT_LEN + 64],
        sh_fixed[MLKEM768_CT_LEN + 65],
    ]) as usize;

    if sh_pad_len > 512 {
        bail!("ServerHello padding length exceeds maximum allowed (512)");
    }

    // Read padding + AEAD verify token (32 + 16 = 48 bytes)
    let mut sh_tail = vec![0u8; sh_pad_len + 32 + AEAD_TAG_LEN];
    stream
        .read_exact(&mut sh_tail)
        .await
        .context("failed to read ServerHello tail")?;

    let verify_ciphertext = &sh_tail[sh_pad_len..];

    let ct = Ciphertext::<MlKem768>::try_from(ct_slice)
        .map_err(|_| anyhow!("invalid ML-KEM-768 ciphertext slice"))?;
    let ss_kem = keypair
        .dk
        .decapsulate(&ct)
        .map_err(|_| anyhow!("ML-KEM-768 decapsulation failed"))?;

    let mut server_eph_arr = [0u8; 32];
    server_eph_arr.copy_from_slice(server_eph_slice);
    let server_eph_pk = X25519PublicKey::from(server_eph_arr);

    let ss_static = keypair.x25519_sk.diffie_hellman(&server_eph_pk);
    let ss_eph = client_eph_sk.diffie_hellman(&server_eph_pk);

    let mut server_nonce = [0u8; 32];
    server_nonce.copy_from_slice(server_nonce_slice);

    let (c2s_key, s2c_key, expected_server_verify, client_verify) = derive_session_keys(
        ss_kem.as_slice(),
        ss_static.as_bytes(),
        ss_eph.as_bytes(),
        &client_nonce,
        &server_nonce,
        &keypair.key_id,
    );

    let s2c_cipher = ChaCha20Poly1305::new(Key::from_slice(&s2c_key));
    let decrypted_verify = s2c_cipher
        .decrypt(&make_nonce(0), verify_ciphertext)
        .map_err(|_| anyhow!("ServerHello authentication tag verification failed"))?;

    if decrypted_verify.as_slice() != expected_server_verify.as_slice() {
        bail!("ServerHello verification token mismatch");
    }

    // Send ClientFinish: pad_len(2) || pad || AEAD(c2s_key, nonce=0, client_verify)
    let c2s_cipher = ChaCha20Poly1305::new(Key::from_slice(&c2s_key));
    let encrypted_client_verify = c2s_cipher
        .encrypt(&make_nonce(0), client_verify.as_slice())
        .map_err(|_| anyhow!("failed to encrypt ClientFinish verify token"))?;

    let finish_pad = random_padding();
    let mut finish_msg = BytesMut::with_capacity(2 + finish_pad.len() + encrypted_client_verify.len());
    finish_msg.put_u16(finish_pad.len() as u16);
    finish_msg.put_slice(&finish_pad);
    finish_msg.put_slice(&encrypted_client_verify);

    stream.write_all(&finish_msg).await?;
    stream.flush().await?;

    Ok(EncryptedStream::new(stream, c2s_cipher, s2c_cipher))
}

/// Perform server-side mlkem768x25519plus post-quantum handshake and authenticate client.
/// Returns the authenticated `EncryptedStream` and the matched client `KeyId`.
pub async fn server_handshake<S>(
    mut stream: S,
    authorizer: &ServerAuthorizer,
) -> Result<(EncryptedStream<S>, KeyId)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read ClientHello fixed header:
    // version(1) || key_id(32) || client_eph_pk(32) || client_nonce(32) || timestamp(8) || pad_len(2) = 107 bytes
    let mut ch_fixed = [0u8; 1 + 32 + 32 + 32 + 8 + 2];
    stream
        .read_exact(&mut ch_fixed)
        .await
        .context("failed to read ClientHello header")?;

    let version = ch_fixed[0];
    if version != PROTOCOL_VERSION {
        bail!("unsupported protocol version: {}", version);
    }

    let mut key_id = [0u8; KEY_ID_LEN];
    key_id.copy_from_slice(&ch_fixed[1..33]);

    let mut client_eph_arr = [0u8; 32];
    client_eph_arr.copy_from_slice(&ch_fixed[33..65]);
    let client_eph_pk = X25519PublicKey::from(client_eph_arr);

    let mut client_nonce = [0u8; 32];
    client_nonce.copy_from_slice(&ch_fixed[65..97]);

    let timestamp = u64::from_be_bytes(ch_fixed[97..105].try_into().unwrap());
    let pad_len = u16::from_be_bytes([ch_fixed[105], ch_fixed[106]]) as usize;

    if pad_len > 512 {
        bail!("ClientHello padding length exceeds maximum allowed (512)");
    }

    let mut pad_buf = vec![0u8; pad_len];
    stream
        .read_exact(&mut pad_buf)
        .await
        .context("failed to read ClientHello padding")?;

    let now = current_unix_secs();
    if now.abs_diff(timestamp) > HANDSHAKE_TIME_WINDOW_SECS {
        bail!("ClientHello timestamp out of acceptable window");
    }

    let auth_key = authorizer
        .get(&key_id)
        .ok_or_else(|| anyhow!("unauthorized client key_id (public key not approved)"))?;

    let mut rng = OsRng;
    let (kem_ct, ss_kem): (Ciphertext<MlKem768>, SharedKey<MlKem768>) = auth_key
        .ek
        .encapsulate(&mut rng)
        .map_err(|_| anyhow!("ML-KEM-768 encapsulation failed"))?;

    let mut server_eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut server_eph_bytes);
    let server_eph_sk = X25519StaticSecret::from(server_eph_bytes);
    let server_eph_pk = X25519PublicKey::from(&server_eph_sk);

    let ss_static = server_eph_sk.diffie_hellman(&auth_key.x25519_pk);
    let ss_eph = server_eph_sk.diffie_hellman(&client_eph_pk);

    let mut server_nonce = [0u8; 32];
    rng.fill_bytes(&mut server_nonce);

    let (c2s_key, s2c_key, server_verify, expected_client_verify) = derive_session_keys(
        ss_kem.as_slice(),
        ss_static.as_bytes(),
        ss_eph.as_bytes(),
        &client_nonce,
        &server_nonce,
        &key_id,
    );

    let s2c_cipher = ChaCha20Poly1305::new(Key::from_slice(&s2c_key));
    let c2s_cipher = ChaCha20Poly1305::new(Key::from_slice(&c2s_key));

    let encrypted_server_verify = s2c_cipher
        .encrypt(&make_nonce(0), server_verify.as_slice())
        .map_err(|_| anyhow!("failed to encrypt ServerHello verify token"))?;

    let sh_pad = random_padding();
    let mut sh_msg = BytesMut::with_capacity(
        MLKEM768_CT_LEN + 32 + 32 + 2 + sh_pad.len() + encrypted_server_verify.len(),
    );
    sh_msg.put_slice(kem_ct.as_slice());
    sh_msg.put_slice(server_eph_pk.as_bytes());
    sh_msg.put_slice(&server_nonce);
    sh_msg.put_u16(sh_pad.len() as u16);
    sh_msg.put_slice(&sh_pad);
    sh_msg.put_slice(&encrypted_server_verify);

    stream.write_all(&sh_msg).await?;
    stream.flush().await?;

    // Read ClientFinish: pad_len(2) || pad || encrypted_client_verify(48)
    let mut cf_pad_len_buf = [0u8; 2];
    stream
        .read_exact(&mut cf_pad_len_buf)
        .await
        .context("failed to read ClientFinish header")?;
    let cf_pad_len = u16::from_be_bytes(cf_pad_len_buf) as usize;
    if cf_pad_len > 512 {
        bail!("ClientFinish padding length exceeds maximum allowed (512)");
    }

    let mut cf_tail = vec![0u8; cf_pad_len + 32 + AEAD_TAG_LEN];
    stream
        .read_exact(&mut cf_tail)
        .await
        .context("failed to read ClientFinish body")?;

    let client_verify_ct = &cf_tail[cf_pad_len..];
    let decrypted_client_verify = c2s_cipher
        .decrypt(&make_nonce(0), client_verify_ct)
        .map_err(|_| anyhow!("ClientFinish authentication tag verification failed"))?;

    if decrypted_client_verify.as_slice() != expected_client_verify.as_slice() {
        bail!("ClientFinish verification token mismatch");
    }

    Ok((EncryptedStream::new(stream, s2c_cipher, c2s_cipher), key_id))
}

/// High-performance AEAD encrypted stream supporting both framed messages and `AsyncRead`/`AsyncWrite`.
pub struct EncryptedStream<S> {
    inner: S,
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    tx_seq: u64,
    rx_seq: u64,
    read_wire_buf: BytesMut,
    read_plain_buf: BytesMut,
    write_wire_buf: BytesMut,
}

impl<S> EncryptedStream<S> {
    pub fn new(inner: S, tx_cipher: ChaCha20Poly1305, rx_cipher: ChaCha20Poly1305) -> Self {
        Self {
            inner,
            tx_cipher,
            rx_cipher,
            // Nonce 0 is used during handshake verification; data frames start at sequence 1.
            tx_seq: 1,
            rx_seq: 1,
            read_wire_buf: BytesMut::with_capacity(MAX_FRAME_PAYLOAD_LEN + 32),
            read_plain_buf: BytesMut::with_capacity(MAX_FRAME_PAYLOAD_LEN),
            write_wire_buf: BytesMut::with_capacity(MAX_FRAME_PAYLOAD_LEN + 32),
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn into_split(self) -> (EncryptedReadHalf<tokio::io::ReadHalf<S>>, EncryptedWriteHalf<tokio::io::WriteHalf<S>>)
    where
        S: AsyncRead + AsyncWrite,
    {
        let (r, w) = tokio::io::split(self.inner);
        (
            EncryptedReadHalf {
                inner: r,
                rx_cipher: self.rx_cipher,
                rx_seq: self.rx_seq,
                read_wire_buf: self.read_wire_buf,
                read_plain_buf: self.read_plain_buf,
            },
            EncryptedWriteHalf {
                inner: w,
                tx_cipher: self.tx_cipher,
                tx_seq: self.tx_seq,
                write_wire_buf: self.write_wire_buf,
            },
        )
    }
}

pub struct EncryptedReadHalf<R> {
    inner: R,
    rx_cipher: ChaCha20Poly1305,
    rx_seq: u64,
    read_wire_buf: BytesMut,
    read_plain_buf: BytesMut,
}

pub struct EncryptedWriteHalf<W> {
    inner: W,
    tx_cipher: ChaCha20Poly1305,
    tx_seq: u64,
    write_wire_buf: BytesMut,
}

impl<R: AsyncRead + Unpin> EncryptedReadHalf<R> {
    pub async fn recv_frame(&mut self) -> io::Result<Option<Bytes>> {
        if !self.read_plain_buf.is_empty() {
            return Ok(Some(self.read_plain_buf.split().freeze()));
        }

        let mut len_buf = [0u8; 4];
        if !self.read_wire_buf.is_empty() {
            while self.read_wire_buf.len() < 4 {
                let mut tmp = [0u8; 4];
                let n = self.inner.read(&mut tmp).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF reading frame header",
                    ));
                }
                self.read_wire_buf.extend_from_slice(&tmp[..n]);
            }
            len_buf.copy_from_slice(&self.read_wire_buf.split_to(4));
        } else {
            match self.inner.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
        }

        let plain_len = u32::from_be_bytes(len_buf) as usize;
        if plain_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("encrypted frame size {} exceeds maximum", plain_len),
            ));
        }

        let wire_len = plain_len + AEAD_TAG_LEN;
        let mut buf = BytesMut::zeroed(wire_len);
        let prebuffered = self.read_wire_buf.len().min(wire_len);
        if prebuffered > 0 {
            buf[..prebuffered].copy_from_slice(&self.read_wire_buf.split_to(prebuffered));
        }
        if prebuffered < wire_len {
            self.inner.read_exact(&mut buf[prebuffered..]).await?;
        }

        let seq = self.rx_seq;
        self.rx_seq = self
            .rx_seq
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "rx nonce overflow"))?;

        let nonce = make_nonce(seq);
        let (ct, tag_bytes) = buf.split_at_mut(plain_len);
        let tag = Tag::from_slice(tag_bytes);

        self.rx_cipher
            .decrypt_in_place_detached(&nonce, &len_buf, ct, tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD authentication failed"))?;

        buf.truncate(plain_len);
        Ok(Some(buf.freeze()))
    }
}

impl<W: AsyncWrite + Unpin> EncryptedWriteHalf<W> {
    pub async fn send_frame(&mut self, mut payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        while !payload.is_empty() {
            let chunk_len = payload.len().min(MAX_FRAME_PAYLOAD_LEN);
            let chunk = &payload[..chunk_len];
            payload = &payload[chunk_len..];

            let seq = self.tx_seq;
            self.tx_seq = self
                .tx_seq
                .checked_add(1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "tx nonce overflow"))?;

            let nonce = make_nonce(seq);
            self.write_wire_buf.clear();
            self.write_wire_buf.reserve(4 + chunk_len + AEAD_TAG_LEN);
            self.write_wire_buf.put_u32(chunk_len as u32);
            self.write_wire_buf.extend_from_slice(chunk);

            let body = &mut self.write_wire_buf[4..4 + chunk_len];
            let tag = self
                .tx_cipher
                .encrypt_in_place_detached(&nonce, &(chunk_len as u32).to_be_bytes(), body)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD encrypt error"))?;
            self.write_wire_buf.extend_from_slice(tag.as_slice());

            self.inner.write_all(&self.write_wire_buf).await?;
            self.write_wire_buf.clear();
        }
        self.inner.flush().await
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedStream<S> {
    /// Encrypt and write a frame over the tunnel.
    /// Frame wire format: `len(u32 BE, plaintext_len) || ciphertext || tag(16B)`
    pub async fn send_frame(&mut self, mut payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        while !payload.is_empty() {
            let chunk_len = payload.len().min(MAX_FRAME_PAYLOAD_LEN);
            let chunk = &payload[..chunk_len];
            payload = &payload[chunk_len..];

            let seq = self.tx_seq;
            self.tx_seq = self
                .tx_seq
                .checked_add(1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "tx nonce overflow"))?;

            let nonce = make_nonce(seq);
            self.write_wire_buf.clear();
            self.write_wire_buf.reserve(4 + chunk_len + AEAD_TAG_LEN);
            self.write_wire_buf.put_u32(chunk_len as u32);
            self.write_wire_buf.extend_from_slice(chunk);

            let body = &mut self.write_wire_buf[4..4 + chunk_len];
            let tag = self
                .tx_cipher
                .encrypt_in_place_detached(&nonce, &(chunk_len as u32).to_be_bytes(), body)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD encrypt error"))?;
            self.write_wire_buf.extend_from_slice(tag.as_slice());

            self.inner.write_all(&self.write_wire_buf).await?;
            self.write_wire_buf.clear();
        }
        self.inner.flush().await
    }

    /// Receive and decrypt a single encrypted frame. Returns `Ok(None)` on clean EOF.
    pub async fn recv_frame(&mut self) -> io::Result<Option<Bytes>> {
        let mut len_buf = [0u8; 4];
        match self.inner.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let plain_len = u32::from_be_bytes(len_buf) as usize;
        if plain_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("encrypted frame size {} exceeds maximum", plain_len),
            ));
        }

        let wire_len = plain_len + AEAD_TAG_LEN;
        let mut buf = BytesMut::zeroed(wire_len);
        self.inner.read_exact(&mut buf).await?;

        let seq = self.rx_seq;
        self.rx_seq = self
            .rx_seq
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "rx nonce overflow"))?;

        let nonce = make_nonce(seq);
        let (ct, tag_bytes) = buf.split_at_mut(plain_len);
        let tag = Tag::from_slice(tag_bytes);

        self.rx_cipher
            .decrypt_in_place_detached(&nonce, &len_buf, ct, tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD authentication failed"))?;

        buf.truncate(plain_len);
        Ok(Some(buf.freeze()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            if !this.read_plain_buf.is_empty() {
                let to_copy = this.read_plain_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_plain_buf.split_to(to_copy));
                return Poll::Ready(Ok(()));
            }

            // Check if we have a full frame in read_wire_buf
            if this.read_wire_buf.len() >= 4 {
                let plain_len = u32::from_be_bytes([
                    this.read_wire_buf[0],
                    this.read_wire_buf[1],
                    this.read_wire_buf[2],
                    this.read_wire_buf[3],
                ]) as usize;

                if plain_len > MAX_FRAME_PAYLOAD_LEN {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "encrypted frame size exceeds maximum",
                    )));
                }

                let total_frame_len = 4 + plain_len + AEAD_TAG_LEN;
                if this.read_wire_buf.len() >= total_frame_len {
                    let mut frame = this.read_wire_buf.split_to(total_frame_len);
                    let aad = [frame[0], frame[1], frame[2], frame[3]];
                    frame.advance(4);

                    let seq = this.rx_seq;
                    this.rx_seq += 1;
                    let nonce = make_nonce(seq);

                    let (ct, tag_slice) = frame.split_at_mut(plain_len);
                    let tag = Tag::from_slice(tag_slice);
                    if this
                        .rx_cipher
                        .decrypt_in_place_detached(&nonce, &aad, ct, tag)
                        .is_err()
                    {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "AEAD decryption failed",
                        )));
                    }

                    frame.truncate(plain_len);
                    this.read_plain_buf.extend_from_slice(&frame);
                    continue;
                }
            }

            // Need more bytes from the underlying stream
            let mut temp = [0u8; 16384];
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        if this.read_wire_buf.is_empty() {
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "incomplete encrypted frame before EOF",
                            )));
                        }
                    }
                    this.read_wire_buf.extend_from_slice(filled);
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // First flush any pending encrypted bytes in write_wire_buf
        while !this.write_wire_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_wire_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write encrypted frame to underlying stream",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_wire_buf.advance(n);
                }
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_len = buf.len().min(MAX_FRAME_PAYLOAD_LEN);
        let chunk = &buf[..chunk_len];

        let seq = this.tx_seq;
        this.tx_seq += 1;
        let nonce = make_nonce(seq);

        this.write_wire_buf.reserve(4 + chunk_len + AEAD_TAG_LEN);
        let len_bytes = (chunk_len as u32).to_be_bytes();
        this.write_wire_buf.put_slice(&len_bytes);
        let start = this.write_wire_buf.len();
        this.write_wire_buf.extend_from_slice(chunk);

        let tag = this
            .tx_cipher
            .encrypt_in_place_detached(&nonce, &len_bytes, &mut this.write_wire_buf[start..start + chunk_len])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD encryption failed"))?;
        this.write_wire_buf.extend_from_slice(tag.as_slice());

        // Attempt immediate write
        while !this.write_wire_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_wire_buf) {
                Poll::Pending => break,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero on encrypted stream",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_wire_buf.advance(n);
                }
            }
        }

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while !this.write_wire_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_wire_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero during flush",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_wire_buf.advance(n);
                }
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mlkem768x25519plus_handshake_and_stream() {
        let (priv_b64, pub_b64) = generate_keypair();
        let client_kp = ClientKeyPair::from_base64(&priv_b64).unwrap();
        assert_eq!(client_kp.public_key_base64(), pub_b64);

        let authorizer = ServerAuthorizer::new(&[pub_b64]).unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let client_task = tokio::spawn(async move {
            let mut stream = client_handshake(client_io, &client_kp).await.unwrap();
            stream.send_frame(b"hello post-quantum world").await.unwrap();
            let reply = stream.recv_frame().await.unwrap().unwrap();
            assert_eq!(&reply[..], b"ack from server");

            stream.write_all(b"streaming payload 12345").await.unwrap();
            stream.flush().await.unwrap();
        });

        let server_task = tokio::spawn(async move {
            let (mut stream, _key_id) = server_handshake(server_io, &authorizer).await.unwrap();
            let msg = stream.recv_frame().await.unwrap().unwrap();
            assert_eq!(&msg[..], b"hello post-quantum world");
            stream.send_frame(b"ack from server").await.unwrap();

            let mut buf = vec![0u8; 23];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"streaming payload 12345");
        });

        client_task.await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_unauthorized_client_rejected() {
        let (priv_b64, _pub_b64) = generate_keypair();
        let (_other_priv, other_pub) = generate_keypair();

        let client_kp = ClientKeyPair::from_base64(&priv_b64).unwrap();
        let authorizer = ServerAuthorizer::new(&[other_pub]).unwrap();

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let server_res = tokio::spawn(async move { server_handshake(server_io, &authorizer).await });
        let _client_res = tokio::spawn(async move { client_handshake(client_io, &client_kp).await });

        assert!(server_res.await.unwrap().is_err());
    }
}
