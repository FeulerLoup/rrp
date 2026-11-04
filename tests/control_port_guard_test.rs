//! Admission control on the control port: silent, garbage and repeat-offender peers are closed
//! quickly and cheaply, and authorized clients still get through.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use rrp::config::{HandshakeGuardConfig, ServerConfig};
use rrp::crypto::{client_handshake, generate_keypair, ClientKeyPair};
use rrp::server::Server;

fn guarded_server(
    handshake: HandshakeGuardConfig,
    authorized_keys: Vec<String>,
) -> (SocketAddr, JoinHandle<()>) {
    let server = Server::new(ServerConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        proxy_bind_ip: "127.0.0.1".to_string(),
        authorized_keys,
        enable_ebpf: false,
        handshake,
        ..Default::default()
    })
    .unwrap();
    let addr = server.local_addr();
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    (addr, handle)
}

fn limits(hello_timeout_secs: u64) -> HandshakeGuardConfig {
    HandshakeGuardConfig {
        hello_timeout_secs,
        ..Default::default()
    }
}

/// Wait until the server closes `stream` (EOF or RST) and return how long that took.
async fn wait_for_close(stream: &mut TcpStream, limit: Duration) -> Duration {
    let started = Instant::now();
    let mut buf = [0u8; 64];
    loop {
        match timeout(limit, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return started.elapsed(),
            Ok(Ok(_)) => continue,
            Err(_) => panic!("server kept the connection open for {:?}", limit),
        }
    }
}

#[tokio::test]
async fn silent_peer_is_dropped_after_the_hello_timeout() {
    let (_priv, pub_b64) = generate_keypair();
    let (addr, server) = guarded_server(limits(1), vec![pub_b64]);

    let mut silent = TcpStream::connect(addr).await.unwrap();
    // Linux first holds a silent connection in the kernel for `hello_timeout` (TCP_DEFER_ACCEPT)
    // and only then starts the user-space wait, so allow roughly two timeouts plus slack.
    let elapsed = wait_for_close(&mut silent, Duration::from_secs(6)).await;
    assert!(
        elapsed >= Duration::from_millis(500),
        "closed too early: {:?}",
        elapsed
    );

    server.abort();
}

#[tokio::test]
async fn garbage_hello_is_dropped_at_once() {
    let (_priv, pub_b64) = generate_keypair();
    let (addr, server) = guarded_server(limits(5), vec![pub_b64]);

    let mut garbage = TcpStream::connect(addr).await.unwrap();
    garbage.write_all(&[0u8; 256]).await.unwrap();
    let elapsed = wait_for_close(&mut garbage, Duration::from_secs(5)).await;
    assert!(
        elapsed < Duration::from_secs(2),
        "garbage should not wait for the hello timeout: {:?}",
        elapsed
    );

    server.abort();
}

#[tokio::test]
async fn per_ip_pending_limit_closes_extra_connections_immediately() {
    let (priv_b64, pub_b64) = generate_keypair();
    let key = ClientKeyPair::from_base64(&priv_b64).unwrap();
    let (addr, server) = guarded_server(
        HandshakeGuardConfig {
            hello_timeout_secs: 5,
            max_pending_per_ip: 1,
            ..Default::default()
        },
        vec![pub_b64],
    );

    // One byte gets the connection past TCP_DEFER_ACCEPT on Linux, then it stalls inside the
    // handshake and occupies the single per-IP slot.
    let mut stalled = TcpStream::connect(addr).await.unwrap();
    stalled.write_all(&[0x01]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Same trick for the second connection: on Linux a silent one would simply sit in the kernel
    // for the whole timeout, never reaching `accept`, which is the point of TCP_DEFER_ACCEPT.
    let mut extra = TcpStream::connect(addr).await.unwrap();
    extra.write_all(&[0x01]).await.unwrap();
    let elapsed = wait_for_close(&mut extra, Duration::from_secs(5)).await;
    assert!(
        elapsed < Duration::from_secs(2),
        "over-limit connection should be refused at accept time: {:?}",
        elapsed
    );

    // Releasing the slot lets an authorized client in again.
    drop(stalled);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stream = TcpStream::connect(addr).await.unwrap();
    client_handshake(stream, &key)
        .await
        .expect("authorized client admitted once the slot is free");

    server.abort();
}

#[tokio::test]
async fn repeated_failures_ban_the_address() {
    let (priv_b64, pub_b64) = generate_keypair();
    let key = ClientKeyPair::from_base64(&priv_b64).unwrap();
    let (addr, server) = guarded_server(
        HandshakeGuardConfig {
            hello_timeout_secs: 5,
            failure_limit: 2,
            ban_secs: 60,
            ..Default::default()
        },
        vec![pub_b64.clone()],
    );

    for _ in 0..2 {
        let mut garbage = TcpStream::connect(addr).await.unwrap();
        garbage.write_all(&[0u8; 256]).await.unwrap();
        wait_for_close(&mut garbage, Duration::from_secs(5)).await;
    }
    // The RST reaches us a hair before the server records the failure.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let result = timeout(Duration::from_secs(5), client_handshake(stream, &key)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "banned address must be refused even with the right key: {:?}",
        result.map(|r| r.map(|_| ()))
    );

    // A server without the ban accepts the very same key.
    let (clean_addr, clean_server) = guarded_server(limits(5), vec![pub_b64]);
    let stream = TcpStream::connect(clean_addr).await.unwrap();
    client_handshake(stream, &key).await.unwrap();

    server.abort();
    clean_server.abort();
}

#[test]
fn handshake_section_parses_with_defaults_and_validates() {
    let cfg: ServerConfig =
        toml::from_str("bind_addr = \"127.0.0.1:3700\"\n[handshake]\nmax_pending_per_ip = 8\n")
            .unwrap();
    assert_eq!(cfg.handshake.max_pending_per_ip, 8);
    assert_eq!(
        cfg.handshake,
        HandshakeGuardConfig {
            max_pending_per_ip: 8,
            ..Default::default()
        }
    );
    cfg.validate().unwrap();

    let zero_timeout: ServerConfig =
        toml::from_str("[handshake]\nhello_timeout_secs = 0\n").unwrap();
    assert!(zero_timeout.validate().is_err());
    let zero_ban: ServerConfig = toml::from_str("[handshake]\nban_secs = 0\n").unwrap();
    assert!(zero_ban.validate().is_err());
    let no_ban: ServerConfig =
        toml::from_str("[handshake]\nfailure_limit = 0\nban_secs = 0\n").unwrap();
    no_ban.validate().unwrap();
}
