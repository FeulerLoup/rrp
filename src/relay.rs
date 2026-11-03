use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::EncryptedStream;
use crate::net_utils::configure_tcp_stream;
use crate::status::ConnectionStatus;

const RELAY_BUF_SIZE: usize = 64 * 1024;

/// Relay data bidirectionally at maximum throughput between an `EncryptedStream<TcpStream>`
/// (post-quantum mlkem768x25519plus tunnel) and a local or visitor `TcpStream`.
///
/// Uses full-duplex split halves with 64 KiB buffers.
pub async fn relay_encrypted_and_plain(
    encrypted: EncryptedStream<TcpStream>,
    plain: TcpStream,
) -> io::Result<(u64, u64)> {
    relay_encrypted_and_plain_with_status(encrypted, plain, None).await
}

/// Same as [`relay_encrypted_and_plain`], with live traffic accounting.
pub async fn relay_encrypted_and_plain_with_status(
    encrypted: EncryptedStream<TcpStream>,
    mut plain: TcpStream,
    status: Option<&ConnectionStatus>,
) -> io::Result<(u64, u64)> {
    configure_tcp_stream(encrypted.get_ref());
    configure_tcp_stream(&plain);

    let (mut enc_read, mut enc_write) = encrypted.into_split();
    let (mut plain_read, mut plain_write) = plain.split();
    let sent_status = status.cloned();
    let received_status = status.cloned();

    let plain_to_enc = async move {
        let mut buf = vec![0u8; RELAY_BUF_SIZE];
        let mut total = 0u64;
        loop {
            let n = plain_read.read(&mut buf).await?;
            if n == 0 {
                let _ = enc_write.shutdown().await;
                break;
            }
            enc_write.send_frame(&buf[..n]).await?;
            total += n as u64;
            if let Some(status) = &sent_status {
                status.record_sent(n);
            }
        }
        Ok::<u64, io::Error>(total)
    };

    let enc_to_plain = async move {
        let mut total = 0u64;
        while let Some(frame) = enc_read.recv_frame().await? {
            if frame.is_empty() {
                break;
            }
            plain_write.write_all(&frame).await?;
            total += frame.len() as u64;
            if let Some(status) = &received_status {
                status.record_received(frame.len());
            }
        }
        let _ = plain_write.shutdown().await;
        Ok::<u64, io::Error>(total)
    };

    tokio::try_join!(plain_to_enc, enc_to_plain)
}

/// Relay two plain `TcpStream`s with live traffic accounting (`a -> b` counts as sent,
/// `b -> a` as received). Used by the tunnel data plane on the client, where both legs are
/// plaintext inside the WireGuard tunnel.
pub async fn relay_plain_with_status(
    mut a: TcpStream,
    mut b: TcpStream,
    status: Option<&ConnectionStatus>,
) -> io::Result<(u64, u64)> {
    configure_tcp_stream(&a);
    configure_tcp_stream(&b);

    let (mut a_read, mut a_write) = a.split();
    let (mut b_read, mut b_write) = b.split();
    let sent_status = status.cloned();
    let received_status = status.cloned();

    let a_to_b = async move {
        let mut buf = vec![0u8; RELAY_BUF_SIZE];
        let mut total = 0u64;
        loop {
            let n = a_read.read(&mut buf).await?;
            if n == 0 {
                let _ = b_write.shutdown().await;
                break;
            }
            b_write.write_all(&buf[..n]).await?;
            total += n as u64;
            if let Some(status) = &sent_status {
                status.record_sent(n);
            }
        }
        Ok::<u64, io::Error>(total)
    };

    let b_to_a = async move {
        let mut buf = vec![0u8; RELAY_BUF_SIZE];
        let mut total = 0u64;
        loop {
            let n = b_read.read(&mut buf).await?;
            if n == 0 {
                let _ = a_write.shutdown().await;
                break;
            }
            a_write.write_all(&buf[..n]).await?;
            total += n as u64;
            if let Some(status) = &received_status {
                status.record_received(n);
            }
        }
        Ok::<u64, io::Error>(total)
    };

    tokio::try_join!(a_to_b, b_to_a)
}

/// Relay two plain `TcpStream` connections using Linux `splice(2)` zero-copy pipes and
/// fallback to `tokio::io::copy_bidirectional`.
pub async fn relay_plain_tcp_pair(mut a: TcpStream, mut b: TcpStream) -> io::Result<(u64, u64)> {
    configure_tcp_stream(&a);
    configure_tcp_stream(&b);

    #[cfg(target_os = "linux")]
    {
        if let Ok(stats) = linux_splice::splice_bidirectional(&a, &b).await {
            return Ok(stats);
        }
    }

    tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, RELAY_BUF_SIZE, RELAY_BUF_SIZE).await
}

#[cfg(target_os = "linux")]
mod linux_splice {
    use std::io;
    use std::os::unix::io::{AsRawFd, RawFd};
    use tokio::io::Interest;
    use tokio::net::TcpStream;

    const SPLICE_CHUNK: usize = 64 * 1024;

    struct Pipe {
        r: RawFd,
        w: RawFd,
    }

    impl Pipe {
        fn new() -> io::Result<Self> {
            let mut fds = [0i32; 2];
            let res = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                r: fds[0],
                w: fds[1],
            })
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.r);
                libc::close(self.w);
            }
        }
    }

    async fn splice_one_way(src: &TcpStream, dst: &TcpStream) -> io::Result<u64> {
        let pipe = Pipe::new()?;
        let mut total = 0u64;

        loop {
            let read_bytes = src
                .async_io(Interest::READABLE, || {
                    let n = unsafe {
                        libc::splice(
                            src.as_raw_fd(),
                            std::ptr::null_mut(),
                            pipe.w,
                            std::ptr::null_mut(),
                            SPLICE_CHUNK,
                            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                })
                .await?;

            if read_bytes == 0 {
                unsafe {
                    libc::shutdown(dst.as_raw_fd(), libc::SHUT_WR);
                }
                break;
            }

            let mut remaining = read_bytes;
            while remaining > 0 {
                let written = dst
                    .async_io(Interest::WRITABLE, || {
                        let n = unsafe {
                            libc::splice(
                                pipe.r,
                                std::ptr::null_mut(),
                                dst.as_raw_fd(),
                                std::ptr::null_mut(),
                                remaining,
                                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                            )
                        };
                        if n < 0 {
                            Err(io::Error::last_os_error())
                        } else {
                            Ok(n as usize)
                        }
                    })
                    .await?;
                remaining -= written;
                total += written as u64;
            }
        }

        Ok(total)
    }

    pub async fn splice_bidirectional(a: &TcpStream, b: &TcpStream) -> io::Result<(u64, u64)> {
        tokio::try_join!(splice_one_way(a, b), splice_one_way(b, a))
    }
}
