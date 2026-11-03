use std::fs;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

use rrp::cli::{Cli, Commands, RunMode, DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_SERVER_CONFIG_PATH};
use rrp::client::Client;
use rrp::config::{
    approve_client_key, install_client_key, install_client_key_with, ClientConfig,
    ClientServerConfig, ProxyConfig, ProxyType, ServerConfig,
};
use rrp::crypto::{
    client_handshake, generate_keypair, AuthorizedPublicKey, ClientKeyPair, MAX_FRAME_PAYLOAD_LEN,
};
use rrp::ebpf::EbpfAccelerator;
use rrp::net_utils::{bind_tcp_listener, bind_udp_socket, connect_tcp};
use rrp::protocol::{ControlSignal, ProxySpec, RoleHandshake, TunnelFrame};
use rrp::relay::relay_plain_tcp_pair;
use rrp::server::Server;
use rrp::service::{
    extract_config_path_from_service, install_autostart_service, uninstall_autostart_service,
    uninstall_rrp, ServicePlatform,
};
use rrp::status::{RuntimeStatus, StatusReporter};

fn get_free_port(bind_ip: &str) -> u16 {
    let addr = if bind_ip.contains(':') {
        format!("[{}]:0", bind_ip)
    } else {
        format!("{}:0", bind_ip)
    };
    let sock = std::net::TcpListener::bind(&addr).expect("bind free port");
    sock.local_addr().unwrap().port()
}

async fn spawn_tcp_echo_server(bind_addr: &str) -> SocketAddr {
    let listener = bind_tcp_listener(bind_addr).expect("bind tcp echo server");
    let local_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    local_addr
}

async fn spawn_udp_echo_server(bind_addr: &str) -> SocketAddr {
    let sock = Arc::new(bind_udp_socket(bind_addr).expect("bind udp echo server"));
    let local_addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let mut reply = b"udp-echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&reply, peer).await;
        }
    });
    local_addr
}

#[test]
fn test_install_and_approve_config_and_cli() {
    let dir = tempdir().unwrap();
    let client_cfg_path = dir.path().join("rrpc.toml");
    let server_cfg_path = dir.path().join("rrps.toml");

    let (priv_b64, pub_b64) = install_client_key(&client_cfg_path).unwrap();
    assert!(!priv_b64.is_empty());
    assert!(!pub_b64.is_empty());

    let parsed_priv = ClientKeyPair::from_base64(&priv_b64).unwrap();
    let parsed_pub = AuthorizedPublicKey::from_base64(&pub_b64).unwrap();
    assert_eq!(parsed_priv.key_id(), parsed_pub.key_id());

    let loaded_client = ClientConfig::load(&client_cfg_path).unwrap();
    assert_eq!(loaded_client.private_key, priv_b64);
    assert_eq!(loaded_client.server_addr, "127.0.0.1:3700");

    let first_add = approve_client_key(&server_cfg_path, &pub_b64).unwrap();
    assert!(first_add);
    let duplicate_add = approve_client_key(&server_cfg_path, &pub_b64).unwrap();
    assert!(!duplicate_add);

    let loaded_server = ServerConfig::load(&server_cfg_path).unwrap();
    assert_eq!(loaded_server.bind_addr, "[::]:3700");
    assert_eq!(loaded_server.authorized_keys, vec![pub_b64]);

    // Also test CLI binary subcommands `install` and `approve`
    let bin = env!("CARGO_BIN_EXE_rrp");
    let cli_client_cfg = dir.path().join("cli_rrpc.toml");
    let cli_server_cfg = dir.path().join("cli_rrps.toml");
    let svc_dir = dir.path().join("services");

    let output = Command::new(bin)
        .args([
            "install",
            "--mode",
            "client",
            "-c",
            cli_client_cfg.to_str().unwrap(),
            "--autostart",
            "--service-dir",
            svc_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run rrp install");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pub_key_line = stdout
        .lines()
        .nth(2)
        .expect("public key output line")
        .trim();

    let approve_out = Command::new(bin)
        .args([
            "approve",
            pub_key_line,
            "-c",
            cli_server_cfg.to_str().unwrap(),
        ])
        .output()
        .expect("run rrp approve");
    assert!(approve_out.status.success());

    let verified_server = ServerConfig::load(&cli_server_cfg).unwrap();
    assert_eq!(verified_server.authorized_keys.len(), 1);
    assert_eq!(verified_server.authorized_keys[0], pub_key_line);

    // Verify default `-c` paths point to `/usr/local/etc/rrp/`
    use clap::Parser;
    let parsed_server = Cli::try_parse_from(["rrp", "server"]).unwrap();
    match parsed_server.command {
        Commands::Server { config } => {
            assert_eq!(config.to_str().unwrap(), DEFAULT_SERVER_CONFIG_PATH);
            assert_eq!(config.to_str().unwrap(), "/usr/local/etc/rrp/rrps.toml");
        }
        _ => panic!("expected Server command"),
    }

    let parsed_client = Cli::try_parse_from(["rrp", "client"]).unwrap();
    match parsed_client.command {
        Commands::Client { config, .. } => {
            assert_eq!(config.to_str().unwrap(), DEFAULT_CLIENT_CONFIG_PATH);
            assert_eq!(config.to_str().unwrap(), "/usr/local/etc/rrp/rrpc.toml");
        }
        _ => panic!("expected Client command"),
    }

    let parsed_approve = Cli::try_parse_from(["rrp", "approve", "dummy_key"]).unwrap();
    match parsed_approve.command {
        Commands::Approve { config, .. } => {
            assert_eq!(config.to_str().unwrap(), DEFAULT_SERVER_CONFIG_PATH);
        }
        _ => panic!("expected Approve command"),
    }

    let parsed_status =
        Cli::try_parse_from(["rrp", "status", "--mode", "client", "--json"]).unwrap();
    match parsed_status.command {
        Commands::Status {
            mode: Some(RunMode::Client),
            json: true,
            file: None,
        } => {}
        _ => panic!("expected client Status command with JSON output"),
    }

    let parsed_uninstall =
        Cli::try_parse_from(["rrp", "uninstall", "--mode", "server", "--purge"]).unwrap();
    match parsed_uninstall.command {
        Commands::Uninstall {
            mode: Some(RunMode::Server),
            config: None,
            purge: true,
            service_dir: None,
        } => {}
        _ => panic!("expected server Uninstall command with --purge"),
    }
}

#[tokio::test]
async fn test_status_subcommand_human_and_json_output() {
    let dir = tempdir().unwrap();
    let status_path = dir.path().join("client.json");
    let runtime = RuntimeStatus::new(RunMode::Client, "disabled by configuration", None);
    let connection = runtime.proxy_endpoint(
        "example_tcp",
        "example_tcp",
        "tcp",
        "127.0.0.1:18080",
        "127.0.0.1:8080",
    );
    connection.mark_connected();
    connection.record_sent(1_024);
    connection.record_received(2_048);
    connection.record_heartbeat(Some(8));
    let _reporter = StatusReporter::start_at(runtime, status_path.clone())
        .await
        .unwrap();

    let bin = env!("CARGO_BIN_EXE_rrp");
    let human = Command::new(bin)
        .args(["status", "--file", status_path.to_str().unwrap()])
        .output()
        .expect("run human status command");
    assert!(human.status.success());
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(human_stdout
        .contains("    - example_tcp [connected]\n      tcp 127.0.0.1:18080 -> 127.0.0.1:8080\n"));
    assert!(human_stdout.contains("Connected for:"));
    assert!(human_stdout.contains("Traffic:"));
    assert!(human_stdout.contains("Last heartbeat:"));
    assert!(!human_stdout.contains("Active:"));
    assert!(!human_stdout.contains("Last update:"));
    assert!(!human_stdout.contains("Proxies:"));

    let json = Command::new(bin)
        .args(["status", "--file", status_path.to_str().unwrap(), "--json"])
        .output()
        .expect("run JSON status command");
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["mode"], "client");
    assert_eq!(value["running"], true);
    assert_eq!(value["traffic"]["bytes_sent"], 1_024);
    assert_eq!(value["connections"][0]["name"], "example_tcp");
    assert_eq!(value["connections"][0]["proxy_type"], "tcp");
    assert_eq!(value["connections"][0]["server_addr"], "127.0.0.1:18080");
    assert_eq!(value["connections"][0]["target_addr"], "127.0.0.1:8080");
    assert_eq!(value["connections"][0]["last_heartbeat_rtt_ms"], 8);
}

#[test]
fn test_autostart_service_generation_linux_and_macos() {
    let dir = tempdir().unwrap();
    let bin_path = dir.path().join("rrp");
    let cfg_path = dir.path().join("rrpc.toml");
    fs::write(&bin_path, b"binary").unwrap();
    fs::write(&cfg_path, b"config").unwrap();

    let linux_dir = dir.path().join("systemd");
    let unit_file = install_autostart_service(
        ServicePlatform::LinuxSystemd,
        RunMode::Client,
        &bin_path,
        &cfg_path,
        Some(&linux_dir),
    )
    .unwrap();
    assert!(unit_file.exists());
    let unit_content = fs::read_to_string(&unit_file).unwrap();
    assert!(unit_content.contains("[Service]"));
    assert!(unit_content.contains("client -c"));
    assert!(unit_content.contains("WantedBy=multi-user.target"));

    let macos_dir = dir.path().join("launchd");
    let plist_file = install_autostart_service(
        ServicePlatform::MacosLaunchd,
        RunMode::Server,
        &bin_path,
        &cfg_path,
        Some(&macos_dir),
    )
    .unwrap();
    assert!(plist_file.exists());
    let plist_content = fs::read_to_string(&plist_file).unwrap();
    assert!(plist_content.contains("<string>com.rrp.server</string>"));
    assert!(plist_content.contains("<key>RunAtLoad</key>"));
    assert!(plist_content.contains("<string>server</string>"));

    // Verify config path extraction from both systemd unit and launchd plist
    assert_eq!(
        extract_config_path_from_service(&unit_content).unwrap(),
        fs::canonicalize(&cfg_path).unwrap()
    );
    assert_eq!(
        extract_config_path_from_service(&plist_content).unwrap(),
        fs::canonicalize(&cfg_path).unwrap()
    );

    // 1. Uninstall autostart service only (without purge): service removed, config and binary kept
    let removed_linux = uninstall_autostart_service(
        ServicePlatform::LinuxSystemd,
        RunMode::Client,
        Some(&linux_dir),
    )
    .unwrap();
    assert_eq!(removed_linux.as_deref(), Some(unit_file.as_path()));
    assert!(!unit_file.exists());
    assert!(bin_path.exists());
    assert!(cfg_path.exists());

    // 2. Uninstall with purge on macOS: plist, config, and binary all removed
    let report = uninstall_rrp(
        ServicePlatform::MacosLaunchd,
        Some(RunMode::Server),
        None,
        true,
        Some(&bin_path),
        Some(&macos_dir),
    )
    .unwrap();
    assert_eq!(report.removed_services, vec![plist_file.clone()]);
    assert!(!plist_file.exists());
    assert!(!cfg_path.exists());
    assert!(!bin_path.exists());

    // 3. Test CLI `rrp uninstall --purge` using a copied binary in temp dir
    let real_bin = env!("CARGO_BIN_EXE_rrp");
    let temp_bin = dir.path().join("rrp_copy");
    let temp_cfg = dir.path().join("temp_rrpc.toml");
    let temp_svc_dir = dir.path().join("cli_svc");
    fs::copy(real_bin, &temp_bin).unwrap();

    let install_out = Command::new(&temp_bin)
        .args([
            "install",
            "--mode",
            "client",
            "-c",
            temp_cfg.to_str().unwrap(),
            "--autostart",
            "--service-dir",
            temp_svc_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run temp_bin install");
    assert!(install_out.status.success());
    assert!(temp_cfg.exists());

    let uninstall_out = Command::new(&temp_bin)
        .args([
            "uninstall",
            "--mode",
            "client",
            "--purge",
            "--service-dir",
            temp_svc_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run temp_bin uninstall --purge");
    assert!(uninstall_out.status.success());
    assert!(!temp_cfg.exists());
    assert!(!temp_bin.exists());
}

#[tokio::test]
async fn test_tcp_udp_and_all_forwarding() {
    let (priv_b64, pub_b64) = generate_keypair();

    let local_tcp_addr = spawn_tcp_echo_server("127.0.0.1:0").await;
    let local_udp_addr = spawn_udp_echo_server("127.0.0.1:0").await;

    // For `all` (TCP + UDP), bind both local TCP and UDP on the same local port
    let local_all_port = get_free_port("127.0.0.1");
    let local_all_addr_str = format!("127.0.0.1:{}", local_all_port);
    let _ = spawn_tcp_echo_server(&local_all_addr_str).await;
    let _ = spawn_udp_echo_server(&local_all_addr_str).await;

    let remote_tcp_port = get_free_port("127.0.0.1");
    let remote_udp_port = get_free_port("127.0.0.1");
    let remote_all_port = get_free_port("127.0.0.1");

    let server_cfg = ServerConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        proxy_bind_ip: "127.0.0.1".to_string(),
        authorized_keys: vec![pub_b64],
        enable_ebpf: true,
        heartbeat_timeout_secs: 60,
    };

    let server = Server::new(server_cfg).unwrap();
    let server_addr = server.local_addr();
    let server_status = server.status();
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let client_cfg = ClientConfig {
        server_addr: server_addr.to_string(),
        private_key: priv_b64,
        enable_ebpf: true,
        heartbeat_interval_secs: 10,
        proxies: vec![
            ProxyConfig {
                name: "tcp_only".to_string(),
                proxy_type: ProxyType::Tcp,
                local_addr: Some(local_tcp_addr.to_string()),
                remote_port: remote_tcp_port,
                ..Default::default()
            },
            ProxyConfig {
                name: "udp_only".to_string(),
                proxy_type: ProxyType::Udp,
                local_addr: Some(local_udp_addr.to_string()),
                remote_port: remote_udp_port,
                ..Default::default()
            },
            ProxyConfig {
                name: "all_both".to_string(),
                proxy_type: ProxyType::All,
                local_addr: Some(local_all_addr_str),
                remote_port: remote_all_port,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let client = Client::new(client_cfg).unwrap();
    let client_status = client.status();
    let (ready_tx, ready_rx) = oneshot::channel();
    let client_handle = tokio::spawn(async move {
        let _ = client.run_session(Some(ready_tx)).await;
    });

    ready_rx.await.unwrap().unwrap();

    // 1. Verify TCP proxy with large multi-frame payload (200 KiB)
    let mut visitor_tcp = TcpStream::connect(format!("127.0.0.1:{}", remote_tcp_port))
        .await
        .unwrap();
    let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    visitor_tcp.write_all(&payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    visitor_tcp.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    // 2. Verify UDP proxy
    let visitor_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    visitor_udp
        .send_to(b"ping-udp", format!("127.0.0.1:{}", remote_udp_port))
        .await
        .unwrap();
    let mut udp_buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), visitor_udp.recv_from(&mut udp_buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&udp_buf[..n], b"udp-echo:ping-udp");

    // 3. Verify ALL (TCP + UDP) on the same remote_all_port
    let mut visitor_all_tcp = TcpStream::connect(format!("127.0.0.1:{}", remote_all_port))
        .await
        .unwrap();
    visitor_all_tcp
        .write_all(b"all-mode-tcp-data")
        .await
        .unwrap();
    let mut all_tcp_reply = [0u8; 17];
    visitor_all_tcp
        .read_exact(&mut all_tcp_reply)
        .await
        .unwrap();
    assert_eq!(&all_tcp_reply, b"all-mode-tcp-data");

    visitor_udp
        .send_to(
            b"all-mode-udp-data",
            format!("127.0.0.1:{}", remote_all_port),
        )
        .await
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), visitor_udp.recv_from(&mut udp_buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&udp_buf[..n], b"udp-echo:all-mode-udp-data");

    let client_snapshot = client_status.snapshot();
    let server_snapshot = server_status.snapshot();
    assert!(client_snapshot.traffic.total_bytes >= 400_000);
    assert!(server_snapshot.traffic.total_bytes >= 400_000);
    assert_eq!(client_snapshot.connections[0].name, "tcp_only");
    assert_eq!(client_snapshot.connections[0].proxy_type, "tcp");
    assert_eq!(
        client_snapshot.connections[0].server_addr,
        format!("127.0.0.1:{}", remote_tcp_port)
    );
    assert_eq!(
        client_snapshot.connections[0].target_addr,
        local_tcp_addr.to_string()
    );
    assert_eq!(client_snapshot.connections[0].state, "connected");
    assert_eq!(server_snapshot.connections[0].name, "tcp_only");
    assert_eq!(server_snapshot.connections[0].proxy_type, "tcp");
    assert_eq!(
        server_snapshot.connections[0].server_addr,
        format!("127.0.0.1:{}", remote_tcp_port)
    );
    assert_eq!(
        server_snapshot.connections[0].target_addr,
        local_tcp_addr.to_string()
    );
    assert_eq!(server_snapshot.connections[0].state, "connected");

    client_handle.abort();
    server_handle.abort();
}

#[tokio::test]
async fn test_ipv4_ipv6_cross_translation() {
    let (priv_b64, pub_b64) = generate_keypair();

    // Local service 1: IPv6-only ([::1]) TCP + UDP
    let v6_local_port = get_free_port("::1");
    let v6_local_addr = format!("[::1]:{}", v6_local_port);
    let _ = spawn_tcp_echo_server(&v6_local_addr).await;
    let _ = spawn_udp_echo_server(&v6_local_addr).await;

    // Local service 2: IPv4-only (127.0.0.1) TCP + UDP
    let v4_local_port = get_free_port("127.0.0.1");
    let v4_local_addr = format!("127.0.0.1:{}", v4_local_port);
    let _ = spawn_tcp_echo_server(&v4_local_addr).await;
    let _ = spawn_udp_echo_server(&v4_local_addr).await;

    let remote_v4_entry_port = get_free_port("127.0.0.1");
    let remote_v6_entry_port = get_free_port("::1");

    // Server listens on dual-stack [::]:0
    let server_cfg = ServerConfig {
        bind_addr: "[::]:0".to_string(),
        proxy_bind_ip: "::".to_string(),
        authorized_keys: vec![pub_b64],
        enable_ebpf: true,
        heartbeat_timeout_secs: 60,
    };

    let server = Server::new(server_cfg).unwrap();
    let server_port = server.local_addr().port();
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Client connects to server via IPv6 [::1] and registers both cross-family proxies
    let client_cfg = ClientConfig {
        server_addr: format!("[::1]:{}", server_port),
        private_key: priv_b64,
        enable_ebpf: true,
        heartbeat_interval_secs: 10,
        proxies: vec![
            // Visitor uses IPv4 (127.0.0.1) -> Server -> Client -> Local IPv6 ([::1])
            ProxyConfig {
                name: "v4_to_v6".to_string(),
                proxy_type: ProxyType::All,
                local_addr: Some(v6_local_addr),
                remote_port: remote_v4_entry_port,
                remote_bind_ip: Some("127.0.0.1".to_string()),
                ..Default::default()
            },
            // Visitor uses IPv6 ([::1]) -> Server -> Client -> Local IPv4 (127.0.0.1)
            ProxyConfig {
                name: "v6_to_v4".to_string(),
                proxy_type: ProxyType::All,
                local_addr: Some(v4_local_addr),
                remote_port: remote_v6_entry_port,
                remote_bind_ip: Some("::1".to_string()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let client = Client::new(client_cfg).unwrap();
    let (ready_tx, ready_rx) = oneshot::channel();
    let client_handle = tokio::spawn(async move {
        let _ = client.run_session(Some(ready_tx)).await;
    });

    ready_rx.await.unwrap().unwrap();

    // Case A: IPv4 Visitor -> IPv6 Local Service (TCP & UDP)
    let mut v4_tcp = TcpStream::connect(format!("127.0.0.1:{}", remote_v4_entry_port))
        .await
        .unwrap();
    v4_tcp
        .write_all(b"ipv4-visitor-to-ipv6-local")
        .await
        .unwrap();
    let mut buf = [0u8; 26];
    v4_tcp.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ipv4-visitor-to-ipv6-local");

    let v4_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    v4_udp
        .send_to(
            b"v4-to-v6-udp",
            format!("127.0.0.1:{}", remote_v4_entry_port),
        )
        .await
        .unwrap();
    let mut ubuf = [0u8; 256];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), v4_udp.recv_from(&mut ubuf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&ubuf[..n], b"udp-echo:v4-to-v6-udp");

    // Case B: IPv6 Visitor -> IPv4 Local Service (TCP & UDP)
    let mut v6_tcp = TcpStream::connect(format!("[::1]:{}", remote_v6_entry_port))
        .await
        .unwrap();
    v6_tcp
        .write_all(b"ipv6-visitor-to-ipv4-local")
        .await
        .unwrap();
    let mut buf2 = [0u8; 26];
    v6_tcp.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"ipv6-visitor-to-ipv4-local");

    let v6_udp = UdpSocket::bind("[::1]:0").await.unwrap();
    v6_udp
        .send_to(b"v6-to-v4-udp", format!("[::1]:{}", remote_v6_entry_port))
        .await
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), v6_udp.recv_from(&mut ubuf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&ubuf[..n], b"udp-echo:v6-to-v4-udp");

    client_handle.abort();
    server_handle.abort();
}

#[tokio::test]
async fn test_unapproved_client_rejected() {
    let (_approved_priv, approved_pub) = generate_keypair();
    let (unapproved_priv, _unapproved_pub) = generate_keypair();

    let server_cfg = ServerConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        proxy_bind_ip: "127.0.0.1".to_string(),
        authorized_keys: vec![approved_pub],
        enable_ebpf: false,
        heartbeat_timeout_secs: 30,
    };

    let server = Server::new(server_cfg).unwrap();
    let server_addr = server.local_addr();
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    let client_cfg = ClientConfig {
        server_addr: server_addr.to_string(),
        private_key: unapproved_priv,
        enable_ebpf: false,
        heartbeat_interval_secs: 10,
        proxies: vec![],
        ..Default::default()
    };

    let client = Client::new(client_cfg).unwrap();
    let res = client.run_session(None).await;
    assert!(res.is_err());

    server_handle.abort();
}

#[tokio::test]
async fn test_ebpf_and_zero_copy_splice_relay() {
    let ebpf_disabled = EbpfAccelerator::try_init(false);
    assert!(!ebpf_disabled.is_active());

    let ebpf_auto = EbpfAccelerator::try_init(true);
    assert!(!ebpf_auto.status_reason().is_empty());

    let echo_addr = spawn_tcp_echo_server("127.0.0.1:0").await;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ebpf_clone = ebpf_auto.clone();
    let relay_task = tokio::spawn(async move {
        let (inbound, _) = proxy_listener.accept().await.unwrap();
        let outbound = TcpStream::connect(echo_addr).await.unwrap();
        relay_plain_tcp_pair(inbound, outbound, Some(&ebpf_clone))
            .await
            .unwrap()
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let data = vec![0x5Au8; 128 * 1024];
    client.write_all(&data).await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    client.read_to_end(&mut received).await.unwrap();
    assert_eq!(received.len(), data.len());
    assert_eq!(received, data);

    let (a2b, b2a) = relay_task.await.unwrap();
    assert_eq!(a2b, 128 * 1024);
    assert_eq!(b2a, 128 * 1024);
}

#[test]
fn test_multi_server_config_resolution_and_toml() {
    let (priv1, _pub1) = generate_keypair();
    let (priv2, _pub2) = generate_keypair();

    let toml_str = format!(
        r#"
server_addrs = ["10.0.0.1:3700", "10.0.0.2:3700"]
private_key = "{priv1}"
enable_ebpf = true
heartbeat_interval_secs = 15

[[servers]]
name = "node_c"
addr = "10.0.0.3:3700"
private_key = "{priv2}"
heartbeat_interval_secs = 25

[[servers.proxies]]
name = "shared_web"
type = "tcp"
local_addr = "127.0.0.1:8083"
remote_port = 38080

[[proxies]]
name = "shared_web"
type = "tcp"
local_addr = "127.0.0.1:8080"
remote_port = 18080

[[proxies]]
name = "only_node_a"
type = "udp"
server = "10.0.0.1:3700"
local_addr = "127.0.0.1:5353"
remote_port = 15353

[[proxies]]
name = "only_node_c"
type = "all"
servers = ["node_c"]
local_addr = "127.0.0.1:9000"
remote_port = 19000
"#
    );

    let cfg: ClientConfig = toml::from_str(&toml_str).expect("parse multi-server client TOML");
    let resolved = cfg.resolve_servers().expect("resolve multi-server config");
    assert_eq!(resolved.len(), 3);

    // 1. `node_c` from [[servers]] has its own `shared_web` (8083 -> 38080) and `only_node_c`
    let node_c = resolved
        .iter()
        .find(|s| s.server_addr == "10.0.0.3:3700")
        .unwrap();
    assert_eq!(node_c.name.as_deref(), Some("node_c"));
    assert_eq!(node_c.private_key, priv2);
    assert_eq!(node_c.heartbeat_interval_secs, 25);
    assert_eq!(node_c.proxies.len(), 2);
    assert_eq!(node_c.proxies[0].name, "shared_web");
    assert_eq!(node_c.proxies[0].remote_port, 38080);
    assert_eq!(node_c.proxies[1].name, "only_node_c");
    assert_eq!(node_c.proxies[1].remote_port, 19000);

    // 2. `10.0.0.1:3700` has global `shared_web` (18080) + targeted `only_node_a` (15353)
    let node_a = resolved
        .iter()
        .find(|s| s.server_addr == "10.0.0.1:3700")
        .unwrap();
    assert_eq!(node_a.private_key, priv1);
    assert_eq!(node_a.heartbeat_interval_secs, 15);
    assert_eq!(node_a.proxies.len(), 2);
    assert_eq!(node_a.proxies[0].name, "shared_web");
    assert_eq!(node_a.proxies[0].remote_port, 18080);
    assert_eq!(node_a.proxies[1].name, "only_node_a");

    // 3. `10.0.0.2:3700` has only global `shared_web` (18080)
    let node_b = resolved
        .iter()
        .find(|s| s.server_addr == "10.0.0.2:3700")
        .unwrap();
    assert_eq!(node_b.proxies.len(), 1);
    assert_eq!(node_b.proxies[0].name, "shared_web");
    assert_eq!(node_b.proxies[0].remote_port, 18080);

    // 4. Conflicting duplicate proxy names on the same server must fail validation
    let conflict_cfg = ClientConfig {
        server_addr: "10.0.0.1:3700".to_string(),
        private_key: priv1,
        proxies: vec![
            ProxyConfig {
                name: "dup".to_string(),
                proxy_type: ProxyType::Tcp,
                local_addr: Some("127.0.0.1:8001".to_string()),
                remote_port: 18001,
                ..Default::default()
            },
            ProxyConfig {
                name: "dup".to_string(),
                proxy_type: ProxyType::Tcp,
                local_addr: Some("127.0.0.1:8002".to_string()),
                remote_port: 18002,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    assert!(conflict_cfg.validate().is_err());
}

#[tokio::test]
async fn test_single_client_multiple_servers_concurrent_forwarding() {
    let (priv12, pub12) = generate_keypair();
    let (priv3, pub3) = generate_keypair();

    // Local backend services
    let shared_port = get_free_port("127.0.0.1");
    let shared_local_addr = format!("127.0.0.1:{}", shared_port);
    let _ = spawn_tcp_echo_server(&shared_local_addr).await;
    let _ = spawn_udp_echo_server(&shared_local_addr).await;

    let s1_tcp_local = spawn_tcp_echo_server("127.0.0.1:0").await;
    let s2_udp_local = spawn_udp_echo_server("127.0.0.1:0").await;
    let s3_tcp_local = spawn_tcp_echo_server("127.0.0.1:0").await;

    // Start 3 independent RRP servers
    let server1 = Server::new(ServerConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        proxy_bind_ip: "127.0.0.1".to_string(),
        authorized_keys: vec![pub12.clone()],
        enable_ebpf: true,
        heartbeat_timeout_secs: 60,
    })
    .unwrap();
    let s1_addr = server1.local_addr();
    let s1_handle = tokio::spawn(async move {
        let _ = server1.run().await;
    });

    let server2 = Server::new(ServerConfig {
        bind_addr: "[::]:0".to_string(),
        proxy_bind_ip: "::".to_string(),
        authorized_keys: vec![pub12],
        enable_ebpf: true,
        heartbeat_timeout_secs: 60,
    })
    .unwrap();
    let s2_addr = format!("[::1]:{}", server2.local_addr().port());
    let s2_handle = tokio::spawn(async move {
        let _ = server2.run().await;
    });

    let server3 = Server::new(ServerConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        proxy_bind_ip: "127.0.0.1".to_string(),
        authorized_keys: vec![pub3],
        enable_ebpf: true,
        heartbeat_timeout_secs: 60,
    })
    .unwrap();
    let s3_addr = server3.local_addr();
    let s3_handle = tokio::spawn(async move {
        let _ = server3.run().await;
    });

    let remote_shared_port_s1 = get_free_port("127.0.0.1");
    let remote_shared_port_s2 = get_free_port("::1");
    let remote_s1_only_port = get_free_port("127.0.0.1");
    let remote_s2_only_port = get_free_port("::1");
    let remote_s3_port = get_free_port("127.0.0.1");

    // Configure a single client connecting to all 3 servers simultaneously
    let client_cfg = ClientConfig {
        server_addrs: vec![s1_addr.to_string(), s2_addr.clone()],
        servers: vec![
            ClientServerConfig {
                name: Some("srv2".to_string()),
                server_addr: s2_addr.clone(),
                private_key: None,
                heartbeat_interval_secs: None,
                proxies: vec![ProxyConfig {
                    name: "shared_all".to_string(),
                    proxy_type: ProxyType::All,
                    local_addr: Some(shared_local_addr.clone()),
                    remote_port: remote_shared_port_s2,
                    remote_bind_ip: Some("::1".to_string()),
                    ..Default::default()
                }],
            },
            ClientServerConfig {
                name: Some("srv3".to_string()),
                server_addr: s3_addr.to_string(),
                private_key: Some(priv3),
                heartbeat_interval_secs: Some(10),
                proxies: vec![ProxyConfig {
                    name: "s3_dedicated_tcp".to_string(),
                    proxy_type: ProxyType::Tcp,
                    local_addr: Some(s3_tcp_local.to_string()),
                    remote_port: remote_s3_port,
                    ..Default::default()
                }],
            },
        ],
        private_key: priv12,
        enable_ebpf: true,
        heartbeat_interval_secs: 10,
        proxies: vec![
            // Global proxy registered on server1 (and overridden on srv2 with remote_shared_port_s2;
            // also registered on srv3 unless targeted—let's target s1_addr for remote_shared_port_s1)
            ProxyConfig {
                name: "shared_all".to_string(),
                proxy_type: ProxyType::All,
                local_addr: Some(shared_local_addr),
                remote_port: remote_shared_port_s1,
                server_addr: Some(s1_addr.to_string()),
                ..Default::default()
            },
            ProxyConfig {
                name: "s1_only_tcp".to_string(),
                proxy_type: ProxyType::Tcp,
                local_addr: Some(s1_tcp_local.to_string()),
                remote_port: remote_s1_only_port,
                server_addr: Some(s1_addr.to_string()),
                ..Default::default()
            },
            ProxyConfig {
                name: "s2_only_udp".to_string(),
                proxy_type: ProxyType::Udp,
                local_addr: Some(s2_udp_local.to_string()),
                remote_port: remote_s2_only_port,
                remote_bind_ip: Some("::1".to_string()),
                server_addr: Some("srv2".to_string()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let client = Client::new(client_cfg).unwrap();
    assert_eq!(client.resolved_servers().len(), 3);

    let (ready_tx, ready_rx) = oneshot::channel();
    let client_handle = tokio::spawn(async move {
        let _ = client.run_session(Some(ready_tx)).await;
    });

    ready_rx.await.unwrap().unwrap();

    // Verify Server 1: shared_all (TCP + UDP) & s1_only_tcp
    let mut s1_tcp = TcpStream::connect(format!("127.0.0.1:{}", remote_shared_port_s1))
        .await
        .unwrap();
    s1_tcp.write_all(b"hello-via-server1-shared").await.unwrap();
    let mut buf = [0u8; 24];
    s1_tcp.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello-via-server1-shared");

    let mut s1_only = TcpStream::connect(format!("127.0.0.1:{}", remote_s1_only_port))
        .await
        .unwrap();
    s1_only.write_all(b"hello-s1-only").await.unwrap();
    let mut buf_s1 = [0u8; 13];
    s1_only.read_exact(&mut buf_s1).await.unwrap();
    assert_eq!(&buf_s1, b"hello-s1-only");

    // Verify Server 2 (IPv6): shared_all (TCP + UDP) & s2_only_udp
    let mut s2_tcp = TcpStream::connect(format!("[::1]:{}", remote_shared_port_s2))
        .await
        .unwrap();
    s2_tcp.write_all(b"hello-via-server2-shared").await.unwrap();
    let mut buf2 = [0u8; 24];
    s2_tcp.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"hello-via-server2-shared");

    let v6_udp = UdpSocket::bind("[::1]:0").await.unwrap();
    v6_udp
        .send_to(b"s2-only-udp-pkt", format!("[::1]:{}", remote_s2_only_port))
        .await
        .unwrap();
    let mut ubuf = [0u8; 256];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), v6_udp.recv_from(&mut ubuf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&ubuf[..n], b"udp-echo:s2-only-udp-pkt");

    // Verify Server 3 (separate keypair): s3_dedicated_tcp
    let mut s3_tcp = TcpStream::connect(format!("127.0.0.1:{}", remote_s3_port))
        .await
        .unwrap();
    s3_tcp.write_all(b"hello-via-server3-key2").await.unwrap();
    let mut buf3 = [0u8; 22];
    s3_tcp.read_exact(&mut buf3).await.unwrap();
    assert_eq!(&buf3, b"hello-via-server3-key2");

    client_handle.abort();
    s1_handle.abort();
    s2_handle.abort();
    s3_handle.abort();
}

#[tokio::test]
async fn test_multi_server_fault_isolation_and_auto_reconnect() {
    let (priv_b64, pub_b64) = generate_keypair();
    let local_tcp = spawn_tcp_echo_server("127.0.0.1:0").await;

    // Server A starts immediately
    let server_a = Server::new(ServerConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        proxy_bind_ip: "127.0.0.1".to_string(),
        authorized_keys: vec![pub_b64.clone()],
        enable_ebpf: false,
        heartbeat_timeout_secs: 60,
    })
    .unwrap();
    let server_a_addr = server_a.local_addr();
    let server_a_handle = tokio::spawn(async move {
        let _ = server_a.run().await;
    });

    // Reserve a port for Server B, which starts offline initially
    let server_b_port = get_free_port("127.0.0.1");
    let server_b_addr_str = format!("127.0.0.1:{}", server_b_port);

    let remote_port_a = get_free_port("127.0.0.1");
    let remote_port_b = get_free_port("127.0.0.1");

    let client_cfg = ClientConfig {
        server_addrs: vec![server_a_addr.to_string(), server_b_addr_str.clone()],
        private_key: priv_b64,
        enable_ebpf: false,
        heartbeat_interval_secs: 10,
        proxies: vec![
            ProxyConfig {
                name: "proxy_a".to_string(),
                proxy_type: ProxyType::Tcp,
                local_addr: Some(local_tcp.to_string()),
                remote_port: remote_port_a,
                server_addr: Some(server_a_addr.to_string()),
                ..Default::default()
            },
            ProxyConfig {
                name: "proxy_b".to_string(),
                proxy_type: ProxyType::Tcp,
                local_addr: Some(local_tcp.to_string()),
                remote_port: remote_port_b,
                server_addr: Some(server_b_addr_str.clone()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let client = Client::new(client_cfg).unwrap();
    let (all_ready_tx, all_ready_rx) = oneshot::channel();
    let client_handle = tokio::spawn(async move {
        let _ = client.run_with_ready(Some(all_ready_tx)).await;
    });

    // Even though Server B is offline, Server A should connect and forward traffic within 1s
    let mut connected_a = None;
    for _ in 0..20 {
        if let Ok(stream) = TcpStream::connect(format!("127.0.0.1:{}", remote_port_a)).await {
            connected_a = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut visitor_a = connected_a.expect("Server A should accept visitor while Server B is down");
    visitor_a.write_all(b"server-a-isolated").await.unwrap();
    let mut buf_a = [0u8; 17];
    visitor_a.read_exact(&mut buf_a).await.unwrap();
    assert_eq!(&buf_a, b"server-a-isolated");

    // Now bring Server B online; the client supervisor for Server B will auto-connect and register
    let server_b = Server::new(ServerConfig {
        bind_addr: server_b_addr_str,
        proxy_bind_ip: "127.0.0.1".to_string(),
        authorized_keys: vec![pub_b64],
        enable_ebpf: false,
        heartbeat_timeout_secs: 60,
    })
    .unwrap();
    let server_b_handle = tokio::spawn(async move {
        let _ = server_b.run().await;
    });

    // Wait for `all_ready_rx` to signal that both Server A and Server B have registered
    tokio::time::timeout(Duration::from_secs(6), all_ready_rx)
        .await
        .expect("timed out waiting for Server B auto-reconnect")
        .unwrap()
        .unwrap();

    let mut visitor_b = TcpStream::connect(format!("127.0.0.1:{}", remote_port_b))
        .await
        .unwrap();
    visitor_b.write_all(b"server-b-reconnected").await.unwrap();
    let mut buf_b = [0u8; 20];
    visitor_b.read_exact(&mut buf_b).await.unwrap();
    assert_eq!(&buf_b, b"server-b-reconnected");

    client_handle.abort();
    server_a_handle.abort();
    server_b_handle.abort();
}

#[test]
fn test_install_preserves_existing_key_and_restricts_permissions() {
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("rrpc.toml");

    let first = install_client_key_with(&cfg_path, false).unwrap();
    assert!(first.generated);

    // Re-running install (e.g. to add --autostart later) must not rotate the key.
    let second = install_client_key_with(&cfg_path, false).unwrap();
    assert!(!second.generated);
    assert_eq!(second.private_key, first.private_key);
    assert_eq!(second.public_key, first.public_key);
    let (kept_priv, kept_pub) = install_client_key(&cfg_path).unwrap();
    assert_eq!(kept_priv, first.private_key);
    assert_eq!(kept_pub, first.public_key);

    // Explicit rotation produces a different keypair and persists it.
    let rotated = install_client_key_with(&cfg_path, true).unwrap();
    assert!(rotated.generated);
    assert_ne!(rotated.private_key, first.private_key);
    assert_eq!(
        ClientConfig::load(&cfg_path).unwrap().private_key,
        rotated.private_key
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&cfg_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "client config holding a private key must be 0600"
        );
    }
}

#[test]
fn test_malformed_configs_are_never_overwritten() {
    let dir = tempdir().unwrap();

    let client_cfg = dir.path().join("rrpc.toml");
    fs::write(&client_cfg, "this is = not [valid toml").unwrap();
    let before = fs::read_to_string(&client_cfg).unwrap();
    assert!(install_client_key(&client_cfg).is_err());
    assert_eq!(fs::read_to_string(&client_cfg).unwrap(), before);

    let server_cfg = dir.path().join("rrps.toml");
    fs::write(&server_cfg, "authorized_keys = [ \"unterminated").unwrap();
    let before = fs::read_to_string(&server_cfg).unwrap();
    let (_priv, pub_b64) = generate_keypair();
    assert!(approve_client_key(&server_cfg, &pub_b64).is_err());
    assert_eq!(fs::read_to_string(&server_cfg).unwrap(), before);

    // A valid server config with an existing key keeps that key when another is approved.
    let (_p1, pub1) = generate_keypair();
    let (_p2, pub2) = generate_keypair();
    assert!(approve_client_key(&client_cfg.with_extension("srv.toml"), &pub1).unwrap());
    assert!(approve_client_key(&client_cfg.with_extension("srv.toml"), &pub2).unwrap());
    let loaded = ServerConfig::load(&client_cfg.with_extension("srv.toml")).unwrap();
    assert_eq!(loaded.authorized_keys, vec![pub1, pub2]);
}

#[test]
fn test_config_validation_rejects_conflicts_and_bad_addresses() {
    let (priv_b64, _pub) = generate_keypair();
    let base = ClientConfig {
        server_addr: "10.0.0.1:3700".to_string(),
        private_key: priv_b64,
        proxies: vec![],
        ..Default::default()
    };

    let proxy = |name: &str, ty: ProxyType, port: u16| ProxyConfig {
        name: name.to_string(),
        proxy_type: ty,
        local_addr: Some("127.0.0.1:8080".to_string()),
        remote_port: port,
        ..Default::default()
    };

    // Two TCP proxies on one remote port cannot both bind on the server.
    let mut tcp_clash = base.clone();
    tcp_clash.proxies = vec![
        proxy("a", ProxyType::Tcp, 18080),
        proxy("b", ProxyType::All, 18080),
    ];
    let err = tcp_clash.validate().unwrap_err().to_string();
    assert!(err.contains("both bind TCP remote_port 18080"), "{err}");

    // TCP and UDP on the same port is fine.
    let mut mixed = base.clone();
    mixed.proxies = vec![
        proxy("a", ProxyType::Tcp, 18080),
        proxy("b", ProxyType::Udp, 18080),
    ];
    mixed.validate().unwrap();

    // Different bind IPs on the same port are fine too.
    let mut split_ip = base.clone();
    let mut v4 = proxy("a", ProxyType::Tcp, 18080);
    v4.remote_bind_ip = Some("127.0.0.1".to_string());
    let mut v6 = proxy("b", ProxyType::Tcp, 18080);
    v6.remote_bind_ip = Some("::1".to_string());
    split_ip.proxies = vec![v4, v6];
    split_ip.validate().unwrap();

    // Malformed addresses are caught at load time rather than at the first registration.
    let mut bad_bind_ip = base.clone();
    let mut p = proxy("a", ProxyType::Tcp, 18080);
    p.remote_bind_ip = Some("not-an-ip".to_string());
    bad_bind_ip.proxies = vec![p];
    assert!(bad_bind_ip.validate().is_err());

    let mut bad_local = base.clone();
    let mut p = proxy("a", ProxyType::Tcp, 18080);
    p.local_addr = Some("127.0.0.1".to_string());
    bad_local.proxies = vec![p];
    assert!(bad_local.validate().is_err());

    let bad_server = ServerConfig {
        bind_addr: "3700".to_string(),
        ..Default::default()
    };
    assert!(bad_server.validate().is_err());
    let bad_proxy_ip = ServerConfig {
        proxy_bind_ip: "[::".to_string(),
        ..Default::default()
    };
    assert!(bad_proxy_ip.validate().is_err());
    ServerConfig::default().validate().unwrap();
}

#[test]
fn test_control_messages_never_span_multiple_frames() {
    let v6_visitor: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
    // The server's receive buffer can yield up to 65535 bytes; with the tag, name and IPv6
    // visitor address header that exceeds MAX_FRAME_PAYLOAD_LEN. Splitting it would
    // desynchronize the control channel, so encoding must refuse instead.
    let too_big = TunnelFrame::UdpDatagram {
        proxy_name: "udp".to_string(),
        visitor_addr: v6_visitor,
        payload: vec![0u8; 65_535].into(),
    };
    assert!(too_big.encode().is_err());

    let fits = TunnelFrame::UdpDatagram {
        proxy_name: "udp".to_string(),
        visitor_addr: v6_visitor,
        payload: vec![0u8; MAX_FRAME_PAYLOAD_LEN - 64].into(),
    };
    let encoded = fits.encode().unwrap();
    assert!(encoded.len() <= MAX_FRAME_PAYLOAD_LEN);
    match TunnelFrame::decode(encoded).unwrap() {
        TunnelFrame::UdpDatagram {
            visitor_addr,
            payload,
            ..
        } => {
            assert_eq!(visitor_addr, v6_visitor);
            assert_eq!(payload.len(), MAX_FRAME_PAYLOAD_LEN - 64);
        }
        other => panic!("unexpected frame {other:?}"),
    }

    let huge_registration = RoleHandshake::Control {
        proxies: (0..2_000)
            .map(|i| ProxySpec {
                name: format!("proxy_{i}"),
                proxy_type: ProxyType::Tcp,
                local_addr: "127.0.0.1:8080".to_string(),
                remote_port: 10_000 + i as u16,
                remote_bind_ip: None,
            })
            .collect(),
    };
    assert!(huge_registration.encode().is_err());
}

#[tokio::test]
async fn test_work_connection_cannot_be_claimed_by_another_client() {
    let (priv_a, pub_a) = generate_keypair();
    let (priv_b, pub_b) = generate_keypair();
    let key_a = ClientKeyPair::from_base64(&priv_a).unwrap();
    let key_b = ClientKeyPair::from_base64(&priv_b).unwrap();

    let server = Server::new(ServerConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        proxy_bind_ip: "127.0.0.1".to_string(),
        authorized_keys: vec![pub_a, pub_b],
        enable_ebpf: false,
        heartbeat_timeout_secs: 60,
    })
    .unwrap();
    let server_addr = server.local_addr().to_string();
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Client A opens a bare control session that registers a TCP proxy but handles work-connection
    // requests manually, so the test controls exactly who answers them.
    let remote_port = get_free_port("127.0.0.1");
    let ctrl = connect_tcp(&server_addr).await.unwrap();
    let mut ctrl = client_handshake(ctrl, &key_a).await.unwrap();
    let role = RoleHandshake::Control {
        proxies: vec![ProxySpec {
            name: "guarded".to_string(),
            proxy_type: ProxyType::Tcp,
            local_addr: "127.0.0.1:1".to_string(),
            remote_port,
            remote_bind_ip: None,
        }],
    };
    ctrl.send_frame(&role.encode().unwrap()).await.unwrap();
    match TunnelFrame::decode(ctrl.recv_frame().await.unwrap().unwrap()).unwrap() {
        TunnelFrame::Signal(ControlSignal::RegisterAck { success, message }) => {
            assert!(success, "{message}");
        }
        other => panic!("unexpected frame {other:?}"),
    }

    // A visitor arrives; the server asks client A for a work connection with some conn_id.
    let mut visitor = TcpStream::connect(format!("127.0.0.1:{remote_port}"))
        .await
        .unwrap();
    let conn_id = loop {
        let raw = tokio::time::timeout(Duration::from_secs(5), ctrl.recv_frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let TunnelFrame::Signal(ControlSignal::ReqWorkConn {
            conn_id,
            proxy_name,
            ..
        }) = TunnelFrame::decode(raw).unwrap()
        {
            assert_eq!(proxy_name, "guarded");
            break conn_id;
        }
    };

    // Client B (authorized, but a different identity) tries to claim that conn_id.
    let rogue = connect_tcp(&server_addr).await.unwrap();
    let mut rogue = client_handshake(rogue, &key_b).await.unwrap();
    let steal = RoleHandshake::WorkTcp {
        conn_id,
        proxy_name: "guarded".to_string(),
    };
    rogue.send_frame(&steal.encode().unwrap()).await.unwrap();
    // The server must refuse and close the connection rather than relay the visitor to B.
    let rogue_result = tokio::time::timeout(Duration::from_secs(5), rogue.recv_frame())
        .await
        .expect("server should close the rogue work connection promptly");
    assert!(
        matches!(rogue_result, Ok(None) | Err(_)),
        "rogue client received visitor traffic: {rogue_result:?}"
    );

    // Client A, using the wrong proxy name, is refused as well.
    let wrong_proxy = connect_tcp(&server_addr).await.unwrap();
    let mut wrong_proxy = client_handshake(wrong_proxy, &key_a).await.unwrap();
    let role = RoleHandshake::WorkTcp {
        conn_id,
        proxy_name: "other".to_string(),
    };
    wrong_proxy
        .send_frame(&role.encode().unwrap())
        .await
        .unwrap();
    let wrong_result = tokio::time::timeout(Duration::from_secs(5), wrong_proxy.recv_frame())
        .await
        .unwrap();
    assert!(matches!(wrong_result, Ok(None) | Err(_)));

    // The legitimate owner can still claim it and receives the visitor's bytes.
    let work = connect_tcp(&server_addr).await.unwrap();
    let mut work = client_handshake(work, &key_a).await.unwrap();
    let role = RoleHandshake::WorkTcp {
        conn_id,
        proxy_name: "guarded".to_string(),
    };
    work.send_frame(&role.encode().unwrap()).await.unwrap();
    visitor.write_all(b"only-for-client-a").await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), work.recv_frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&got[..], b"only-for-client-a");

    server_handle.abort();
}
