use std::env;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rrp::cli::{Cli, Commands, RunMode, DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_SERVER_CONFIG_PATH};
use rrp::client::run_client;
use rrp::config::{approve_client_key, install_client_key_with, ClientConfig, ServerConfig};
use rrp::server::run_server;
use rrp::service::{install_autostart_service, uninstall_rrp, ServicePlatform};
use rrp::status::{load_statuses, render_human, render_json};

#[tokio::main]
async fn main() -> Result<()> {
    // netlink-packet-route warns (harmlessly) whenever a newer kernel appends fields to link
    // attributes it knows; keep that off the default log level.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,netlink_packet_route=error")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { config } => {
            let cfg = ServerConfig::load(&config)?;
            run_server(cfg).await
        }
        Commands::Client {
            config,
            server_addr,
        } => {
            let mut cfg = ClientConfig::load_unvalidated(&config)?;
            if !server_addr.is_empty() {
                cfg.server_addr.clear();
                cfg.server_addrs = server_addr;
            }
            cfg.validate()?;
            run_client(cfg).await
        }
        Commands::Install {
            mode,
            config,
            autostart,
            service_dir,
            regenerate_key,
        } => {
            let cfg_path = config.unwrap_or_else(|| match mode {
                RunMode::Client => PathBuf::from(DEFAULT_CLIENT_CONFIG_PATH),
                RunMode::Server => PathBuf::from(DEFAULT_SERVER_CONFIG_PATH),
            });

            match mode {
                RunMode::Client => {
                    let installed = install_client_key_with(&cfg_path, regenerate_key)?;
                    if installed.generated {
                        println!(
                            "Generated mlkem768x25519 keypair and wrote private_key to {}",
                            cfg_path.display()
                        );
                    } else {
                        println!(
                            "Kept existing mlkem768x25519 keypair in {} (use --regenerate-key to rotate)",
                            cfg_path.display()
                        );
                    }
                    println!("Public key (run `rrp approve` on server):");
                    println!("{}", installed.public_key);
                }
                RunMode::Server => {
                    if cfg_path.exists() {
                        // Validate rather than touch an existing file.
                        ServerConfig::load(&cfg_path)?;
                        println!("Server config already present at {}", cfg_path.display());
                    } else {
                        ServerConfig::default().save(&cfg_path)?;
                        println!("Initialized server config at {}", cfg_path.display());
                    }
                }
            }

            if autostart {
                let exe_path =
                    env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/rrp"));
                let platform = ServicePlatform::current();
                let service_file = install_autostart_service(
                    platform,
                    mode,
                    &exe_path,
                    &cfg_path,
                    service_dir.as_deref(),
                )?;
                info!(
                    "installed system autostart service at {}",
                    service_file.display()
                );
                println!("Installed autostart service at {}", service_file.display());
            }

            Ok(())
        }
        Commands::Uninstall {
            mode,
            config,
            purge,
            service_dir,
        } => {
            let exe_path =
                env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/rrp"));
            let platform = ServicePlatform::current();
            let report = uninstall_rrp(
                platform,
                mode,
                config.as_deref(),
                purge,
                purge.then_some(exe_path.as_path()),
                service_dir.as_deref(),
            )?;

            if report.removed_services.is_empty() {
                println!("No autostart service found to uninstall");
            } else {
                for svc in &report.removed_services {
                    info!("uninstalled system autostart service at {}", svc.display());
                    println!("Uninstalled autostart service at {}", svc.display());
                }
            }

            if purge {
                for cfg in &report.removed_configs {
                    info!("removed configuration file at {}", cfg.display());
                    println!("Removed configuration file at {}", cfg.display());
                }
                if let Some(bin) = &report.removed_binary {
                    info!("removed rrp binary at {}", bin.display());
                    println!("Removed rrp binary at {}", bin.display());
                }
            }

            Ok(())
        }
        Commands::Approve { public_key, config } => {
            let added = approve_client_key(&config, &public_key)?;
            if added {
                println!(
                    "Approved mlkem768x25519 public key and saved to {}",
                    config.display()
                );
            } else {
                println!("Public key already exists in {}", config.display());
            }
            Ok(())
        }
        Commands::Status { mode, json, file } => {
            let snapshots = load_statuses(mode, file.as_deref())?;
            if json {
                println!("{}", render_json(&snapshots)?);
            } else {
                println!("{}", render_human(&snapshots));
            }
            Ok(())
        }
    }
}
