use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::cli::{RunMode, DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_SERVER_CONFIG_PATH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePlatform {
    LinuxSystemd,
    MacosLaunchd,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    pub removed_services: Vec<PathBuf>,
    pub removed_configs: Vec<PathBuf>,
    pub removed_binary: Option<PathBuf>,
}

impl ServicePlatform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            ServicePlatform::MacosLaunchd
        } else {
            ServicePlatform::LinuxSystemd
        }
    }
}

/// Generate Linux systemd unit content for rrp.
pub fn generate_systemd_unit(bin_path: &Path, config_path: &Path, mode: RunMode) -> String {
    let mode_str = mode.as_str();
    format!(
        "[Unit]\n\
Description=RRP (Rust Reverse Proxy) - {mode_str} service\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=\"{bin}\" {mode_str} -c \"{cfg}\"\n\
Restart=always\n\
RestartSec=5s\n\
LimitNOFILE=1048576\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n",
        mode_str = mode_str,
        bin = bin_path.display(),
        cfg = config_path.display()
    )
}

/// Generate macOS launchd plist content for rrp.
pub fn generate_launchd_plist(bin_path: &Path, config_path: &Path, mode: RunMode) -> String {
    let mode_str = mode.as_str();
    let label = format!("com.rrp.{}", mode_str);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key>\n\
    <string>{label}</string>\n\
    <key>ProgramArguments</key>\n\
    <array>\n\
        <string>{bin}</string>\n\
        <string>{mode_str}</string>\n\
        <string>-c</string>\n\
        <string>{cfg}</string>\n\
    </array>\n\
    <key>RunAtLoad</key>\n\
    <true/>\n\
    <key>KeepAlive</key>\n\
    <true/>\n\
    <key>StandardOutPath</key>\n\
    <string>/var/log/rrp-{mode_str}.log</string>\n\
    <key>StandardErrorPath</key>\n\
    <string>/var/log/rrp-{mode_str}.err.log</string>\n\
</dict>\n\
</plist>\n",
        label = label,
        bin = bin_path.display(),
        mode_str = mode_str,
        cfg = config_path.display()
    )
}

/// Install system-level autostart service for Linux (systemd) or macOS (launchd).
/// Returns the path of the written service file.
pub fn install_autostart_service(
    platform: ServicePlatform,
    mode: RunMode,
    bin_path: &Path,
    config_path: &Path,
    custom_dir: Option<&Path>,
) -> Result<PathBuf> {
    let abs_bin = fs::canonicalize(bin_path).unwrap_or_else(|_| bin_path.to_path_buf());
    let abs_cfg = fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    let mode_str = mode.as_str();

    match platform {
        ServicePlatform::LinuxSystemd => {
            let dir = custom_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create systemd directory {}", dir.display()))?;

            let service_name = format!("rrp-{}.service", mode_str);
            let service_path = dir.join(&service_name);
            let content = generate_systemd_unit(&abs_bin, &abs_cfg, mode);
            fs::write(&service_path, content).with_context(|| {
                format!(
                    "failed to write systemd service file to {}",
                    service_path.display()
                )
            })?;

            if custom_dir.is_none() {
                let reload = Command::new("systemctl").arg("daemon-reload").status();
                let enable = Command::new("systemctl")
                    .args(["enable", &service_name])
                    .status();
                match (reload, enable) {
                    (Ok(r), Ok(e)) if r.success() && e.success() => {
                        info!("enabled systemd autostart service: {}", service_name);
                    }
                    _ => {
                        warn!(
                            "wrote {}, but `systemctl enable` could not complete (try running with sudo)",
                            service_path.display()
                        );
                    }
                }
            }
            Ok(service_path)
        }
        ServicePlatform::MacosLaunchd => {
            let dir = custom_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/Library/LaunchDaemons"));
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create LaunchDaemons directory {}", dir.display()))?;

            let plist_name = format!("com.rrp.{}.plist", mode_str);
            let plist_path = dir.join(&plist_name);
            let content = generate_launchd_plist(&abs_bin, &abs_cfg, mode);
            fs::write(&plist_path, content).with_context(|| {
                format!(
                    "failed to write launchd plist file to {}",
                    plist_path.display()
                )
            })?;

            if custom_dir.is_none() {
                let status = Command::new("launchctl")
                    .args(["load", "-w", &plist_path.to_string_lossy()])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        info!("loaded launchd autostart service: {}", plist_name);
                    }
                    _ => {
                        warn!(
                            "wrote {}, but `launchctl load -w` could not complete (try running with sudo)",
                            plist_path.display()
                        );
                    }
                }
            }
            Ok(plist_path)
        }
    }
}

/// Return the path of the autostart service file for the given platform and mode.
pub fn service_file_path(
    platform: ServicePlatform,
    mode: RunMode,
    custom_dir: Option<&Path>,
) -> PathBuf {
    let mode_str = mode.as_str();
    match platform {
        ServicePlatform::LinuxSystemd => {
            let dir = custom_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
            dir.join(format!("rrp-{}.service", mode_str))
        }
        ServicePlatform::MacosLaunchd => {
            let dir = custom_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/Library/LaunchDaemons"));
            dir.join(format!("com.rrp.{}.plist", mode_str))
        }
    }
}

/// Extract the configuration file path (`-c <path>`) embedded in a systemd unit or launchd plist.
pub fn extract_config_path_from_service(content: &str) -> Option<PathBuf> {
    // 1. Check systemd unit `ExecStart="..." <mode> -c "<cfg>"`
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("ExecStart=") {
            if let Some(idx) = rest.find(" -c \"") {
                let after = &rest[idx + 5..];
                if let Some(end_quote) = after.rfind('"') {
                    let path_str = &after[..end_quote];
                    if !path_str.is_empty() {
                        return Some(PathBuf::from(path_str));
                    }
                }
            }
        }
    }

    // 2. Check macOS launchd plist `<string>-c</string>` followed by `<string><cfg></string>`
    let mut lines = content.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if line == "<string>-c</string>" {
            if let Some(next_line) = lines.next() {
                if let Some(inner) = next_line
                    .strip_prefix("<string>")
                    .and_then(|s| s.strip_suffix("</string>"))
                {
                    if !inner.is_empty() {
                        return Some(PathBuf::from(inner));
                    }
                }
            }
        }
    }

    None
}

/// Uninstall system-level autostart service for Linux (systemd) or macOS (launchd).
/// Returns `Ok(Some(path))` if the service file existed and was removed, or `Ok(None)` if not found.
pub fn uninstall_autostart_service(
    platform: ServicePlatform,
    mode: RunMode,
    custom_dir: Option<&Path>,
) -> Result<Option<PathBuf>> {
    let service_path = service_file_path(platform, mode, custom_dir);
    if !service_path.exists() {
        return Ok(None);
    }

    let mode_str = mode.as_str();
    match platform {
        ServicePlatform::LinuxSystemd => {
            let service_name = format!("rrp-{}.service", mode_str);
            if custom_dir.is_none() {
                let stop = Command::new("systemctl")
                    .args(["stop", &service_name])
                    .status();
                let disable = Command::new("systemctl")
                    .args(["disable", &service_name])
                    .status();
                match (stop, disable) {
                    (Ok(s), Ok(d)) if s.success() && d.success() => {
                        info!(
                            "stopped and disabled systemd autostart service: {}",
                            service_name
                        );
                    }
                    _ => {
                        warn!(
                            "removing {}, but `systemctl stop/disable` could not complete (try running with sudo)",
                            service_path.display()
                        );
                    }
                }
            }

            fs::remove_file(&service_path).with_context(|| {
                format!(
                    "failed to remove systemd service file {}",
                    service_path.display()
                )
            })?;

            if custom_dir.is_none() {
                let _ = Command::new("systemctl").arg("daemon-reload").status();
            }

            Ok(Some(service_path))
        }
        ServicePlatform::MacosLaunchd => {
            let plist_name = format!("com.rrp.{}.plist", mode_str);
            if custom_dir.is_none() {
                let status = Command::new("launchctl")
                    .args(["unload", "-w", &service_path.to_string_lossy()])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        info!("unloaded launchd autostart service: {}", plist_name);
                    }
                    _ => {
                        warn!(
                            "removing {}, but `launchctl unload -w` could not complete (try running with sudo)",
                            service_path.display()
                        );
                    }
                }
            }

            fs::remove_file(&service_path).with_context(|| {
                format!(
                    "failed to remove launchd plist file {}",
                    service_path.display()
                )
            })?;

            Ok(Some(service_path))
        }
    }
}

/// Uninstall autostart service(s) and, when `purge` is enabled, remove configuration file(s) and binary.
pub fn uninstall_rrp(
    platform: ServicePlatform,
    mode: Option<RunMode>,
    explicit_config: Option<&Path>,
    purge: bool,
    bin_path: Option<&Path>,
    custom_service_dir: Option<&Path>,
) -> Result<UninstallReport> {
    let modes: Vec<RunMode> = match mode {
        Some(m) => vec![m],
        None => vec![RunMode::Client, RunMode::Server],
    };

    let mut report = UninstallReport::default();
    let mut discovered_configs: Vec<PathBuf> = Vec::new();

    for &m in &modes {
        let svc_path = service_file_path(platform, m, custom_service_dir);
        if purge && svc_path.exists() {
            if let Ok(content) = fs::read_to_string(&svc_path) {
                if let Some(cfg_path) = extract_config_path_from_service(&content) {
                    discovered_configs.push(cfg_path);
                }
            }
        }
        if let Some(removed_path) = uninstall_autostart_service(platform, m, custom_service_dir)? {
            report.removed_services.push(removed_path);
        }
    }

    if purge {
        let mut config_candidates: Vec<PathBuf> = Vec::new();
        if let Some(cfg) = explicit_config {
            config_candidates.push(cfg.to_path_buf());
        }
        for cfg in discovered_configs {
            if !config_candidates.iter().any(|c| c == &cfg) {
                config_candidates.push(cfg);
            }
        }
        if explicit_config.is_none() {
            for &m in &modes {
                let default_cfg = match m {
                    RunMode::Client => PathBuf::from(DEFAULT_CLIENT_CONFIG_PATH),
                    RunMode::Server => PathBuf::from(DEFAULT_SERVER_CONFIG_PATH),
                };
                if !config_candidates.iter().any(|c| c == &default_cfg) {
                    config_candidates.push(default_cfg);
                }
            }
        }

        for cfg_path in config_candidates {
            if cfg_path.exists() {
                fs::remove_file(&cfg_path).with_context(|| {
                    format!("failed to remove config file {}", cfg_path.display())
                })?;
                if let Some(parent) = cfg_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        // Best-effort cleanup if config directory is now empty
                        let _ = fs::remove_dir(parent);
                    }
                }
                report.removed_configs.push(cfg_path);
            }
        }

        if let Some(bin) = bin_path {
            if bin.exists() {
                fs::remove_file(bin)
                    .with_context(|| format!("failed to remove binary {}", bin.display()))?;
                report.removed_binary = Some(bin.to_path_buf());
            }
        }
    }

    Ok(report)
}
