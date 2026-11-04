//! Admission control for the control port.
//!
//! Everything that reaches the control listener is unauthenticated until the mlkem768x25519plus
//! handshake completes, and a peer that never sends its `ClientHello` cannot be told apart from a
//! slow legitimate client until the hello timeout expires. This module bounds how much of the
//! server a peer can occupy while in that state:
//!
//! - a global cap on connections that are still in the handshake,
//! - a per-IP cap on the same,
//! - a temporary ban for IPs that keep failing the handshake (garbage, silence, unknown key).
//!
//! Refused connections are closed at `accept` time without spawning a task.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::warn;

use crate::config::HandshakeGuardConfig;

/// Entries older than this are purged opportunistically so the failure table stays bounded even
/// under a long scan from many addresses.
const FAILURE_TABLE_PURGE_THRESHOLD: usize = 4096;
/// How often "global handshake limit reached" is logged, so a flood does not flood the log too.
const GLOBAL_LIMIT_WARN_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The address exceeded `failure_limit` handshake failures within `ban_secs`.
    Banned { remaining: Duration },
    /// `max_pending` connections are already inside the handshake.
    GlobalLimit,
    /// `max_pending_per_ip` connections from this address are already inside the handshake.
    PerIpLimit,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Banned { remaining } => {
                write!(f, "address is banned for another {}s", remaining.as_secs())
            }
            Refusal::GlobalLimit => write!(f, "global pending-handshake limit reached"),
            Refusal::PerIpLimit => write!(f, "per-IP pending-handshake limit reached"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FailureRecord {
    count: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

pub struct HandshakeGuard {
    config: HandshakeGuardConfig,
    pending_total: AtomicUsize,
    pending_per_ip: DashMap<IpAddr, u32>,
    failures: DashMap<IpAddr, FailureRecord>,
    last_global_warn: Mutex<Option<Instant>>,
}

/// Held while a connection is inside the handshake; dropping it releases the slot.
pub struct HandshakePermit {
    guard: Arc<HandshakeGuard>,
    ip: IpAddr,
}

impl std::fmt::Debug for HandshakePermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakePermit")
            .field("ip", &self.ip)
            .finish()
    }
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        self.guard.release(self.ip);
    }
}

impl HandshakeGuard {
    pub fn new(config: HandshakeGuardConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            pending_total: AtomicUsize::new(0),
            pending_per_ip: DashMap::new(),
            failures: DashMap::new(),
            last_global_warn: Mutex::new(None),
        })
    }

    pub fn config(&self) -> &HandshakeGuardConfig {
        &self.config
    }

    /// Number of connections currently inside the handshake.
    pub fn pending(&self) -> usize {
        self.pending_total.load(Ordering::Relaxed)
    }

    /// Admit a freshly accepted connection from `ip`, or say why it must be closed right away.
    pub fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Result<HandshakePermit, Refusal> {
        self.try_admit_at(ip, Instant::now())
    }

    fn try_admit_at(
        self: &Arc<Self>,
        ip: IpAddr,
        now: Instant,
    ) -> Result<HandshakePermit, Refusal> {
        if let Some(remaining) = self.ban_remaining(ip, now) {
            return Err(Refusal::Banned { remaining });
        }

        let max_pending = self.config.max_pending as usize;
        if max_pending > 0 {
            let mut current = self.pending_total.load(Ordering::Acquire);
            loop {
                if current >= max_pending {
                    self.warn_global_limit(now);
                    return Err(Refusal::GlobalLimit);
                }
                match self.pending_total.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
        } else {
            self.pending_total.fetch_add(1, Ordering::AcqRel);
        }

        let per_ip_limit = self.config.max_pending_per_ip;
        let mut per_ip = self.pending_per_ip.entry(ip).or_insert(0);
        if per_ip_limit > 0 && *per_ip >= per_ip_limit {
            drop(per_ip);
            self.pending_total.fetch_sub(1, Ordering::AcqRel);
            return Err(Refusal::PerIpLimit);
        }
        *per_ip += 1;
        drop(per_ip);

        Ok(HandshakePermit {
            guard: Arc::clone(self),
            ip,
        })
    }

    fn release(&self, ip: IpAddr) {
        self.pending_total.fetch_sub(1, Ordering::AcqRel);
        if let Some(mut per_ip) = self.pending_per_ip.get_mut(&ip) {
            *per_ip = per_ip.saturating_sub(1);
            let empty = *per_ip == 0;
            drop(per_ip);
            if empty {
                self.pending_per_ip.remove_if(&ip, |_, count| *count == 0);
            }
        }
    }

    /// Record a handshake that failed before authentication. Returns `true` when this failure
    /// started a ban for the address.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        self.record_failure_at(ip, Instant::now())
    }

    fn record_failure_at(&self, ip: IpAddr, now: Instant) -> bool {
        let limit = self.config.failure_limit;
        if limit == 0 {
            return false;
        }
        let window = Duration::from_secs(self.config.ban_secs);

        if self.failures.len() > FAILURE_TABLE_PURGE_THRESHOLD {
            self.purge_expired(now);
        }

        let mut entry = self.failures.entry(ip).or_insert(FailureRecord {
            count: 0,
            window_start: now,
            banned_until: None,
        });
        if entry.banned_until.is_some_and(|until| until > now) {
            return false;
        }
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
            entry.banned_until = None;
        }
        entry.count += 1;
        if entry.count >= limit {
            entry.banned_until = Some(now + window);
            entry.count = 0;
            entry.window_start = now;
            drop(entry);
            warn!(
                "banning {} from the control port for {}s after {} failed handshakes",
                ip, self.config.ban_secs, limit
            );
            return true;
        }
        false
    }

    fn ban_remaining(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let record = self.failures.get(&ip)?;
        match record.banned_until {
            Some(until) if until > now => Some(until - now),
            _ => {
                let window = Duration::from_secs(self.config.ban_secs);
                let stale = now.duration_since(record.window_start) >= window;
                drop(record);
                if stale {
                    self.failures.remove_if(&ip, |_, record| {
                        record.banned_until.is_none_or(|until| until <= now)
                    });
                }
                None
            }
        }
    }

    fn purge_expired(&self, now: Instant) {
        let window = Duration::from_secs(self.config.ban_secs);
        self.failures.retain(|_, record| {
            record.banned_until.is_some_and(|until| until > now)
                || now.duration_since(record.window_start) < window
        });
    }

    fn warn_global_limit(&self, now: Instant) {
        let mut last = self
            .last_global_warn
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|at| now.duration_since(at) < GLOBAL_LIMIT_WARN_INTERVAL) {
            return;
        }
        *last = Some(now);
        warn!(
            "control port has {} connections waiting in the handshake (max_pending); new connections are being closed",
            self.config.max_pending
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn cfg(
        max_pending: u32,
        per_ip: u32,
        failure_limit: u32,
        ban_secs: u64,
    ) -> HandshakeGuardConfig {
        HandshakeGuardConfig {
            hello_timeout_secs: 3,
            max_pending,
            max_pending_per_ip: per_ip,
            failure_limit,
            ban_secs,
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn per_ip_and_global_limits_release_on_drop() {
        let guard = HandshakeGuard::new(cfg(3, 2, 0, 60));
        let a1 = guard.try_admit(ip(1)).unwrap();
        let a2 = guard.try_admit(ip(1)).unwrap();
        assert_eq!(guard.try_admit(ip(1)).unwrap_err(), Refusal::PerIpLimit);
        let b1 = guard.try_admit(ip(2)).unwrap();
        assert_eq!(guard.try_admit(ip(2)).unwrap_err(), Refusal::GlobalLimit);
        assert_eq!(guard.pending(), 3);

        drop(a1);
        assert_eq!(guard.pending(), 2);
        let b2 = guard.try_admit(ip(2)).unwrap();
        assert_eq!(guard.try_admit(ip(3)).unwrap_err(), Refusal::GlobalLimit);

        drop((a2, b1, b2));
        assert_eq!(guard.pending(), 0);
        assert!(guard.pending_per_ip.is_empty());
    }

    #[test]
    fn zero_limits_disable_the_caps() {
        let guard = HandshakeGuard::new(cfg(0, 0, 0, 60));
        let permits: Vec<_> = (0..100).map(|_| guard.try_admit(ip(1)).unwrap()).collect();
        assert_eq!(guard.pending(), 100);
        drop(permits);
        assert_eq!(guard.pending(), 0);
        for _ in 0..100 {
            assert!(!guard.record_failure(ip(1)));
        }
        assert!(guard.failures.is_empty());
    }

    #[test]
    fn repeated_failures_ban_then_expire() {
        let guard = HandshakeGuard::new(cfg(0, 0, 3, 60));
        let t0 = Instant::now();
        assert!(!guard.record_failure_at(ip(1), t0));
        assert!(!guard.record_failure_at(ip(1), t0 + Duration::from_secs(10)));
        assert!(guard
            .try_admit_at(ip(1), t0 + Duration::from_secs(11))
            .is_ok());
        assert!(guard.record_failure_at(ip(1), t0 + Duration::from_secs(20)));

        let refusal = guard
            .try_admit_at(ip(1), t0 + Duration::from_secs(30))
            .unwrap_err();
        assert!(
            matches!(refusal, Refusal::Banned { remaining } if remaining == Duration::from_secs(50))
        );
        // Other addresses are unaffected.
        assert!(guard
            .try_admit_at(ip(2), t0 + Duration::from_secs(30))
            .is_ok());
        // Failures while banned do not extend the ban.
        assert!(!guard.record_failure_at(ip(1), t0 + Duration::from_secs(40)));
        assert!(guard
            .try_admit_at(ip(1), t0 + Duration::from_secs(79))
            .is_err());
        assert!(guard
            .try_admit_at(ip(1), t0 + Duration::from_secs(80))
            .is_ok());
    }

    #[test]
    fn failure_window_resets_when_failures_are_spread_out() {
        let guard = HandshakeGuard::new(cfg(0, 0, 3, 60));
        let t0 = Instant::now();
        assert!(!guard.record_failure_at(ip(1), t0));
        assert!(!guard.record_failure_at(ip(1), t0 + Duration::from_secs(30)));
        // The window restarts here, so the next two failures stay below the limit.
        assert!(!guard.record_failure_at(ip(1), t0 + Duration::from_secs(61)));
        assert!(!guard.record_failure_at(ip(1), t0 + Duration::from_secs(62)));
        assert!(guard.record_failure_at(ip(1), t0 + Duration::from_secs(63)));
    }

    #[test]
    fn stale_failure_entries_are_purged() {
        let guard = HandshakeGuard::new(cfg(0, 0, 10, 60));
        let t0 = Instant::now();
        for i in 0..=FAILURE_TABLE_PURGE_THRESHOLD as u32 {
            let addr = IpAddr::V4(Ipv4Addr::from(i + 1));
            guard.record_failure_at(addr, t0);
        }
        assert!(guard.failures.len() > FAILURE_TABLE_PURGE_THRESHOLD);
        guard.record_failure_at(ip(1), t0 + Duration::from_secs(61));
        assert_eq!(guard.failures.len(), 1);
    }
}
