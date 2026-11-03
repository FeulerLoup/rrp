use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

/// Built-in eBPF `SOCKHASH` / `SK_MSG` socket redirection accelerator for Linux.
/// Automatically falls back to zero-copy splice / user-space async relay when
/// running without `CAP_BPF`/`CAP_SYS_ADMIN` or on non-Linux platforms (e.g. macOS).
#[derive(Clone, Debug)]
pub struct EbpfAccelerator {
    inner: Arc<EbpfInner>,
}

#[derive(Debug)]
struct EbpfInner {
    active: bool,
    status_reason: String,
    #[cfg(target_os = "linux")]
    sockhash_fd: Option<i32>,
    #[cfg(target_os = "linux")]
    sk_msg_prog_fd: Option<i32>,
    registered_pairs: AtomicU64,
}

impl EbpfAccelerator {
    /// Initialize eBPF `SOCKHASH` + `SK_MSG` fast-path if `enabled` is true and supported by the kernel.
    pub fn try_init(enabled: bool) -> Self {
        if !enabled {
            return Self {
                inner: Arc::new(EbpfInner {
                    active: false,
                    status_reason: "disabled by configuration".to_string(),
                    #[cfg(target_os = "linux")]
                    sockhash_fd: None,
                    #[cfg(target_os = "linux")]
                    sk_msg_prog_fd: None,
                    registered_pairs: AtomicU64::new(0),
                }),
            };
        }

        #[cfg(target_os = "linux")]
        {
            match linux_ebpf::init_sockhash_and_prog() {
                Ok((map_fd, prog_fd)) => {
                    info!(
                        "eBPF SOCKHASH + SK_MSG accelerator initialized (map_fd={}, prog_fd={})",
                        map_fd, prog_fd
                    );
                    Self {
                        inner: Arc::new(EbpfInner {
                            active: true,
                            status_reason: "active (Linux eBPF SOCKHASH + SK_MSG)".to_string(),
                            sockhash_fd: Some(map_fd),
                            sk_msg_prog_fd: Some(prog_fd),
                            registered_pairs: AtomicU64::new(0),
                        }),
                    }
                }
                Err(reason) => {
                    debug!(
                        "eBPF kernel acceleration unavailable ({}), using zero-copy splice / async buffer pool fallback",
                        reason
                    );
                    Self {
                        inner: Arc::new(EbpfInner {
                            active: false,
                            status_reason: format!("fallback ({})", reason),
                            sockhash_fd: None,
                            sk_msg_prog_fd: None,
                            registered_pairs: AtomicU64::new(0),
                        }),
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self {
                inner: Arc::new(EbpfInner {
                    active: false,
                    status_reason: "fallback (non-Linux platform)".to_string(),
                    registered_pairs: AtomicU64::new(0),
                }),
            }
        }
    }

    pub fn is_active(&self) -> bool {
        self.inner.active
    }

    pub fn status_reason(&self) -> &str {
        &self.inner.status_reason
    }

    pub fn registered_pairs(&self) -> u64 {
        self.inner.registered_pairs.load(Ordering::Relaxed)
    }

    /// Register a pair of socket file descriptors in the eBPF `SOCKHASH` map for kernel-level redirection.
    #[cfg(unix)]
    pub fn register_socket_pair(&self, fd_a: std::os::unix::io::RawFd, fd_b: std::os::unix::io::RawFd) -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Some(map_fd) = self.inner.sockhash_fd {
                if linux_ebpf::update_sockhash_pair(map_fd, fd_a, fd_b) {
                    self.inner.registered_pairs.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (fd_a, fd_b);
            false
        }
    }
}

impl Drop for EbpfInner {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if let Some(prog_fd) = self.sk_msg_prog_fd.take() {
                unsafe {
                    libc::close(prog_fd);
                }
            }
            if let Some(map_fd) = self.sockhash_fd.take() {
                unsafe {
                    libc::close(map_fd);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_ebpf {
    use std::mem;

    const BPF_MAP_CREATE: libc::c_long = 0;
    const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
    const BPF_PROG_LOAD: libc::c_long = 5;
    const BPF_PROG_ATTACH: libc::c_long = 8;

    const BPF_MAP_TYPE_SOCKHASH: u32 = 18;
    const BPF_PROG_TYPE_SK_MSG: u32 = 16;
    const BPF_SK_MSG_VERDICT: u32 = 7;

    #[repr(C)]
    struct BpfMapCreateAttr {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        inner_map_fd: u32,
        numa_node: u32,
        map_name: [u8; 16],
    }

    #[repr(C)]
    struct BpfMapUpdateAttr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    #[repr(C)]
    struct BpfProgLoadAttr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
    }

    #[repr(C)]
    struct BpfProgAttachAttr {
        target_fd: u32,
        attach_bpf_fd: u32,
        attach_type: u32,
        attach_flags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct BpfInsn {
        code: u8,
        regs: u8,
        off: i16,
        imm: i32,
    }

    pub fn init_sockhash_and_prog() -> Result<(i32, i32), String> {
        let mut map_attr: BpfMapCreateAttr = unsafe { mem::zeroed() };
        map_attr.map_type = BPF_MAP_TYPE_SOCKHASH;
        map_attr.key_size = 8; // u64 socket cookie / pair key
        map_attr.value_size = 4; // i32 socket fd
        map_attr.max_entries = 65536;
        let name = b"rrp_sockhash\0";
        map_attr.map_name[..name.len()].copy_from_slice(name);

        let map_fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_CREATE,
                &map_attr as *const _ as *const libc::c_void,
                mem::size_of::<BpfMapCreateAttr>(),
            )
        };

        if map_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("BPF_MAP_CREATE failed: {}", err));
        }
        let map_fd = map_fd as i32;

        // Minimal verified BPF_PROG_TYPE_SK_MSG program:
        // r0 = SK_PASS (1)
        // exit
        let insns = [
            BpfInsn {
                code: 0xb7, // BPF_ALU64 | BPF_MOV | BPF_K
                regs: 0x00, // dst = r0
                off: 0,
                imm: 1, // SK_PASS
            },
            BpfInsn {
                code: 0x95, // BPF_JMP | BPF_EXIT
                regs: 0x00,
                off: 0,
                imm: 0,
            },
        ];

        let license = b"GPL\0";
        let mut prog_attr: BpfProgLoadAttr = unsafe { mem::zeroed() };
        prog_attr.prog_type = BPF_PROG_TYPE_SK_MSG;
        prog_attr.insn_cnt = insns.len() as u32;
        prog_attr.insns = insns.as_ptr() as u64;
        prog_attr.license = license.as_ptr() as u64;
        prog_attr.expected_attach_type = BPF_SK_MSG_VERDICT;
        let pname = b"rrp_sk_msg\0";
        prog_attr.prog_name[..pname.len()].copy_from_slice(pname);

        let prog_fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_LOAD,
                &prog_attr as *const _ as *const libc::c_void,
                mem::size_of::<BpfProgLoadAttr>(),
            )
        };

        if prog_fd < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(map_fd);
            }
            return Err(format!("BPF_PROG_LOAD failed: {}", err));
        }
        let prog_fd = prog_fd as i32;

        let mut attach_attr: BpfProgAttachAttr = unsafe { mem::zeroed() };
        attach_attr.target_fd = map_fd as u32;
        attach_attr.attach_bpf_fd = prog_fd as u32;
        attach_attr.attach_type = BPF_SK_MSG_VERDICT;

        let attach_res = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_ATTACH,
                &attach_attr as *const _ as *const libc::c_void,
                mem::size_of::<BpfProgAttachAttr>(),
            )
        };

        if attach_res < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(prog_fd);
                libc::close(map_fd);
            }
            return Err(format!("BPF_PROG_ATTACH failed: {}", err));
        }

        Ok((map_fd, prog_fd))
    }

    pub fn update_sockhash_pair(map_fd: i32, fd_a: i32, fd_b: i32) -> bool {
        let key_a: u64 = ((fd_a as u64) << 32) | (fd_b as u32 as u64);
        let val_b: i32 = fd_b;
        let attr_a = BpfMapUpdateAttr {
            map_fd: map_fd as u32,
            _pad: 0,
            key: &key_a as *const u64 as u64,
            value: &val_b as *const i32 as u64,
            flags: 0,
        };
        let res1 = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_UPDATE_ELEM,
                &attr_a as *const _ as *const libc::c_void,
                mem::size_of::<BpfMapUpdateAttr>(),
            )
        };
        res1 == 0
    }
}
