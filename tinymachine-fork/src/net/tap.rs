use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::io;

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891C;
const SIOCSIFHWADDR: libc::c_ulong = 0x8924;

#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

// ─── /dev/net/tun + ioctl config ───────────────────────────────────────

#[derive(Debug)]
pub struct TapInterface {
    fd: OwnedFd,
    pub name: String,
}

impl TapInterface {
    /// Wrap an already-open fd as a `TapInterface`.
    /// The fd must refer to a valid TAP device (e.g. obtained via a privileged helper).
    pub unsafe fn from_fd(fd: i32) -> Self {
        TapInterface {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            name: String::new(),
        }
    }

    pub fn open(name: &str) -> io::Result<Self> {
        let fd = unsafe {
            let raw = libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            );
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            OwnedFd::from_raw_fd(raw)
        };

        let mut ifr = Ifreq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TAP | IFF_NO_PI,
            _pad: [0u8; 22],
        };

        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(15);
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);

        let ret = unsafe {
            libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &ifr as *const _ as *const libc::c_void)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let actual_name = std::ffi::CStr::from_bytes_until_nul(&ifr.ifr_name)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_else(|_| name.to_string());

        Ok(TapInterface { fd, name: actual_name })
    }

    pub fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Bring the interface up via `ip link set <name> up`.
    pub fn set_up(&self) -> io::Result<()> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 { return Err(io::Error::last_os_error()); }

        let name_bytes = self.name.as_bytes();
        let mut buf = [0u8; 40];
        buf[..name_bytes.len()].copy_from_slice(name_bytes);

        // SIOCGIFFLAGS — get current flags
        let ret = unsafe { libc::ioctl(sock, 0x8913, &buf as *const _ as *const libc::c_void) };
        if ret < 0 { unsafe { libc::close(sock); } return Err(io::Error::last_os_error()); }

        let flags = u16::from_ne_bytes([buf[16], buf[17]]);
        let new_flags = flags | 1u16; // IFF_UP = 1
        buf[16..18].copy_from_slice(&new_flags.to_ne_bytes());

        // SIOCSIFFLAGS — set updated flags
        let ret = unsafe { libc::ioctl(sock, 0x8914, &buf as *const _ as *const libc::c_void) };
        if ret < 0 { unsafe { libc::close(sock); } return Err(io::Error::last_os_error()); }

        unsafe { libc::close(sock); }
        Ok(())
    }

    /// Set the interface IP address and netmask via SIOCSIFADDR / SIOCSIFNETMASK.
    pub fn set_addr(&self, ip: [u8; 4], mask: [u8; 4]) -> io::Result<()> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 { return Err(io::Error::last_os_error()); }

        let name_bytes = self.name.as_bytes();
        let mut name_buf = [0u8; 16];
        name_buf[..name_bytes.len()].copy_from_slice(name_bytes);

        // s_addr stores raw bytes in network order (mem bytes = IP octets).
        #[repr(C)]
        struct IfReq {
            ifr_name: [u8; 16],
            ifr_addr: libc::sockaddr_in,
            _pad: [u8; 8],
        }

        let ifr = IfReq {
            ifr_name: name_buf,
            ifr_addr: libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip) },
                sin_zero: [0u8; 8],
            },
            _pad: [0u8; 8],
        };

        let ret = unsafe {
            libc::ioctl(sock, SIOCSIFADDR, &ifr as *const _ as *const libc::c_void)
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            let ecode = e.raw_os_error().unwrap_or(0);
            tracing::warn!("SIOCSIFADDR failed: errno={} ({})", ecode, e);
            unsafe { libc::close(sock); }
            return Err(e);
        }

        // SIOCSIFNETMASK
        let ifr2 = IfReq {
            ifr_name: name_buf,
            ifr_addr: libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(mask) },
                sin_zero: [0u8; 8],
            },
            _pad: [0u8; 8],
        };

        let ret = unsafe {
            libc::ioctl(sock, SIOCSIFNETMASK, &ifr2 as *const _ as *const libc::c_void)
        };
        if ret < 0 { unsafe { libc::close(sock); } return Err(io::Error::last_os_error()); }

        unsafe { libc::close(sock); }
        Ok(())
    }

    /// Set the TAP interface MAC address to match the guest's virtio-net MAC.
    pub fn set_mac(&self, mac: [u8; 6]) -> io::Result<()> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 { return Err(io::Error::last_os_error()); }

        let name_bytes = self.name.as_bytes();
        let mut name_buf = [0u8; 16];
        name_buf[..name_bytes.len()].copy_from_slice(name_bytes);

        let mut sa: libc::sockaddr = unsafe { std::mem::zeroed() };
        sa.sa_family = 1; // ARPHRD_ETHER
        let mac_i8: [i8; 6] = [
            mac[0] as i8, mac[1] as i8, mac[2] as i8,
            mac[3] as i8, mac[4] as i8, mac[5] as i8,
        ];
        sa.sa_data[..6].copy_from_slice(&mac_i8);

        #[repr(C)]
        struct IfReqMac {
            ifr_name: [u8; 16],
            ifr_hwaddr: libc::sockaddr,
        }

        let ifr = IfReqMac {
            ifr_name: name_buf,
            ifr_hwaddr: sa,
        };

        let ret = unsafe { libc::ioctl(sock, SIOCSIFHWADDR, &ifr as *const _ as *const libc::c_void) };
        unsafe { libc::close(sock); }
        if ret < 0 { return Err(io::Error::last_os_error()); }
        Ok(())
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe {
            libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let ret = unsafe {
            libc::write(self.fd.as_raw_fd(), buf.as_ptr() as *const libc::c_void, buf.len())
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

impl AsRawFd for TapInterface {
    fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}
