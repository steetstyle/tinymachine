use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use tinymachine_fork::register_all_backends;
use tinymachine_api::sandbox::SandboxBackend;
use tinymachine_fork::fork::KvmForkBackend;
use tinymachine_fork::net::tap::TapInterface;
use tinymachine_api::Variant;

/// Check whether `fd` is a valid open file descriptor.
fn fd_is_valid(fd: i32) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .with_target(false)
        .try_init();
}

fn test_code(code: &str, expected: &str, label: &str) {
    let _ = init_logging();
    register_all_backends();
    let variant = Variant::new("python", "minimal", "base");
    let mut backend = KvmForkBackend::new();
    SandboxBackend::init(&mut backend, &variant).expect("init failed");
    let output = SandboxBackend::exec(&mut backend, code).expect("exec failed");
    eprintln!("{label} output: {}", output.trim());
    assert!(
        output.contains(expected),
        "{label}: expected '{expected}' in output: {}",
        output
    );
    SandboxBackend::destroy(&mut backend).expect("destroy failed");
    eprintln!("PASS: {label}");
}

#[test]
fn test_fork_network_getaddrinfo() {
    test_code(
        "import socket; print(socket.getaddrinfo('1.1.1.1', 80))",
        "bytearray",
        "getaddrinfo",
    );
}

#[test]
fn test_fork_network_socket_create() {
    test_code(
        "import socket; s=socket.socket(); print('SOCKET_OK')",
        "SOCKET_OK",
        "socket_create",
    );
}

#[test]
fn test_fork_network_tcp_connect_with_timeout() {
    // To avoid the 30s host timeout, use a short connect timeout.
    // MicroPython's settimeout uses poll() internally (guest-side, not affected by seccomp).
    test_code(
        "\
import socket, os
os.system('arp -s 10.0.2.1 ce:37:22:5e:e0:b9')
info = socket.getaddrinfo('1.1.1.1', 80)
s = socket.socket()
s.settimeout(5)
try:
    s.connect(info[0][4])
    print('CONNECT_OK')
except OSError as e:
    print('CONNECT_FAIL:', e)
",
        "CONNECT_",
        "tcp_connect",
    );
}

/// Start an HTTP server on the TAP interface and return the port.
fn start_http_server() -> u16 {
    let server = TcpListener::bind("10.0.2.1:0").expect("bind HTTP server");
    let port = server.local_addr().unwrap().port();
    eprintln!("TAP HTTP server listening on 10.0.2.1:{port}");
    thread::spawn(move || {
        for stream in server.incoming() {
            match stream {
                Ok(mut s) => {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf);
                    let body = b"HELLO_FROM_TAP_SERVER\n";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        std::str::from_utf8(body).unwrap(),
                    );
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.flush();
                }
                Err(e) => eprintln!("HTTP server accept error: {e}"),
            }
        }
    });
    port
}

/// Open a TAP interface (requires CAP_NET_ADMIN).
/// Falls back to a text file (TAP_FD_FILE env var or /tmp/tap-fd.txt),
/// then to TAP_FD env var.
fn open_tap() -> Result<TapInterface, Box<dyn std::error::Error>> {
    // 1) Try text file (lets a privileged wrapper write the fd).
    let fd_path = std::env::var("TAP_FD_FILE").unwrap_or_else(|_| "/tmp/tap-fd.txt".into());
    if let Ok(content) = std::fs::read_to_string(&fd_path) {
        if let Ok(fd) = content.trim().parse::<i32>() {
            if fd_is_valid(fd) {
                eprintln!("Using TAP fd {fd} from {fd_path}");
                return Ok(unsafe { TapInterface::from_fd(fd) });
            }
            eprintln!("TAP fd {fd} from {fd_path} is stale (not valid in this process), falling through");
        }
    }

    // 2) Try env var.
    if let Ok(fd_str) = std::env::var("TAP_FD") {
        if let Ok(fd) = fd_str.parse::<i32>() {
            if fd_is_valid(fd) {
                eprintln!("Using TAP_FD={fd} from environment");
                return Ok(unsafe { TapInterface::from_fd(fd) });
            }
            eprintln!("TAP_FD={fd} is stale (not valid in this process), falling through");
        }
    }

    // 3) Try privileged open (requires CAP_NET_ADMIN).
    eprintln!("Opening TAP directly (may need root)");
    let tap = TapInterface::open("tap-test")?;
    tap.set_addr([10, 0, 2, 1], [255, 255, 255, 0])?;
    tap.set_up()?;
    tap.set_mac([0xce, 0x37, 0x22, 0x5e, 0xe0, 0xb9])?;
    // Add a static ARP entry so the host knows the guest's MAC without ARP exchange.
    let _ = std::process::Command::new("arp")
        .args(["-s", "10.0.2.2", "52:54:00:12:34:56", "-i", "tap-test"])
        .status();
    Ok(tap)
}

#[test]
fn test_fork_network_real_tcp_download() {
    let _ = init_logging();
    register_all_backends();

    let tap = match open_tap() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("SKIP: TAP setup failed (need root?): {e}");
            return;
        }
    };
    let port = start_http_server();

    let variant = Variant::new("python", "minimal", "base");
    let mut backend = KvmForkBackend::new();
    SandboxBackend::init(&mut backend, &variant).expect("init failed");
    unsafe { libc::write(2, b"AFTER_INIT\n" as *const u8 as *const libc::c_void, 12); }

    backend.set_tap_fd(tap.fd());
    use std::io::Write;
    std::io::stderr().write_all(b"BEFORE_EXEC\n").ok();
    std::io::stderr().flush().ok();

    let code = format!(
        "\
import socket, os
os.system('ifconfig eth0 10.0.2.2 up 2>&1')
os.system('ifconfig 2>&1')
os.system('arp -n 2>&1')
s = socket.socket()
s.settimeout(15)
try:
    info = socket.getaddrinfo('10.0.2.1', {port})
    s.connect(info[0][4])
    s.send(b'GET /test HTTP/1.0\\r\\n\\r\\n')
    data = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    if b'HELLO_FROM_TAP_SERVER' in data:
        print('CONTENT_OK')
    else:
        print('CONTENT_BAD:', data[:200])
except Exception as e:
    print('DOWNLOAD_FAIL:', e)
    os.system('arp -n 2>&1')
",
    );

    let output = SandboxBackend::exec(&mut backend, &code).expect("exec failed");
    eprintln!("download output: {}", output.trim());
    assert!(output.contains("CONTENT_OK"), "Expected CONTENT_OK, got: {output}");
    SandboxBackend::destroy(&mut backend).expect("destroy failed");
    eprintln!("PASS: test_fork_network_real_tcp_download");
}
