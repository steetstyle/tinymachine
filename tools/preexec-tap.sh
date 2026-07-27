#!/bin/bash
# Pre-exec wrapper for TAP network tests.
# Opens /dev/net/tun, configures the TAP interface, and exec's the test
# command with the fd inherited. The test finds the fd via $TAP_FD or
# /tmp/tap-fd.txt.
#
# Usage:
#   sudo ./tools/preexec-tap.sh [--tap-name NAME] [command...]
#
# Examples:
#   sudo ./tools/preexec-tap.sh cargo test test_fork_network_real_tcp_download -- --nocapture
#   sudo ./tools/preexec-tap.sh --tap-name tap-test cargo test ...
#
# The script:
#   1. Creates/opens a TAP interface
#   2. Configures IP 10.0.2.1/24, MAC ce:37:22:5e:e0:b9
#   3. Dups the fd to a stable high number (TAP_FD_NR, default 200)
#   4. Sets $TAP_FD and writes to /tmp/tap-fd.txt
#   5. Exec's the command (fd survives exec, no CLOEXEC)

set -euo pipefail

TAP_FD_NR="${TAP_FD_NR:-200}"
TAP_NAME="${TAP_NAME:-tap-test}"
TAP_ADDR="${TAP_ADDR:-10.0.2.1}"
TAP_MASK="${TAP_MASK:-24}"

# Parse --tap-name if provided
if [ "${1:-}" = "--tap-name" ]; then
    TAP_NAME="$2"
    shift 2
fi

ORIG_USER="${SUDO_USER:-$USER}"
ORIG_HOME="$(getent passwd "$ORIG_USER" | cut -d: -f6)"

# Create/configure the TAP interface
ip tuntap add "$TAP_NAME" mode tap 2>/dev/null || true
ip link set "$TAP_NAME" up
ip addr add "$TAP_ADDR/$TAP_MASK" dev "$TAP_NAME" 2>/dev/null || true
ip link set dev "$TAP_NAME" address ce:37:22:5e:e0:b9 2>/dev/null || true
ip neigh add 10.0.2.2 lladdr 52:54:00:12:34:56 dev "$TAP_NAME" nud permanent 2>/dev/null || true

# Open TAP fd and exec into the command (same process = fd stays open)
exec python3 -c "
import os, fcntl, struct, sys, shutil

raw_fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
name = sys.argv[1].encode() + b'\x00'
flags = struct.pack('16sh', name, 0x0002 | 0x1000)
fcntl.ioctl(raw_fd, 0x400454ca, flags)

TAP_FD = int(sys.argv[2])

# Dup to the target fd number, ensuring NO CLOEXEC
os.dup2(raw_fd, TAP_FD)
os.close(raw_fd)

# Explicitly clear FD_CLOEXEC on the target fd
fd_flags = fcntl.fcntl(TAP_FD, fcntl.F_GETFD)
if fd_flags & fcntl.FD_CLOEXEC:
    fcntl.fcntl(TAP_FD, fcntl.F_SETFD, fd_flags & ~fcntl.FD_CLOEXEC)

# Verify the fd is valid
try:
    fcntl.fcntl(TAP_FD, fcntl.F_GETFD)
except OSError as e:
    print(f'FATAL: TAP fd {TAP_FD} not valid after setup: {e}', flush=True)
    sys.exit(1)

print(f'TAP fd={TAP_FD} name={sys.argv[1]} pid={os.getpid()}', flush=True)

# Write fd to file
with open('/tmp/tap-fd.txt', 'w') as f:
    f.write(str(TAP_FD))

# Set env var for direct consumption
os.environ['TAP_FD'] = str(TAP_FD)

# Use the original user's home so templates, rustup, cargo all work
orig_home = sys.argv[3]
os.environ['HOME'] = orig_home
os.environ['PATH'] = orig_home + '/.cargo/bin:' + os.environ.get('PATH', '')
os.environ['RUSTUP_HOME'] = orig_home + '/.rustup'
os.environ['CARGO_HOME'] = orig_home + '/.cargo'

# Parse leading KEY=VALUE arguments and set them as env vars
cmd_args = sys.argv[4:]
i = 0
while i < len(cmd_args) and '=' in cmd_args[i] and not cmd_args[i].startswith('-'):
    k, v = cmd_args[i].split('=', 1)
    os.environ[k] = v
    i += 1

if i >= len(cmd_args):
    print('no command specified', file=sys.stderr)
    sys.exit(1)

exe = cmd_args[i]
cmd_argv = cmd_args[i:]
if '/' not in exe:
    resolved = shutil.which(exe)
    if resolved:
        exe = resolved
os.execv(exe, cmd_argv)
" "$TAP_NAME" "$TAP_FD_NR" "$ORIG_HOME" "$@"
