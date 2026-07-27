#!/bin/bash
# Open TAP, set HOME, then exec into the given command.
# Must be run with sudo: sudo ./tools/run-tap-test.sh [command...]
#
# The TAP fd stays open across exec so the test can read it from /tmp/tap-fd.txt.
# HOME is set to the original user so templates are found in ~/.tinymachine.
#
# Example:
#   sudo ./tools/run-tap-test.sh RUST_LOG=info cargo test test_fork_network_real_tcp_download -- --nocapture

set -e

ORIG_USER="${SUDO_USER:-$USER}"
ORIG_HOME="$(getent passwd "$ORIG_USER" | cut -d: -f6)"

# Standalone TAP with the gateway MAC (ce:37:22:5e:e0:b9) matching the guest's ARP.
TAP_NAME="${TAP_NAME:-tap-test}"
TAP_ADDR="${TAP_ADDR:-10.0.2.1}"
TAP_MASK="${TAP_MASK:-24}"

ip tuntap add "$TAP_NAME" mode tap 2>/dev/null || true
ip link set "$TAP_NAME" up
ip addr add "$TAP_ADDR/$TAP_MASK" dev "$TAP_NAME" 2>/dev/null || true
ip link set dev "$TAP_NAME" address ce:37:22:5e:e0:b9 2>/dev/null || true
# Static ARP: host learns guest MAC so SYN/ACK flows without ARP exchange
ip neigh add 10.0.2.2 lladdr 52:54:00:12:34:56 dev "$TAP_NAME" nud permanent 2>/dev/null || true

# Open TAP fd and exec into the command (same process = fd stays open)
exec python3 -c "
import os, fcntl, struct, sys, shutil

raw_fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
name = sys.argv[1].encode() + b'\x00'
flags = struct.pack('16sh', name, 0x0002 | 0x1000)
fcntl.ioctl(raw_fd, 0x400454ca, flags)

# Dup to a high fd number so it survives cargo/test fd reuse
TAP_FD = 200
os.dup2(raw_fd, TAP_FD)
os.close(raw_fd)
print(f'TAP fd {TAP_FD} (raw was {raw_fd}, pid={os.getpid()})', flush=True)

# Write fd to file so the test can find it
with open('/tmp/tap-fd.txt', 'w') as f:
    f.write(str(TAP_FD))

# Use the original user's home so templates, rustup, cargo all work
orig_home = sys.argv[2]
os.environ['HOME'] = orig_home
os.environ['PATH'] = orig_home + '/.cargo/bin:' + os.environ.get('PATH', '')
os.environ['RUSTUP_HOME'] = orig_home + '/.rustup'
os.environ['CARGO_HOME'] = orig_home + '/.cargo'

# Parse leading KEY=VALUE arguments and set them as env vars
cmd_args = sys.argv[3:]
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
" "$TAP_NAME" "$ORIG_HOME" "$@"
