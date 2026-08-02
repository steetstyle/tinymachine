// SPDX-License-Identifier: MIT OR Apache-2.0
//
// TinyOS init — PID 1 for KVM sandbox
//
// Protocol (same as shell version):
//   CMD_BUF  = 0x7E000  (516096) — host writes command here
//   OUT_BUF  = 0x7F000  (520192) — guest writes output here
//   READY    = 0x7FFA   (524282) — "READY\0" when done
//
// Busy-polling loop:
//   1. Read CMD_BUF via mmap'd /dev/mem (zero-copy, no syscall)
//   2. If command: fork+exec python -c 'cmd', capture output
//   3. Write output to OUT_BUF via mmap (zero-copy)
//   4. Write "READY\0" via mmap
//   5. write(1, "\n", 1) to trigger KVM_EXIT_IO
//   6. Userspace spin (no syscalls) for clean snapshot capture
//
// Compile: gcc -static -O2 -s -o init init.c -lc

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/random.h>
#include <dirent.h>
#include <errno.h>


// ─── Directory listing helper for diagnostics ──────────────────────
// Lists up to `max_entries` entries from a directory to standard output.
static void ls_dir(const char *path, int max_entries) {
    DIR *d = opendir(path);
    if (!d) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf), "  ls(%s): opendir failed errno=%d\n", path, errno);
        syscall(SYS_write, STDOUT_FILENO, buf, (size_t)(n < (int)sizeof(buf) ? n : sizeof(buf) - 1));
        return;
    }
    char buf[4096];
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL && count < max_entries) {
        char ftype = '?';
        if (entry->d_type == DT_DIR) ftype = 'd';
        else if (entry->d_type == DT_REG) ftype = 'f';
        else if (entry->d_type == DT_LNK) ftype = 'l';
        else if (entry->d_type == DT_CHR) ftype = 'c';
        else if (entry->d_type == DT_BLK) ftype = 'b';
        int n = snprintf(buf, sizeof(buf), "  %c %s\n", ftype, entry->d_name);
        if (n > 0) syscall(SYS_write, STDOUT_FILENO, buf, (size_t)(n < (int)sizeof(buf) ? n : sizeof(buf) - 1));
        count++;
    }
    closedir(d);
}

// ─── Shared memory layout (matches host's CMD_BUF/OUT_BUF) ──────────
#define ENTROPY_BUF_PHYS 0x7D000ULL  // host writes 64B CSPRNG before each KVM_RUN
#define ENTROPY_SIZE     64
// Ctrl byte at 0x7CFFF: 1 = entropy divergence enabled (default), 0 = disabled (measurement mode)
#define ENTROPY_DIVERGENCE_CTRL_PHYS 0x7CFFFULL
#define CMD_BUF_PHYS    0x7E000ULL
#define OUT_BUF_PHYS    0x7F000ULL
#define READY_OFFSET    4090
#define BUF_MAX         4096
#define OUT_BUF_MAX     65536   // 64KB for Python stdout+stderr output (tracebacks can be large)
#define SPIN_ITER       10000

#define MODULES_DIR "/lib/modules/7.1.4"
#ifndef SYS_finit_module
#define SYS_finit_module 313
#endif

// Write to /dev/kmsg (forward declaration — defined later)
static void kmsg_puts(const char *s);

// Serial output using write(1, ...) which goes through kernel serial driver.
// Each write() causes the kernel to access UART port 0x3F8, triggering
// KVM_EXIT_IO — the host captures this as serial output.
// No iopl() needed since we don't use inb/outb directly.
static void serial_putchar(char c);
static void serial_puts(const char *s);
static void flush_utrace(void);

// ─── Detect best available Python interpreter ──────────────────────
static const char *detect_python(void) {
    // Try common Python paths. The initrd may have CPython at /bin/python3,
    // or the MicroPython variant at /bin/micropython.
    static const char *candidates[] = {
        "/bin/python3",
        "/usr/bin/python3",
        "/bin/micropython",
        "/bin/python",
        "/usr/bin/python",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], X_OK) == 0) {
            return candidates[i];
        }
    }
    // Fallback — the exec will fail if it truly doesn't exist
    return "/bin/python3";
}

// ─── Execute Python code, capture stdout+stderr ────────────────────
// Uses simple blocking read(). The host's 60-second timeout kills the
// VM if the child hangs in D state during GPU access.  The poll-based
// approach with guest-side timeout was tested but caused deadlocks —
// SIGKILL on a D-state child is ineffective, and waitpid() blocks
// forever on D-state processes.  The host-level timeout is simpler
// and more reliable.

// OUT_BUF pointer for out_puts() diagnostics (used by module loading
// and the optional run_python diagnostic marker below).
static volatile unsigned char *g_out_buf = NULL;
static volatile size_t g_out_off = 0;

static char *run_python(const char *code, const char *python) {
    serial_puts("RP_FORK\n");
    int stdout_pipe[2];
    if (pipe(stdout_pipe) < 0) { serial_puts("RP_PIPE_FAIL\n"); return NULL; }
    serial_puts("RP_PIPE_OK\n");

    pid_t pid = fork();
    if (pid < 0) { serial_puts("RP_FORK_FAIL\n"); close(stdout_pipe[0]); close(stdout_pipe[1]); return NULL; }
    serial_puts("RP_FORK_DONE\n");

    if (pid == 0) {
        close(stdout_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stdout_pipe[1], STDERR_FILENO);
        if (stdout_pipe[1] > STDERR_FILENO) close(stdout_pipe[1]);

        syscall(SYS_write, STDOUT_FILENO, "ROOTFS_DUMP\n", 12);

        char *new_argv[] = {"python3", "-c", (char *)code, NULL};
        char *envp[] = {"PATH=/bin:/usr/bin", "HOME=/root", "TERM=linux", "LD_PRELOAD=/lib/libtrace_cuda.so", NULL};
        execve("/bin/python3", new_argv, envp);

        char ebuf[128];
        int en = snprintf(ebuf, sizeof(ebuf), "[EXECVE_FAIL errno=%d]\n", errno);
        syscall(SYS_write, STDOUT_FILENO, ebuf, (size_t)(en < (int)sizeof(ebuf) ? en : sizeof(ebuf) - 1));
        _exit(127);
    }

    // Close write end immediately — the child now holds the only write
    // fd (via dup2). When the child exits, the pipe read returns EOF.
    close(stdout_pipe[1]);

    // Diagnostic: fork a watcher that samples the child's /proc/<pid>/syscall
    // so we can see exactly what the hung GPU thread blocks on (futex,
    // clock_nanosleep, read, ...).
    pid_t wpid = fork();
    if (wpid == 0) {
        char spath[64];
        int sn = snprintf(spath, sizeof(spath), "/proc/%d/syscall", pid);
        char sbuf[256];
        struct { long tv_sec; long tv_nsec; } ts = { 0, 200000000 };
        for (int i = 0; i < 220; i++) {
            /* Sample syscall for EVERY thread of the TGID. */
            char tpath[96];
            snprintf(tpath, sizeof(tpath), "/proc/%d/task", pid);
            DIR *td = opendir(tpath);
            if (td) {
                struct dirent *de;
                while ((de = readdir(td))) {
                    if (de->d_name[0] < '0' || de->d_name[0] > '9')
                        continue;
                    snprintf(spath, sizeof(spath), "/proc/%d/task/%s/syscall", pid, de->d_name);
                    int wfd = open(spath, O_RDONLY);
                    if (wfd >= 0) {
                        int rn = read(wfd, sbuf, sizeof(sbuf) - 1);
                        if (rn > 0) {
                            sbuf[rn] = 0;
                            char ob[300];
                            int on = snprintf(ob, sizeof(ob), "PSYSCALL tid=%s %s", de->d_name, sbuf);
                            if (on > 0 && on < (int)sizeof(ob)) serial_puts(ob);
                            serial_puts("\n");
                        }
                        close(wfd);
                    }
                    snprintf(spath, sizeof(spath), "/proc/%d/task/%s/wchan", pid, de->d_name);
                    wfd = open(spath, O_RDONLY);
                    if (wfd >= 0) {
                        int rn = read(wfd, sbuf, sizeof(sbuf) - 1);
                        if (rn > 0) {
                            sbuf[rn] = 0;
                            char ob[300];
                            int on = snprintf(ob, sizeof(ob), "PWCHAN tid=%s %s", de->d_name, sbuf);
                            if (on > 0 && on < (int)sizeof(ob)) serial_puts(ob);
                            serial_puts("\n");
                            if (strstr(sbuf, "anon_pipe_write") || strstr(sbuf, "pipe_wait")) {
                                /* Dump this thread's fd table: the pipe's
                                 * inode reveals its read-end owner. */
                                char fpath[96];
                                snprintf(fpath, sizeof(fpath), "/proc/%d/task/%s/fd", pid, de->d_name);
                                DIR *fd = opendir(fpath);
                                if (fd) {
                                    struct dirent *de2;
                                    while ((de2 = readdir(fd))) {
                                        if (de2->d_name[0] < '0' || de2->d_name[0] > '9')
                                            continue;
                                        snprintf(fpath, sizeof(fpath), "/proc/%d/task/%s/fd/%s", pid, de->d_name, de2->d_name);
                                        char lb[128];
                                        ssize_t ln = readlink(fpath, lb, sizeof(lb) - 1);
                                        char ob[300];
                                        if (ln > 0) { lb[ln] = 0; snprintf(ob, sizeof(ob), "  FD %s -> %s\n", de2->d_name, lb); }
                                        else snprintf(ob, sizeof(ob), "  FD %s -> ?\n", de2->d_name);
                                        serial_puts(ob);
                                    }
                                    closedir(fd);
                                }
                                serial_puts("FDT-END\n");
                            }
                        }
                        close(wfd);
                    }
                }
                closedir(td);
            }
            syscall(SYS_nanosleep, &ts, NULL);
        }
        _exit(0);
    }
    /* Sample the parent (run_python's caller = init) too. */
    pid_t ppid2 = getpid();
    pid_t wpid2 = fork();
    if (wpid2 == 0) {
        char spath[64];
        char sbuf[256];
        struct { long tv_sec; long tv_nsec; } ts = { 0, 400000000 };
        for (int i = 0; i < 110; i++) {
            char tpath[96];
            snprintf(tpath, sizeof(tpath), "/proc/%d/task", ppid2);
            DIR *td = opendir(tpath);
            if (td) {
                struct dirent *de;
                while ((de = readdir(td))) {
                    if (de->d_name[0] < '0' || de->d_name[0] > '9')
                        continue;
                    snprintf(spath, sizeof(spath), "/proc/%d/task/%s/syscall", ppid2, de->d_name);
                    int wfd = open(spath, O_RDONLY);
                    if (wfd >= 0) {
                        int rn = read(wfd, sbuf, sizeof(sbuf) - 1);
                        if (rn > 0) {
                            sbuf[rn] = 0;
                            char ob[300];
                            int on = snprintf(ob, sizeof(ob), "PSYSCALL-PARENT tid=%s %s", de->d_name, sbuf);
                            if (on > 0 && on < (int)sizeof(ob)) serial_puts(ob);
                            serial_puts("\n");
                        }
                        close(wfd);
                    }
                }
                closedir(td);
            }
            syscall(SYS_nanosleep, &ts, NULL);
        }
        _exit(0);
    }

    /* Flusher: dump /tmp/utrace.log growth to serial every 2s. */
    pid_t fpid = fork();
    if (fpid == 0) {
        struct { long tv_sec; long tv_nsec; } fts = { 2, 0 };
        for (;;) {
            flush_utrace();
            syscall(SYS_nanosleep, &fts, NULL);
        }
    }

    char *output = malloc(OUT_BUF_MAX);
    if (!output) { close(stdout_pipe[0]); waitpid(pid, NULL, 0); return NULL; }

    // Read with 60-second timeout. If child hangs (e.g. Device["NV"] init
    // stuck on GSP RPC), we SIGKILL it and return what we have so far.
    // Use poll() (not alarm/SIGALRM): this runs in threads, and SIGALRM
    // would be delivered to an arbitrary thread, so the alarm never
    // interrupted this read() reliably.
    //
    // IMPORTANT: never stop draining the pipe even if the output exceeds
    // OUT_BUF_MAX — a child blocked in write() to a full pipe would hang
    // the whole UMD. Stream everything to serial and keep a sliding tail.
    //
    // IMPORTANT 2: read()==0 (EOF) is NOT a reason to stop. The UMD
    // closes all its fds (including its stdout) mid-run and then reopens
    // them (observed: the CUDA process re-dups its stdout as fd 4, same
    // pipe inode). If we stop draining at the transient EOF, the UMD's
    // output writes block on the full pipe forever (observed deadlock:
    // writers in anon_pipe_write on the drain pipe). Only the child's
    // DEATH ends the drain.
    ssize_t total = 0;
    ssize_t n = 0;
    int eof_seen = 0;
    struct pollfd pfd = { .fd = stdout_pipe[0], .events = POLLIN };
    while (1) {
        /* child liveness: the only legit end of the drain */
        int status;
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid || wr < 0) {
            serial_puts("RP_CHILD_DIED\n");
            break;
        }
        n = poll(&pfd, 1, 1000);
        if (n < 0) {
            if (errno == EINTR)
                continue;   /* don't bail on signals (SIGCHLD etc.) */
            serial_puts("RP_POLL_ERR\n");
            break;
        }
        if (n == 0)
            continue;       /* tick: re-check the child liveness */
        if (!(pfd.revents & (POLLIN | POLLERR | POLLHUP))) {
            serial_puts("RP_POLL_REV\n");
            break;
        }
        ssize_t got = read(stdout_pipe[0], output + total, OUT_BUF_MAX - 1 - total);
        if (got < 0) {
            if (errno == EINTR)
                continue;   /* signals (SIGCHLD etc.) are not EOF */
            serial_puts("RP_READ_ERR\n");
            break;
        }
        if (got == 0) {
            if (!eof_seen) {
                serial_puts("RP_READ_EOF\n");
                eof_seen = 1;
            }
            usleep(100000); /* transient EOF — keep draining */
            continue;
        }
        eof_seen = 0;
        total += got;
        /* Stream output live to serial so a hanging child still shows
         * its trace (it never exits, so the pipe is only drained here). */
        output[total] = '\0';
        serial_puts(output + (total - got));
        if (total >= OUT_BUF_MAX - 1) {
            /* Keep the LAST OUT_BUF_MAX bytes as the return value. */
            ssize_t tail = OUT_BUF_MAX - 1;
            memmove(output, output + total - tail, tail);
            total = tail;
        }
    }
    close(stdout_pipe[0]);
    serial_puts("RP_WAIT4\n");
    int status;
    int attempts = 0;
    while (1) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            break;
        if (r < 0)
            break;
        if (kill(pid, 0) != 0)
            break; /* child gone (maybe reaped elsewhere) */
        if (++attempts >= 300) { /* ~30s */
            serial_puts("RP_CHILD_ALIVE\n");
            return output;
        }
        usleep(100000);
    }
    serial_puts("RP_WAIT4_DONE\n");
    return output;
}

// ─── Forward declarations ─────────────────────────────────────────
static void serial_puts(const char *s);
static void out_puts(const char *s);

// ─── Load a kernel module via finit_module in a child process ────
// nvidia.ko's init function can hang (PCI probe stalls through VFIO).
// By forking a child, we can SIGKILL it after a timeout and continue.
// The host also has a safety timeout, but killing from inside the guest
// is faster and produces better diagnostic output.

static int load_kernel_module(const char *path) {
    kmsg_puts("mod_load: ");
    kmsg_puts(path);
    kmsg_puts("\n");
    out_puts("mod_load: ");
    out_puts(path);
    out_puts("\n");

    // Determine module parameters based on module type:
    // - nvidia*.ko uses NVreg params (MSI/PCIe workarounds for VFIO)
    // - nouveau.ko uses nouveau.config=Gsp=0 (no GSP firmware on VFIO)
    // - Other DRM deps use empty params
    int is_nvidia = 0;
    int is_nouveau = 0;
    const char *base = path;
    const char *slash = strrchr(path, '/');
    if (slash) base = slash + 1;
    if (base[0] == 'n' && base[1] == 'v' && base[2] == 'i' && base[3] == 'd' && base[4] == 'i' && base[5] == 'a')
        is_nvidia = 1;
    if (strstr(path, "nouveau") != NULL)
        is_nouveau = 1;

    // Open the module file in parent so the child just calls finit_module
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        kmsg_puts("  ERROR: cannot open\n");
        out_puts("  ERROR: cannot open\n");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        kmsg_puts("  ERROR: fork failed\n");
        out_puts("  ERROR: fork failed\n");
        close(fd);
        return -1;
    }

    if (pid == 0) {
        // ── CHILD: call finit_module ──
        // Close unused fds inherited from parent (just fd+1 up to 256)
        for (int i = fd + 1; i < 256; i++) close(i);

        const char *params = "";
        if (is_nvidia) {
            // Minimal params. Let defaults handle the rest.
            // NVreg_EnableGpuFirmware=0 disables GSP, uses monolithic RM.
            // With RmMsg=Msg we get verbose RM init debug output.
            // GpuInitOnProbe=1 runs RmInitAdapter during probe.
            // NVreg_IgnoreMMIOCheck=1 is REQUIRED for VFIO passthrough:
            // QEMU VFIO's BAR2 (MMIO) is at 0x4000000040 (non-standard
            // address) which triggers MMIO range validation. Without
            // IgnoreMMIOCheck, nv_pci_probe returns -1 before GSP init.
            // InitializeSystemMemoryAllocations=1 is the default (enables
            // GSP-allocated system memory). Setting to 0 breaks UVM.
            //
            // GSP FIRMWARE NOTE: The gsp_ga10x.bin ELF has section header
            // table ending exactly at the file boundary (e_shoff + e_shnum *
            // e_shentsize == filesize). The kernel module's check at
            // kernel_gsp.c:5962 uses `elfDataSize >= elfSectionHeaderMaxIdx`
            // which FAILS when they are exactly equal (off-by-one). Fix:
            // append 1 null byte to the firmware file.
            // GpuInitOnProbe=1 runs RmInitAdapter during probe.
            // NVreg_IgnoreMMIOCheck=1 is REQUIRED for VFIO passthrough:
            params =
                "NVreg_EnableGpuFirmware=1 "
                "NVreg_GpuInitOnProbe=1 "
                "NVreg_IgnoreMMIOCheck=1 "
                "NVreg_InitializeSystemMemoryAllocations=1 ";
        } else if (is_nouveau) {
            // Disable GSP firmware for VFIO passthrough (no display)
            params = "nouveau.config=Gsp=0";
        }
        int saved_errno = 0;
        long ret = syscall(SYS_finit_module, fd, params, 0);
        if (ret != 0) {
            saved_errno = errno;
        }
        close(fd);

        // Write result to a temporary file for parent to read
        char buf[64];
        int len;
        if (ret == 0) {
            len = snprintf(buf, sizeof(buf), "OK");
        } else if (saved_errno == EEXIST) {
            len = snprintf(buf, sizeof(buf), "EXISTS");
        } else {
            len = snprintf(buf, sizeof(buf), "FAIL:%d", saved_errno);
        }
        int res_fd = open("/tmp/mod_result", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (res_fd >= 0) {
            write(res_fd, buf, len);
            close(res_fd);
        }
        _exit(ret == 0 ? 0 : 1);
    }

    // ── PARENT: wait with 10-second timeout ──
    close(fd);

    int status;
    int waited = 0;
    while (waited < 10) {
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                // Check the result file
                int res_fd = open("/tmp/mod_result", O_RDONLY);
                if (res_fd >= 0) {
                    char buf[32];
                    int n = read(res_fd, buf, sizeof(buf) - 1);
                    close(res_fd);
                    unlink("/tmp/mod_result");
                    if (n > 0) {
                        buf[n] = 0;
                        if (strcmp(buf, "OK") == 0) {
                            kmsg_puts("  OK\n");
                            out_puts("  OK\n");
                            return 0;
                        }
                        if (strcmp(buf, "EXISTS") == 0) {
                            kmsg_puts("  already loaded\n");
                            out_puts("  already loaded\n");
                            return 0;
                        }
                        kmsg_puts("  failed: ");
                        kmsg_puts(buf);
                        kmsg_puts("\n");
                        out_puts("  failed: ");
                        out_puts(buf);
                        out_puts("\n");
                        return -1;
                    }
                }
                kmsg_puts("  OK\n");
                return 0;
            }
            // Read result from temp file on failure
            int res_fd = open("/tmp/mod_result", O_RDONLY);
            if (res_fd >= 0) {
                char buf[32];
                int n = read(res_fd, buf, sizeof(buf) - 1);
                close(res_fd);
                unlink("/tmp/mod_result");
                if (n > 0) {
                    buf[n] = 0;
                    kmsg_puts("  failed: ");
                    kmsg_puts(buf);
                    kmsg_puts("\n");
                    out_puts("  failed: ");
                    out_puts(buf);
                    out_puts("\n");
                    return -1;
                }
            }
            kmsg_puts("  failed (unknown)\n");
            out_puts("  failed (unknown)\n");
            return -1;
        }
        // Sleep 1 second and retry
        struct { long tv_sec; long tv_nsec; } sleep_ts = { 1, 0 };
        syscall(SYS_nanosleep, &sleep_ts, NULL);
        waited++;
    }

    // Timeout — kill child with extreme prejudice
    kmsg_puts("  TIMEOUT after 10s — killing child\n");
    out_puts("  TIMEOUT after 10s\n");
    kill(pid, SIGKILL);
    // Non-blocking wait: if child is in D state (uninterruptible sleep
    // in finit_module), SIGKILL won't wake it and a blocking waitpid
    // would hang the init forever. We clean up the zombie in the
    // next call (init.c's main loop calls waitpid(-1, ...)).
    int wstatus;
    waitpid(pid, &wstatus, WNOHANG);
    return -1;
}

// ─── Wait for NVIDIA GSP firmware handshake ─────────────────────
// nvidia.ko loads firmware into the GSP Falcon asynchronously during
// PCI probe. The GSP-RM handshake takes ~10-15s (Ada AD104 observed).
// /dev/nvidia0 is only usable AFTER GSP handshake completes.
//
// This function polls /dev/nvidia0 with open() until the device is
// ready or the timeout expires.
//
// Returns 0 on success (device ready), -1 on timeout.
static int wait_for_nvidia_gsp(int timeout_secs, int nvidia_major) {
    // Create the device node first (devtmpfs may not auto-create it
    // until GSP handshake, but we need the node to exist for open()).
    // Minor 0 = first NVIDIA GPU.
    dev_t dev0 = makedev(nvidia_major, 0);
    mknod("/dev/nvidia0", 0660 | S_IFCHR, dev0);
    mknod("/dev/nvidiactl", 0660 | S_IFCHR, makedev(nvidia_major, 255));

    kmsg_puts("GSP: waiting for firmware handshake (");
    { char tmp[16]; int n = snprintf(tmp, sizeof(tmp), "%d", timeout_secs); if (n > 0) { tmp[n] = 0; kmsg_puts(tmp); } }
    kmsg_puts("s timeout)...\n");

    for (int i = 0; i < timeout_secs; i++) {
        int fd = open("/dev/nvidia0", O_RDWR | O_NONBLOCK);
        if (fd >= 0) {
            close(fd);
            kmsg_puts("GSP: handshake complete (");
            { char tmp[16]; int n = snprintf(tmp, sizeof(tmp), "%d", i + 1); if (n > 0) { tmp[n] = 0; kmsg_puts(tmp); } }
            kmsg_puts("s)\n");
            return 0; // success
        }
        // ENODEV/ENXIO: node exists but GSP not ready yet
        // ENOENT: shouldn't happen since we mknod'd above
        // Log errno every 5 seconds
        if ((i % 5) == 0) {
            { char tmp[64];
              snprintf(tmp, sizeof(tmp), "GSP: errno=%d at %ds\n", errno, i);
              kmsg_puts(tmp); }
        }
        sleep(1);
    }

    kmsg_puts("GSP: handshake TIMEOUT after ");
    { char tmp[16]; int n = snprintf(tmp, sizeof(tmp), "%d", timeout_secs); if (n > 0) { tmp[n] = 0; kmsg_puts(tmp); } }
    kmsg_puts("s — continuing anyway\n");
    return -1; // timeout — continue anyway (fallback behavior)
}

// Read the nvidia char device major number from /proc/devices.
// Returns major (> 0) on success, -1 if not found.
static int get_nvidia_major(void) {
    int fd = open("/proc/devices", O_RDONLY);
    if (fd < 0) return -1;
    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;

    // Scan for "nvidia" entry (NOT nvidia-uvm)
    char *p = buf;
    while ((p = strstr(p, "nvidia")) != NULL) {
        char after = *(p + 6);
        if (after == '\n' || after == '\0' || after == ' ') {
            // Found "nvidia" — parse major from start of line
            char *start = p;
            while (start > buf && *(start - 1) != '\n') start--;
            return atoi(start);
        }
        p++;
    }
    return -1; // not found
}

// Load NVIDIA kernel modules in dependency order with GSP handshake wait.
//
// Flow:
//   1. Load nvidia.ko (GSP firmware starts asynchronously)
//   2. Wait for GSP firmware handshake (poll /dev/nvidia0, ~10-15s)
//   3. Load nvidia-uvm.ko and other sub-modules (need GSP to be ready)
//   4. Create /dev/nvidia-uvm device node
//
// Without the GSP wait, nvidia-uvm.ko and downstream modules load
// before the GSP-RM handshake completes, causing probe failures and
// Xid errors. The GSP handshake must finish BEFORE loading UVM.
static void load_nvidia_modules(void) {
    kmsg_puts("--- load_nvidia_modules start ---\n");

    struct stat st;
    if (stat(MODULES_DIR, &st) != 0 || !S_ISDIR(st.st_mode)) {
        kmsg_puts("No modules directory\n");
        return;
    }

    // ── Step 1: Load nvidia.ko (primary) ──────────────────────────
    // This starts the GSP firmware async handshake. The module init
    // (alloc_chrdev_region) completes immediately, but the GSP-RM
    // handshake takes ~10-15s asynchronously.
    kmsg_puts("--- Step 1: loading nvidia.ko ---\n");
    load_kernel_module(MODULES_DIR "/nvidia.ko");

    // ── Step 2: Wait for GSP firmware handshake ───────────────────
    // The nvidia.ko driver creates /dev/nvidia0 in devtmpfs when the
    // GSP-RM handshake completes. We poll with open() to detect this.
    kmsg_puts("--- Step 2: waiting for GSP firmware handshake ---\n");
    int nvidia_major = get_nvidia_major();
    int gsp_ready = 0;
    if (nvidia_major > 0) {
        gsp_ready = (wait_for_nvidia_gsp(30, nvidia_major) == 0);
    } else {
        kmsg_puts("GSP: nvidia major not found in /proc/devices\n");
    }

    // ── Step 3: Load remaining NVIDIA modules ─────────────────────
    // nvidia-uvm.ko and nvidia-modeset.ko depend on the GSP being
    // ready. They should only be loaded after GSP handshake.
    kmsg_puts("--- Step 3: loading remaining NVIDIA modules ---\n");
    if (gsp_ready) {
        load_kernel_module(MODULES_DIR "/nvidia-uvm.ko");
        load_kernel_module(MODULES_DIR "/nvidia-modeset.ko");
        load_kernel_module(MODULES_DIR "/nvidia-drm.ko");
        load_kernel_module(MODULES_DIR "/nvidia-peermem.ko");
    } else {
        // GSP not ready — try loading anyway (may hang or fail)
        kmsg_puts("GSP: not ready — loading remaining modules anyway (may fail)\n");
        load_kernel_module(MODULES_DIR "/nvidia-uvm.ko");
        load_kernel_module(MODULES_DIR "/nvidia-modeset.ko");
        load_kernel_module(MODULES_DIR "/nvidia-drm.ko");
        load_kernel_module(MODULES_DIR "/nvidia-peermem.ko");
    }

    // ── Step 4: Create nvidia-uvm device node ─────────────────────
    // /dev/nvidia0 and /dev/nvidiactl were created by
    // wait_for_nvidia_gsp(). nvidia-uvm needs a separate node.
    {
        int fd = open("/proc/devices", O_RDONLY);
        if (fd >= 0) {
            char buf[4096];
            int n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0) {
                buf[n] = 0;
                // Create /dev/nvidia-uvm from /proc/devices
                char *p = strstr(buf, "nvidia-uvm");
                if (p) {
                    char *start = p;
                    while (start > buf && *(start - 1) != '\n') start--;
                    int major = atoi(start);
                    if (major > 0) {
                        dev_t dev = makedev(major, 0);
                        mknod("/dev/nvidia-uvm", 0660 | S_IFCHR, dev);
                        kmsg_puts("/dev/nvidia-uvm created\n");
                    }
                }
            }
        }

        // Verify nvidia0
        if (stat("/dev/nvidia0", &st) == 0) {
            kmsg_puts("GPU nodes: /dev/nvidia0 OK\n");
        } else {
            kmsg_puts("GPU nodes: /dev/nvidia0 MISSING\n");
        }
        // Verify nvidia-uvm
        if (stat("/dev/nvidia-uvm", &st) == 0) {
            kmsg_puts("GPU nodes: /dev/nvidia-uvm OK\n");
        } else {
            kmsg_puts("GPU nodes: /dev/nvidia-uvm MISSING\n");
        }
        // Verify device usability with open()
        int test_fd = open("/dev/nvidia0", O_RDWR | O_NONBLOCK);
        if (test_fd >= 0) {
            close(test_fd);
            kmsg_puts("GPU device: /dev/nvidia0 READY\n");
        } else {
            kmsg_puts("GPU device: /dev/nvidia0 NOT READY\n");
        }
    }

    kmsg_puts("--- load_nvidia_modules end ---\n");
}

// ─── Direct NVIDIA module loading for QEMU serial path ──────────
// This variant calls finit_module from the init process directly
// (no fork), avoiding serial FD inheritance issues that break the
// QEMU serial communication channel.
//
// Unlike the auto-modprobe path (load_nvidia_modules), this path
// DOES wait for GSP firmware handshake because the serial protocol
// doesn't support async GSP polling from the host.
//
// REGRESSION (2026-07-27): GSP firmware RM handshake times out in
// VFIO passthrough — /dev/nvidia0 open() returns ENODEV.
// Switching to GSP=0 bypasses GSP handshake. The legacy RM init path
// handles Falcon power-gating correctly on nvidia 595.84.
static void load_nvidia_modules_direct(void) {
    struct stat st;
    if (stat(MODULES_DIR, &st) != 0 || !S_ISDIR(st.st_mode)) {
        kmsg_puts("ERROR: no modules directory\n");
        return;
    }

    // ── Step 1: Load nvidia.ko (creates /dev/nvidia*) ─────────
    {
        const char *path = MODULES_DIR "/nvidia.ko";
        kmsg_puts("mod_load: ");
        kmsg_puts(path);
        kmsg_puts("\n");
        serial_puts("mod_load: ");
        serial_puts(path);
        serial_puts("\n");

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            kmsg_puts("  ERROR: cannot open stub module\n");
            serial_puts("  ERROR: cannot open stub module\n");
            return;
        }

        long ret = syscall(SYS_finit_module, fd, "", 0);
        int saved_errno = errno;
        close(fd);

        if (ret == 0) {
            kmsg_puts("  OK (stub)\n");
            serial_puts("  OK (stub)\n");
        } else if (saved_errno == EEXIST) {
            kmsg_puts("  already loaded\n");
            serial_puts("  already loaded\n");
        } else {
            { char tmp[64];
              snprintf(tmp, sizeof(tmp), "  FAIL: errno=%d\n", saved_errno);
              kmsg_puts(tmp);
              serial_puts(tmp); }
            return;
        }
    }

    // ── Step 2: Skip nvidia.ko (GSP hangs in VFIO) ─────────────────
    kmsg_puts("nvidia.ko: skipped (stub provides device nodes)\n");
    serial_puts("nvidia.ko: skipped (stub provides device nodes)\n");

    // ── Skip sub-modules (nvidia-uvm, modeset; not needed with stub) ─
    kmsg_puts("sub-modules: skipped (stub provides all nodes)\n");
    serial_puts("sub-modules: skipped (stub provides all nodes)\n");

    // ── Step 3: Verify device nodes (stub creates them) ────────────
    {
        // Verify nvidia0 exists
        if (stat("/dev/nvidia0", &st) == 0) {
            kmsg_puts("GPU nodes: /dev/nvidia0 OK\n");
            serial_puts("GPU nodes: /dev/nvidia0 OK\n");
        } else {
            kmsg_puts("GPU nodes: /dev/nvidia0 MISSING\n");
            serial_puts("GPU nodes: /dev/nvidia0 MISSING\n");
        }
        // Test open nvidia0
        int test_fd = open("/dev/nvidia0", O_RDWR | O_NONBLOCK);
        if (test_fd >= 0) {
            close(test_fd);
            kmsg_puts("GPU device: /dev/nvidia0 READY\n");
            serial_puts("GPU device: /dev/nvidia0 READY\n");
        } else {
            { char tmp[64];
              snprintf(tmp, sizeof(tmp), "GPU device: /dev/nvidia0 errno=%d\n", errno);
              kmsg_puts(tmp);
              serial_puts(tmp); }
        }
        // Test open nvidiactl
        int ctl_fd = open("/dev/nvidiactl", O_RDWR | O_NONBLOCK);
        if (ctl_fd >= 0) {
            close(ctl_fd);
            kmsg_puts("GPU device: /dev/nvidiactl READY\n");
            serial_puts("GPU device: /dev/nvidiactl READY\n");
        } else {
            { char tmp[64];
              snprintf(tmp, sizeof(tmp), "GPU device: /dev/nvidiactl errno=%d\n", errno);
              kmsg_puts(tmp);
              serial_puts(tmp); }
        }
    }
}

// Load Nouveau kernel module with DRM subsystem dependencies.
// nouveau.ko needs: ttm, drm_kms_helper, drm_exec, drm_gpuvm, gpu-sched, etc.
// These are all under MODULES_DIR/drivers/gpu/drm/ and related paths.
//
// Uses the same fork+timeout mechanism as load_nvidia_modules().
// Returns 0 if nouveau loaded successfully, -1 on failure.
static int load_nouveau_modules(void) {
    kmsg_puts("--- load_nouveau_modules start ---\n");

    struct stat st;
    if (stat(MODULES_DIR, &st) != 0 || !S_ISDIR(st.st_mode)) {
        kmsg_puts("No modules directory\n");
        out_puts("No modules directory\n");
        return -1;
    }

    // Load DRM subsystem modules in dependency order, then nouveau.
    // DRM core (drm.ko) is typically built-in on modern kernels — only
    // the sub-modules need explicit loading.
    const char *modules[] = {
        // DRM dependencies (in dependency order)
        MODULES_DIR "/drivers/video/backlight/backlight.ko",
        MODULES_DIR "/drivers/i2c/algos/i2c-algo-bit.ko",
        MODULES_DIR "/drivers/platform/wmi/wmi.ko",
        MODULES_DIR "/drivers/acpi/video.ko",
        MODULES_DIR "/drivers/gpu/drm/ttm/ttm.ko",
        MODULES_DIR "/drivers/gpu/drm/scheduler/gpu-sched.ko",
        MODULES_DIR "/drivers/gpu/drm/drm_exec.ko",
        MODULES_DIR "/drivers/gpu/drm/drm_gpuvm.ko",
        MODULES_DIR "/drivers/gpu/drm/drm_ttm_helper.ko",
        // drm_kms_helper MUST be before drm_display_helper
        // (drm_display_helper depends on drm_kms_helper symbols)
        MODULES_DIR "/drivers/gpu/drm/drm_kms_helper.ko",
        MODULES_DIR "/drivers/gpu/drm/display/drm_display_helper.ko",
        // Finally, nouveau itself (depends on drm_kms_helper, drm_display_helper, ttm, ...)
        MODULES_DIR "/drivers/gpu/drm/nouveau/nouveau.ko",
        NULL
    };

    int nouveau_loaded = 0;
    for (int i = 0; modules[i] != NULL; i++) {
        int ret = load_kernel_module(modules[i]);
        if (ret == 0) {
            kmsg_puts("  [OK] ");
            kmsg_puts(modules[i] + strlen(MODULES_DIR) + 1);
            kmsg_puts("\n");
            out_puts("  [OK] ");
            out_puts(modules[i] + strlen(MODULES_DIR) + 1);
            out_puts("\n");
            // nouveau.ko is the last entry in modules[] (before NULL)
            if (modules[i + 1] == NULL) nouveau_loaded = 1;
        } else if (ret == -1) {
            const char *name = modules[i] + strlen(MODULES_DIR) + 1;
            kmsg_puts("  [FAIL] ");
            kmsg_puts(name);
            kmsg_puts("\n");
            out_puts("  [FAIL] ");
            out_puts(name);
            out_puts("\n");
        }
    }

    // Check if /dev/dri/card0 appeared
    if (stat("/dev/dri/card0", &st) == 0) {
        kmsg_puts("Nouveau GPU driver active: /dev/dri/card0 available\n");
    } else if (stat("/dev/dri", &st) == 0) {
        kmsg_puts("Nouveau loaded but /dev/dri/card0 not yet available\n");
    } else {
        kmsg_puts("/dev/dri not created — nouveau may not have probed\n");
    }
    kmsg_puts("--- load_nouveau_modules end ---\n");
    return nouveau_loaded ? 0 : -1;
}

// Write to /dev/kmsg with KERN_ERR priority (level <4, visible at loglevel=4)
// Goes through kernel printk → serial console (polled mode, always works)
static int kmsg_fd = -1;

static void kmsg_puts(const char *s) {
    if (kmsg_fd < 0) return;
    struct iovec iov[2];
    // Use KERN_EMERG (<0>) which prints at ANY loglevel
    static const char prefix[] = "<0>";
    iov[0].iov_base = (void *)(uintptr_t)prefix;
    iov[0].iov_len = 3;
    iov[1].iov_base = (void *)(uintptr_t)s;
    iov[1].iov_len = strlen(s);
    long ignored = syscall(SYS_writev, kmsg_fd, iov, 2);
    (void)ignored;
}

// Write to OUT_BUF (shared memory visible to host) — used by module loading
// functions to report per-module diagnostics. Falls back to kmsg if OUT_BUF
// pointer not yet initialized (early init).
// NOTE: g_out_buf and g_out_off are declared earlier (before run_python)
// to enable real-time output forwarding in the read loop.
static void out_puts(const char *s) {
    if (!g_out_buf) {
        kmsg_puts(s);  // fallback before OUT_BUF is mapped
        return;
    }
    size_t off = g_out_off;
    while (*s && off < BUF_MAX - 1) {
        g_out_buf[off++] = (unsigned char)*s++;
    }
    g_out_buf[off] = 0;
    g_out_off = off;
    // Memory barrier: ensure writes are visible to host
    __asm__ volatile("mfence" ::: "memory");
}

// Serial output using write(1, ...) — goes through kernel serial driver.
// No inb/outb needed; iopl() not required. The kernel's 8250 serial driver
// handles the actual UART access, triggering KVM_EXIT_IO naturally.
// CR before LF for proper terminal output.

static void serial_putchar(char c) {
    if (c == '\n') {
        char cr = '\r';
        syscall(SYS_write, 1, &cr, 1);
    }
    syscall(SYS_write, 1, &c, 1);
}

static void serial_puts(const char *s) {
    while (*s) {
        serial_putchar(*s++);
    }
}

// Trim trailing newlines
static void trim_trailing_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r'))
        s[--len] = '\0';
}

// ─── Kernel cmdline parsing ────────────────────────────────────────
static void flush_utrace(void) {
    static int ufd = -1;
    static long last = 0;
    if (ufd < 0) ufd = open("/tmp/utrace.log", O_RDONLY);
    if (ufd < 0) return;
    char ubuf[2048];
    long end = lseek(ufd, 0, SEEK_END);
    if (end > last) {
        serial_puts("UT_FLUSH\n");
        lseek(ufd, last, SEEK_SET);
        ssize_t rn;
        while ((rn = read(ufd, ubuf, sizeof(ubuf))) > 0) {
            write(1, ubuf, rn);
            last = lseek(ufd, 0, SEEK_CUR);
        }
    }
}
// Check if a flag is present in /proc/cmdline
static int cmdline_has_flag(const char *flag) {
    int cmdline_fd = open("/proc/cmdline", O_RDONLY);
    if (cmdline_fd < 0) return 0;
    char buf[4096];
    int n = read(cmdline_fd, buf, sizeof(buf) - 1);
    close(cmdline_fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    return strstr(buf, flag) != NULL;
}

// ─── QEMU serial protocol ──────────────────────────────────────────
// Reads a line from stdin (serial console), executes it, outputs result.
// Protocol:
//   1. Output "READY\n" to signal boot complete
//   2. Read code from stdin (up to BUF_MAX-1 bytes, newline-terminated)
//   3. Execute with Python
//   4. Output result, then "DONE\n"
//   5. Read next command (loop until EOF or error)
static void qemu_serial_loop(const char *python) {
    // Signal boot complete
    serial_puts("READY\n");

    char code_buf[BUF_MAX];
    int pos;
    char ch;

    for (;;) {
        // Read code from stdin (serial console)
        pos = 0;
        while (pos < BUF_MAX - 1) {
            int n = syscall(SYS_read, 0, &ch, 1);
            if (n <= 0) { _exit(0); }
            if (ch == '\n' || ch == '\r') break;
            code_buf[pos++] = ch;
        }
        code_buf[pos] = '\0';

        // Empty line = no-op (e.g. leftover newlines)
        if (pos == 0) continue;

        // Execute
        char *result = NULL;
        if (python) {
            result = run_python(code_buf, python);
        }

        // Output result
        if (result) {
            serial_puts(result);
            free(result);
        } else {
            serial_puts("ERROR: execution failed or no Python");
        }

        // Signal done
        serial_puts("\nDONE\n");
    }
}

// ─── cmd.json parsing ─────────────────────────────────────────────────
// Reads /cmd.json from the initramfs to determine the interpreter
// or direct executable to use for code execution.
//
// Format:
//   { "interpreter": "/usr/bin/python3", "args": ["-c"] }
//   { "exec": "/app/myapp" }
//
// Returns 0 and fills *interpreter/*args if cmd.json found and valid.
// Returns -1 if no cmd.json (use default python detect).

#define CMD_JSON_MAX 4096

static int parse_cmd_json(char *interpreter, size_t intr_size,
                          char **args, int *arg_count,
                          char *exec_path, size_t exec_size) {
    int fd = open("/cmd.json", O_RDONLY);
    if (fd < 0) return -1;  // No cmd.json

    char buf[CMD_JSON_MAX];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;

    buf[n] = '\0';

    // Very simple JSON parsing — look for "interpreter" or "exec" fields
    // Full JSON parser not needed for this simple schema.

    // Check for "exec" field first (direct binary exec)
    char *exec_match = strstr(buf, "\"exec\"");
    if (exec_match) {
        char *colon = strchr(exec_match, ':');
        if (colon) {
            char *start = strchr(colon, '"');
            if (start) {
                start++;  // skip opening quote
                char *end = strchr(start, '"');
                if (end && (size_t)(end - start) < exec_size - 1) {
                    memcpy(exec_path, start, end - start);
                    exec_path[end - start] = '\0';
                    return 0;  // exec mode
                }
            }
        }
    }

    // Check for "interpreter" field
    char *intr_match = strstr(buf, "\"interpreter\"");
    if (!intr_match) return -1;

    char *colon = strchr(intr_match, ':');
    if (!colon) return -1;

    char *start = strchr(colon, '"');
    if (!start) return -1;
    start++;  // skip opening quote

    char *end = strchr(start, '"');
    if (!end || (size_t)(end - start) >= intr_size) return -1;

    memcpy(interpreter, start, end - start);
    interpreter[end - start] = '\0';

    // Look for "args" array — just read first string element
    char *args_match = strstr(buf, "\"args\"");
    if (args_match) {
        char *abracket = strchr(args_match, '[');
        if (abracket) {
            // Find first string in array
            char *astart = strchr(abracket, '"');
            if (astart) {
                astart++;
                char *aend = strchr(astart, '"');
                if (aend && (size_t)(aend - astart) < 64) {
                    static char arg_buf[64];
                    memcpy(arg_buf, astart, aend - astart);
                    arg_buf[aend - astart] = '\0';
                    if (args && arg_count) {
                        args[0] = arg_buf;
                        *arg_count = 1;
                    }
                }
            }
        }
    }

    return 0;  // interpreter mode
}

// ─── Generalized execution ───────────────────────────────────────────
// Execute code using the configured interpreter or direct exec.
// Supports both "interpreter + args" and "exec" modes from cmd.json.

// Forward declarations
static char *run_python(const char *code, const char *python);

static char *run_general(const char *code,
                         const char *interpreter,
                         char **args, int arg_count,
                         const char *exec_path) {
    // Direct exec mode: run the executable directly (code passed via CMD_BUF)
    if (exec_path && exec_path[0] != '\0') {
        // For direct exec, we fork + exec the binary
        // The binary reads code from CMD_BUF or uses its own protocol
        int stdout_pipe[2];
        if (pipe(stdout_pipe) < 0) return NULL;

        pid_t pid = fork();
        if (pid < 0) { close(stdout_pipe[0]); close(stdout_pipe[1]); return NULL; }

        if (pid == 0) {
            close(stdout_pipe[0]);
            dup2(stdout_pipe[1], STDOUT_FILENO);
            dup2(stdout_pipe[1], STDERR_FILENO);
            if (stdout_pipe[1] > STDERR_FILENO) close(stdout_pipe[1]);
            execl(exec_path, exec_path, NULL);
            char buf[128];
            int n = snprintf(buf, sizeof(buf), "EXEC FAILED: path=%s errno=%d\n", exec_path, errno);
            syscall(SYS_write, STDOUT_FILENO, buf, (size_t)(n < (int)sizeof(buf) ? n : sizeof(buf) - 1));
            _exit(127);
        }

        close(stdout_pipe[1]);
        char *output = malloc(OUT_BUF_MAX);
        if (!output) { close(stdout_pipe[0]); waitpid(pid, NULL, 0); return NULL; }

        ssize_t total = 0;
        ssize_t nread;
        while (total < OUT_BUF_MAX - 1 &&
               (nread = read(stdout_pipe[0], output + total, OUT_BUF_MAX - 1 - total)) > 0)
            total += nread;
        output[total] = '\0';
        close(stdout_pipe[0]);
        waitpid(pid, NULL, 0);
        return output;
    }

    // Interpreter mode: run interpreter + args (typically python -c ...)
    if (interpreter && interpreter[0] != '\0') {
        // If it's python-like (has -c arg), use run_python
        if (strstr(interpreter, "python") || strstr(interpreter, "micropython")) {
            return run_python(code, interpreter);
        }

        // General interpreter: run interpreter arg0 "code"
        int stdout_pipe[2];
        if (pipe(stdout_pipe) < 0) return NULL;

        pid_t pid = fork();
        if (pid < 0) { close(stdout_pipe[0]); close(stdout_pipe[1]); return NULL; }

        if (pid == 0) {
            close(stdout_pipe[0]);
            dup2(stdout_pipe[1], STDOUT_FILENO);
            dup2(stdout_pipe[1], STDERR_FILENO);
            if (stdout_pipe[1] > STDERR_FILENO) close(stdout_pipe[1]);

            if (arg_count > 0 && args[0]) {
                // interpreter -c "code"  (e.g., python -c, node -e)
                execl(interpreter, interpreter, args[0], code, NULL);
            } else {
                // interpreter "code"  (just pass code as first arg)
                execl(interpreter, interpreter, code, NULL);
            }
            char buf[128];
            int n = snprintf(buf, sizeof(buf), "EXEC FAILED: path=%s errno=%d\n", interpreter, errno);
            syscall(SYS_write, STDOUT_FILENO, buf, (size_t)(n < (int)sizeof(buf) ? n : sizeof(buf) - 1));
            _exit(127);
        }

        close(stdout_pipe[1]);
        char *output = malloc(OUT_BUF_MAX);
        if (!output) { close(stdout_pipe[0]); waitpid(pid, NULL, 0); return NULL; }

        ssize_t total = 0;
        ssize_t nread;
        while (total < OUT_BUF_MAX - 1 &&
               (nread = read(stdout_pipe[0], output + total, OUT_BUF_MAX - 1 - total)) > 0)
            total += nread;
        output[total] = '\0';
        close(stdout_pipe[0]);
        waitpid(pid, NULL, 0);
        return output;
    }

    // Fallback: python -c
    const char *python = detect_python();
    if (python) return run_python(code, python);
    return NULL;
}

// ─── Entry point ─────────────────────────────────────────────────────
int main(int argc, char *argv[]) {
    // Mount essential filesystems.
    // Order matters: devtmpfs must be mounted before creating /dev/shm
    // because devtmpfs populates /dev with device nodes. The mkdir for
    // /dev/shm must happen AFTER to be visible inside the mount.
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);
    mkdir("/dev", 0755);
    mount("none", "/dev", "devtmpfs", 0, NULL);
    mount("none", "/proc", "proc", 0, NULL);
    mount("none", "/sys", "sysfs", 0, NULL);
    // /dev/shm needs to be mounted after devtmpfs so it's visible
    mkdir("/dev/shm", 0755);
    mount("none", "/dev/shm", "tmpfs", 0, NULL);

    // Parse cmd.json for interpreter configuration
    char cmd_interpreter[256] = "";
    char *cmd_args[4] = {NULL, NULL, NULL, NULL};
    int cmd_arg_count = 0;
    char cmd_exec_path[256] = "";
    int has_cmd_json = (parse_cmd_json(cmd_interpreter, sizeof(cmd_interpreter),
                                        cmd_args, &cmd_arg_count,
                                        cmd_exec_path, sizeof(cmd_exec_path)) == 0);

    const char *python = detect_python();

    // Set PATH so tinygrad's dynamic library loader can find libc
    // (tinygrad runtime uses c.DLL.findlib() which reads os.environ['PATH'])
    setenv("PATH", "/usr/bin:/bin:/sbin", 1);

    // Don't write .pyc at runtime — they're precompiled in the initramfs.
    // Saves ~200-500ms on first import.
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1);

    // Set NV_RENDERER=NAK (used by tinymesa's NAK compiler runtime)
    setenv("NV_RENDERER", "NAK", 1);

    // Set DEV=NV:NAK to force tinygrad to select the NAK renderer for the NV
    // device. Without this, tinygrad tries CUDARenderer which needs `nvcc`
    // from the CUDA toolkit (not available in the initrd). The NAK renderer
    // compiles GPU SASS directly via libtinymesa.so (bundled in the initrd
    // at /usr/local/lib/libtinymesa.so or found via LD_LIBRARY_PATH).
    setenv("DEV", "NV:NAK", 1);
    setenv("LD_PRELOAD", "/lib/libtrace_cuda.so", 1);

    // Set LD_LIBRARY_PATH so Python's ctypes.util.find_library() can find
    // shared libraries without needing ldconfig. Without this, ctypes
    // returns None for CDLL(None) which loads the main binary by mistake.
    // See the "atomic_thread_fence" bug in BLOG.md for the gory details.
    setenv("LD_LIBRARY_PATH", "/lib:/usr/lib:/usr/lib/x86_64-linux-gnu", 0);
    setenv("PYTHONHOME", "/usr", 0);

    // Run ldconfig to rebuild /etc/ld.so.cache so Python's ctypes
    // can find libraries by SONAME. This is the canonical fix — the
    // environment approach, not source-code patching.
    // ldconfig.real is statically linked (no library dependencies).
    // We use the real binary directly since /sbin/ldconfig on Ubuntu
    // is a shell wrapper that execs ldconfig.real.
    system("/sbin/ldconfig 2>/dev/null || true");

    // Create /dev/kmsg and open for kernel diagnostic output
    // Writes with KERN_ERR (<3>) prefix appear on serial console at loglevel=4
    mknod("/dev/kmsg", 0600 | S_IFCHR, makedev(1, 11));
    kmsg_fd = open("/dev/kmsg", O_WRONLY);
    if (kmsg_fd < 0) {
        // /dev/kmsg may not be available; fall back to write(1, ...) or uart
    } else {
        // Write a test message to verify kmsg works
        kmsg_puts("init: /dev/kmsg opened successfully\n");
    }

    // Serial output goes through write(1, ...) — kernel serial driver handles
    // the UART access, triggering KVM_EXIT_IO. No iopl() needed.
    // kmsg_puts() is used for diagnostics (goes through /dev/kmsg → printk).
    kmsg_puts("init: serial output via write(1, ...)\n");

    // ── Check for QEMU serial mode ──
    // If booting under QEMU (detected via kernel cmdline flag),
    // use the serial console protocol instead of shared memory.
    {
        // Debug: dump /proc/cmdline contents
        int dbg_fd = open("/proc/cmdline", O_RDONLY);
        if (dbg_fd >= 0) {
            char dbg_buf[512];
            int n = read(dbg_fd, dbg_buf, sizeof(dbg_buf) - 1);
            close(dbg_fd);
            if (n > 0) {
                dbg_buf[n] = 0;
                // Print cmdline to serial so we can debug
                serial_puts("cmdline: ");
                serial_puts(dbg_buf);
                serial_puts("\n");
            }
        }
    }
    if (cmdline_has_flag("tinyos.qemu=1")) {
        // Load NVIDIA modules directly before starting serial loop.
        // Uses direct finit_module (no fork) to avoid serial FD leak.
        // finit_module returns quickly; GSP firmware continues async.
        load_nvidia_modules_direct();

        // Run NV test script if present, then fall through to serial loop.
        // The test script uses PCIIface (direct BAR MMIO, no kernel module
        // dependency) to initialize the NV device and print device info.
        // Check if the full NV VFIO test script exists and run it via system()
        // Using system() instead of run_python() to bypass pipe/fork issues
        if (access("/usr/lib/python3.12/dist-packages/nv_test_vfio.py", F_OK) == 0) {
            serial_puts("NV_TEST_BEGIN\n");
            serial_puts("NV_PYTHON: ");
            serial_puts(python ? python : "(null)");
            serial_puts("\n");

            // Wait 3 seconds for GPU to be in a stable state after module load
            serial_puts("NV_WAIT_3s\n");
            for (int i = 0; i < 3; i++) {
                sleep(1);
                serial_puts(".");
            }
            serial_puts("\n");

            serial_puts("NV_EXEC\n");
            char *nv_result = run_python("import os, sys, time\nsys.path.insert(0, '/usr/lib/python3.12/dist-packages')\nos.environ['NV_DEBUG'] = '0'\nexec(open('/usr/lib/python3.12/dist-packages/tinyos_nv_patch.py').read())\napply_patches()\n# ── TRACE: wrap os.open for nvidia device nodes ──\nimport os as _os\nimport ctypes as _ctypes\nimport glob as _glob\n_orig_open = _os.open\ndef _trace_open(path, flags, mode=0o777, **kw):\n    p = path if isinstance(path, str) else path.decode(errors='replace')\n    if 'nvidia' in p:\n        print('TRACE_OPEN:', p); sys.stdout.flush()\n    return _orig_open(path, flags, mode, **kw)\n_os.open = _trace_open\n# ── TRACE: wrap ctypes.CDLL for library loading ──\n_orig_cdll = _ctypes.CDLL.__init__\ndef _trace_cdll(self, name, **kw):\n    print('TRACE_CDLL:', name); sys.stdout.flush()\n    return _orig_cdll(self, name, **kw)\n_ctypes.CDLL.__init__ = _trace_cdll\n# ── SYSFS PCI enumeration ──\nprint('SYSFS_PCI:', _glob.glob('/sys/bus/pci/devices/*'))\nsys.stdout.flush()\nprint('SYSFS_NV_DRV:', _glob.glob('/sys/bus/pci/drivers/*nvidia*'))\nsys.stdout.flush()\nprint('DEV_NV:', _glob.glob('/dev/nvidia*'))\nsys.stdout.flush()\nif _os.path.exists('/proc/bus/pci/devices'):\n    print('PROC_PCI:', open('/proc/bus/pci/devices').read()[:600])\n    sys.stdout.flush()\nelse:\n    print('PROC_PCI: MISSING')\n    sys.stdout.flush()\n# Check for VFIO PCI devices\nprint('VFIO_PCI:', _glob.glob('/sys/bus/pci/devices/*/driver')[:5])\nsys.stdout.flush()\n# Check libcuda availability\nfor _libp in ['/usr/lib/libcuda.so.1', '/usr/lib/libcuda.so', '/usr/lib/x86_64-linux-gnu/libcuda.so']:\n    print('LIBCUDA:', _libp, _os.path.exists(_libp))\n    sys.stdout.flush()\n# ── End trace ──\nfrom tinygrad import Device, dtypes\nprint('M1:start')\nsys.stdout.flush()\ndev = Device['NV']\nprint('M2:dev', type(dev).__name__, type(dev.iface).__name__)\nsys.stdout.flush()\niface = dev.iface\n# BAR0 info via PCIIface API\nbar0_addr, bar0_sz = iface.pci_dev.bar_info(0)\nprint('M3:BAR0', hex(bar0_addr), hex(bar0_sz))\nsys.stdout.flush()\n# Read BAR0 offset 0 (Device ID) using map_bar\nbar0 = iface.pci_dev.map_bar(bar=0, off=0, size=0x1000, fmt='I')\nprint('M4:BAR0_devid', hex(bar0[0]))\nsys.stdout.flush()\n# Test gpu_mmio (pre-mapped by setup_usermode)\nprint('M5:gpu_mmio', hex(dev.gpu_mmio[0]))\nsys.stdout.flush()\n# VRAM allocation\nbuf = iface.alloc(256, host=False)\nprint('M6:alloc', hex(buf.va_addr), buf.size)\nsys.stdout.flush()\niface.free(buf)\nprint('M7:free_ok')\nsys.stdout.flush()\n# Re-bind GPU to nvidia stub for CUDA RM API\nimport os as _rb_os\n_rb_path = '/sys/bus/pci/drivers/nvidia/bind'\nif _rb_os.path.exists(_rb_path):\n    try:\n        _rb_fd = _rb_os.open(_rb_path, _rb_os.O_WRONLY)\n        _rb_os.write(_rb_fd, b'0000:00:02.0\\n')\n        _rb_os.close(_rb_fd)\n        print('M7b:rebind_ok', flush=True)\n    except Exception as _rb_e:\n        print('M7b:rebind_fail_' + str(_rb_e), flush=True)\n# CUDA tensor operations (requires libcuda.so in initrd)\nfrom tinygrad import Tensor\nimport traceback as _tb\n# Print lsof-like info before CUDA\ntry:\n    print('BEFORE_CUDA_open_fds:', [(p, str(_os.readlink(f'/proc/self/fd/{p}'))) for p in _os.listdir('/proc/self/fd') if p.isdigit()])\nexcept Exception as _ex:\n    print('BEFORE_CUDA_open_fds_err:', _ex)\nsys.stdout.flush()\ntry:\n    cdev = Device['CUDA']\n    print('M8:CUDA_dev', type(cdev).__name__, cdev.arch)\n    sys.stdout.flush()\n    a = Tensor([1,2,3], device='CUDA')\n    b = Tensor([4,5,6], device='CUDA')\n    c = (a + b).tolist()\n    print('M9:CUDA_add', c)\n    sys.stdout.flush()\n    x = Tensor.eye(3, device='CUDA')\n    print('MA:CUDA_eye', x.tolist())\n    sys.stdout.flush()\n    print('MB:CUDA_OK')\n    sys.stdout.flush()\nexcept Exception as _e:\n    print('M8:CUDA_err', type(_e).__name__, str(_e)[:300])\n    sys.stdout.flush()\n    _tb.print_exc()\n    sys.stdout.flush()\n# Print open fds after CUDA attempt\nprint('AFTER_CUDA_open_fds:', [(p, str(_os.readlink(f'/proc/self/fd/{p}'))) for p in _os.listdir('/proc/self/fd') if p.isdigit()])\nsys.stdout.flush()\n", python);
            if (nv_result) {
                serial_puts("NV_TEST_OUTPUT:\n");
                serial_puts(nv_result);
                free(nv_result);
            } else {
                serial_puts("NV_TEST_ERROR: execution failed\n");
            }
            // Print CUDA trace log (from LD_PRELOAD)
            int trace_fd = open("/tmp/cuda_trace.log", O_RDONLY);
            if (trace_fd >= 0) {
                char trace_buf[4096];
                int n;
                serial_puts("CUDA_TRACE:\n");
                while ((n = read(trace_fd, trace_buf, sizeof(trace_buf))) > 0)
                    write(1, trace_buf, n);
                close(trace_fd);
            }
            serial_puts("UTRACE_BEGIN\n");
            int utrace_fd = open("/tmp/utrace.log", O_RDONLY);
            if (utrace_fd >= 0) {
                char trace_buf[4096];
                int n;
                while ((n = read(utrace_fd, trace_buf, sizeof(trace_buf))) > 0)
                    write(1, trace_buf, n);
                close(utrace_fd);
            }
            serial_puts("UTRACE_END\n");
            serial_puts("NV_TEST_END\n");
        }

        qemu_serial_loop(python);
        // qemu_serial_loop never returns; if it does, exit
        _exit(0);
    }

    // ── Shared memory protocol (KVM CoW fork) ──

    // mmap /dev/mem for zero-copy shared memory
    int fd = open("/dev/mem", O_RDWR);
    if (fd < 0) {
        serial_puts("ERROR: /dev/mem not available\n");
        _exit(1);
    }

    // mmap must cover ENTROPY_DIVERGENCE_CTRL_PHYS (0x7CFFF) through
    // OUT_BUF_PHYS + BUF_MAX + 16. Align start down to include the control byte.
    size_t map_start = ENTROPY_DIVERGENCE_CTRL_PHYS & ~(size_t)0xFFF;  // 0x7C000
    size_t map_offset = CMD_BUF_PHYS - map_start;
    size_t map_size = (OUT_BUF_PHYS - map_start) + BUF_MAX + 16;

    volatile unsigned char *map_base = mmap(NULL, map_size,
                                            PROT_READ | PROT_WRITE,
                                            MAP_SHARED, fd, map_start);
    close(fd);

    if (map_base == MAP_FAILED) {
        serial_puts("ERROR: /dev/mem mmap failed\n");
        _exit(1);
    }

    volatile unsigned char *cmd_buf = map_base + map_offset;
    volatile unsigned char *out_buf = map_base + (OUT_BUF_PHYS - map_start);
    volatile unsigned char *ready   = out_buf + READY_OFFSET;
    g_out_buf = out_buf;  // init global OUT_BUF pointer for out_puts()/run_python()

    // ── Boot READY — signal host that init is alive ──
    // This is a ONE-TIME signal (not in the while loop) so the host's
    // boot-time run_until_ready() can detect that init is running and
    // waiting for commands. After this, READY is only set when a command
    // is actually processed (inside the if(cmd_len > 0) block below),
    // eliminating the stale-READY race condition that caused commands
    // to be skipped or host to read empty output.
    ready[0] = 'R';
    ready[1] = 'E';
    ready[2] = 'A';
    ready[3] = 'D';
    ready[4] = 'Y';
    ready[5] = 0;
    // Serial write to produce VM exit so host detects READY
    syscall(SYS_write, 1, "\n", 1);

    // ── Network configuration from kernel cmdline ──────────────────
    // Without CONFIG_IP_PNP the kernel ip= cmdline is ignored, so init.c
    // configures the interface via raw ioctl (no busybox dependencies).
    {
        int net_fd2 = open("/proc/cmdline", O_RDONLY);
        if (net_fd2 >= 0) {
            char net_buf[1024];
            int n2 = read(net_fd2, net_buf, sizeof(net_buf) - 1);
            close(net_fd2);
            if (n2 > 0) {
                net_buf[n2] = 0;
                char *ip_p2 = strstr(net_buf, "ip=");
                if (ip_p2) {
                    char *p2 = ip_p2 + 3;
                    char client2[64] = {0}, gw2[64] = {0}, nm2[64] = {0}, dev2[64] = {0};
                    int i2;
                    for (i2 = 0; *p2 && *p2 != ':' && i2 < 63;) client2[i2++] = *p2++;
                    if (*p2) p2++;
                    for (; *p2 && *p2 != ':';) p2++;
                    if (*p2) p2++;
                    for (i2 = 0; *p2 && *p2 != ':' && i2 < 63;) gw2[i2++] = *p2++;
                    if (*p2) p2++;
                    for (i2 = 0; *p2 && *p2 != ':' && i2 < 63;) nm2[i2++] = *p2++;
                    if (*p2) p2++;
                    for (; *p2 && *p2 != ':';) p2++;
                    if (*p2) p2++;
                    for (i2 = 0; *p2 && *p2 != ':' && *p2 != ' ' && i2 < 63;) dev2[i2++] = *p2++;

                    if (client2[0] && dev2[0]) {
                        int sock2 = socket(AF_INET, SOCK_DGRAM, 0);
                        if (sock2 >= 0) {
                            struct ifreq ifr2;
                            struct sockaddr_in *sin2;

                            // Set IP address
                            memset(&ifr2, 0, sizeof(ifr2));
                            strncpy(ifr2.ifr_name, dev2, IFNAMSIZ - 1);
                            sin2 = (struct sockaddr_in *)&ifr2.ifr_addr;
                            sin2->sin_family = AF_INET;
                            sin2->sin_addr.s_addr = inet_addr(client2);
                            ioctl(sock2, SIOCSIFADDR, &ifr2);

                            // Set netmask
                            if (nm2[0]) {
                                memset(&ifr2, 0, sizeof(ifr2));
                                strncpy(ifr2.ifr_name, dev2, IFNAMSIZ - 1);
                                sin2 = (struct sockaddr_in *)&ifr2.ifr_netmask;
                                sin2->sin_family = AF_INET;
                                sin2->sin_addr.s_addr = inet_addr(nm2);
                                ioctl(sock2, SIOCSIFNETMASK, &ifr2);
                            }

                            // Bring up
                            memset(&ifr2, 0, sizeof(ifr2));
                            strncpy(ifr2.ifr_name, dev2, IFNAMSIZ - 1);
                            ioctl(sock2, SIOCGIFFLAGS, &ifr2);
                            ifr2.ifr_flags |= IFF_UP;
                            ioctl(sock2, SIOCSIFFLAGS, &ifr2);

                            close(sock2);
                        }
                    }
                }
            }
        }
    }

    // ── Busy-polling loop ──
    while (1) {
        // 1. Check CMD_BUF for a command (non-empty, non-zero)
        int cmd_len = 0;
        for (int i = 0; i < BUF_MAX - 1; i++) {
            if (cmd_buf[i] == 0) break;
            cmd_len = i + 1;
        }

        if (cmd_len > 0) {
            // Copy command to local stack
            char cmd[BUF_MAX];
            for (int i = 0; i < cmd_len && i < BUF_MAX - 1; i++)
                cmd[i] = (char)cmd_buf[i];
            cmd[cmd_len < BUF_MAX - 1 ? cmd_len : BUF_MAX - 1] = '\0';

            // Clear CMD_BUF so it's not re-executed
            memset((void *)cmd_buf, 0, BUF_MAX);

            // Clear READY area before execution
            memset((void *)ready, 0, 6);

            // ── Per-fork entropy divergence ──
            // Every KVM fork from a snapshot has an identical CRNG state.
            // The host writes 64 bytes of fresh CSPRNG to ENTROPY_BUF_PHYS
            // before each KVM_RUN, and sets the control byte at
            // ENTROPY_DIVERGENCE_CTRL_PHYS:
            //   1 (=ENTROPY_DIVERGENCE_ENABLED, default): consume a
            //     host-entropy-derived number of getrandom() bytes to offset
            //     the CRNG output position — each fork gets unique urandom.
            //   0 (=ENTROPY_DIVERGENCE_DISABLED, --measure flag): skip
            //     divergence entirely — every fork keeps the exact same
            //     CRNG state from the snapshot. Subsequent getrandom()
            //     returns identical data across forks, exposing natural
            //     system decorrelation (timer jitter, cache effects, etc.)
            //     for Lyapunov exponent / entropy rate measurement.
            {
                volatile unsigned char *div_ctrl =
                    map_base + (ENTROPY_DIVERGENCE_CTRL_PHYS - map_start);
                if (*div_ctrl != 0) {
                    // ── Normal mode: diverge CRNG across forks ──
                    volatile unsigned char *entropy_src =
                        map_base + (ENTROPY_BUF_PHYS - map_start);
                    // First 2 bytes of host entropy → skip amount
                    unsigned int skip = (unsigned int)entropy_src[0]
                                      | ((unsigned int)entropy_src[1] << 8);
                    skip = (skip % 4096) + 64;  // at least 64, at most 4159

                    // Write skip value to OUT_BUF tail so host can verify
                    out_buf[BUF_MAX - 8] = (unsigned char)(skip & 0xff);
                    out_buf[BUF_MAX - 7] = (unsigned char)(skip >> 8);

                    // Consume 'skip' bytes from CRNG, discarding them
                    // If getrandom fails (e.g., EINTR, or CRNG not initialized),
                    // we just skip the divergence and continue — the host entropy
                    // write to /dev/urandom may still help eventual reseeding.
                    char discard_buf[64];
                    int getrandom_retries = 0;
                    while (skip > 0 && getrandom_retries < 100) {
                        size_t chunk = (skip > 64) ? 64 : skip;
                        long got = syscall(SYS_getrandom, discard_buf, chunk, 0);
                        if (got > 0) {
                            skip -= (unsigned int)got;
                            getrandom_retries = 0;  // reset on success
                        } else if (got < 0) {
                            // EINTR → retry; other errors → bail out
                            int err = errno;
                            if (err != EINTR) break;
                            getrandom_retries++;
                        } else {
                            break;  // got == 0 shouldn't happen, but bail
                        }
                    }
                }
                // else: measurement mode — skip divergence entirely,
                // all forks keep identical CRNG state from snapshot
            }

// ── Special commands ──
            if (strcmp(cmd, "!load-modules") == 0) {
                // Write diagnostic to OUT_BUF for host to read on timeout
                const char *msg1 = "got !load-modules\n";
                size_t off = 0;
                for (size_t i = 0; msg1[i] && off < BUF_MAX - 1; i++, off++)
                    out_buf[off] = (unsigned char)msg1[i];

                // Set up global OUT_BUF pointers so load_kernel_module() can
                // append per-module diagnostics via out_puts().
                g_out_buf = out_buf;
                g_out_off = off;

                // Now try loading modules
                load_nvidia_modules();

                // Read back offset from globals (updated by out_puts calls)
                off = g_out_off;

                // Read module load result file and append to OUT_BUF
                int res_fd = open("/tmp/mod_result", O_RDONLY);
                if (res_fd >= 0) {
                    char buf[64];
                    int n = read(res_fd, buf, sizeof(buf) - 1);
                    close(res_fd);
                    unlink("/tmp/mod_result");
                    if (n > 0) {
                        buf[n] = 0;
                        // Append "result: <buf>\n" to out_buf
                        const char *prefix = "result: ";
                        for (size_t i = 0; prefix[i] && off < BUF_MAX - 1; i++, off++)
                            out_buf[off] = (unsigned char)prefix[i];
                        for (size_t i = 0; buf[i] && off < BUF_MAX - 1; i++, off++)
                            out_buf[off] = (unsigned char)buf[i];
                        if (off < BUF_MAX - 1) {
                            out_buf[off] = '\n';
                            off++;
                        }
                    }
                } else {
                    // No result file — probably timed out
                    const char *timeout_msg = "result: TIMEOUT\n";
                    for (size_t i = 0; timeout_msg[i] && off < BUF_MAX - 1; i++, off++)
                        out_buf[off] = (unsigned char)timeout_msg[i];
                }
                // Append GPU device-ready status
                {
                    int test_fd = open("/dev/nvidia0", O_RDWR | O_NONBLOCK);
                    const char *status = (test_fd >= 0)
                        ? "device: READY\n"
                        : "device: NOT_READY\n";
                    if (test_fd >= 0) close(test_fd);
                    for (size_t i = 0; status[i] && off < BUF_MAX - 1; i++, off++)
                        out_buf[off] = (unsigned char)status[i];
                }
                out_buf[off] = 0;
                // Memory barrier: ensure out_buf writes are visible to host
                __asm__ volatile("mfence" ::: "memory");
            } else if (strcmp(cmd, "!load-nouveau") == 0) {
                // Write diagnostic to OUT_BUF for host to read on timeout
                const char *msg1 = "got !load-nouveau\n";
                size_t off = 0;
                for (size_t i = 0; msg1[i] && off < BUF_MAX - 1; i++, off++)
                    out_buf[off] = (unsigned char)msg1[i];

                // Set up global OUT_BUF pointers so load_kernel_module() and
                // load_nouveau_modules() can append per-module diagnostics.
                g_out_buf = out_buf;
                g_out_off = off;

                // Load nouveau + DRM dependencies
                int ret = load_nouveau_modules();

                // Read back offset from globals (updated by out_puts calls)
                off = g_out_off;

                // Write result summary to OUT_BUF
                const char *result_str = (ret == 0) ? "nouveau: OK\n" : "nouveau: FAILED\n";
                for (size_t i = 0; result_str[i] && off < BUF_MAX - 1; i++, off++)
                    out_buf[off] = (unsigned char)result_str[i];
                out_buf[off] = 0;
                // Memory barrier: ensure out_buf writes are visible to host
                __asm__ volatile("mfence" ::: "memory");
                } else {
                    // Execute code and capture output
                    // Clean up stale tinygrad lock files from previous failed init attempts
                    // (PCIDevice.__init__ can leak flock fds when PCI resource setup fails)
                    static int locks_cleaned = 0;
                    if (!locks_cleaned) {
                        system("rm -f /tmp/*.lock 2>/dev/null");
                        locks_cleaned = 1;
                    }

                    // ── DIAGNOSTIC markers visible via serial / kmsg ──
                    // Write before and after run_python so we can see where
                    // the guest hangs even when READY is never set.
                    serial_puts("CP_BEFORE_RUN_PYTHON\n");
                    kmsg_puts("CP_BEFORE_RUN_PYTHON\n");

                    // Use cmd.json configured executor, fallback to python
                    char *result = NULL;
                    if (has_cmd_json && cmd_exec_path[0] != '\0') {
                        // Direct exec mode
                        result = run_general(cmd, NULL, NULL, 0, cmd_exec_path);
                    } else if (has_cmd_json && cmd_interpreter[0] != '\0') {
                        // Interpreter mode from cmd.json
                        result = run_general(cmd, cmd_interpreter, cmd_args, cmd_arg_count, NULL);
                    } else if (python) {
                    // Execute code directly with python -c <code>.
                    // run_python uses execl() which does NOT go through a shell,
                    // so there are no quoting concerns — the code string is passed
                    // as argv[2] directly to the Python interpreter.
                    result = run_python(cmd, python);
                } else {
                    // NO PYTHON FOUND — write diagnostic
                    result = strdup("ERROR: no python interpreter found");
                }

                if (result) {
                    trim_trailing_newline(result);
                    size_t out_len = strlen(result);
                    if (out_len > BUF_MAX - 1) out_len = BUF_MAX - 1;
                    for (size_t i = 0; i < out_len; i++)
                        out_buf[i] = (unsigned char)result[i];
                    out_buf[out_len] = 0;
                    // If exec returned nothing, write a diagnostic
                    if (out_len == 0) {
                        const char *diag = "WARNING: exec returned empty output";
                        for (size_t i = 0; diag[i] && i < BUF_MAX - 1; i++)
                            out_buf[i] = (unsigned char)diag[i];
                        out_buf[strlen(diag)] = 0;
                    }
                    free(result);
                } else {
                    const char *err = "ERROR: run_general/run_python returned NULL";
                    for (size_t i = 0; err[i] && i < BUF_MAX - 1; i++)
                        out_buf[i] = (unsigned char)err[i];
                    out_buf[strlen(err)] = 0;
                }
            }
            // Signal READY: write "READY\0" so the host knows we're done.
            // IMPORTANT: This ONLY runs when a command was processed (cmd_len > 0).
            // During idle loop iterations, we do NOT set READY — otherwise the
            // host could detect a stale READY before the guest processes a new
            // command, causing run_until_ready() to return prematurely with
            // empty output (the classic "stale READY race condition").
            ready[0] = 'R';
            ready[1] = 'E';
            ready[2] = 'A';
            ready[3] = 'D';
            ready[4] = 'Y';
            ready[5] = 0;

            // Notify the host by triggering KVM_EXIT_IO via serial write
            // write(1, ...) goes through kernel serial driver → UART → KVM_EXIT_IO
            syscall(SYS_write, 1, "\n", 1);

            // Spin loop with periodic write(1, ...) to produce KVM_EXIT_IO,
            // allowing the host to detect the guest is alive and in userspace.
            // Without these exits, the pure userspace PAUSE loop never exits
            // KVM_RUN and the host can't detect progress.
            for (int i = 0; i < SPIN_ITER; i++) {
                // Every 512 iterations, write a byte to serial to produce a
                // KVM_EXIT_IO. This lets the host see the guest is running.
                if ((i & 0x1FF) == 0) {
                    syscall(SYS_write, 1, "\n", 1);
                }
                __asm__ volatile("pause" ::: "memory");
            }
            continue;  // back to while(1) top — don't fall through to idle yield
        }  // end if (cmd_len > 0)

        // ── No command pending: yield without setting READY ──
        // Produce a KVM_EXIT_IO via serial write so the host can detect the
        // guest is alive and inject a new command. Unlike the command-processing
        // path above, we do NOT write "READY\0" — the host checks the READY
        // flag on every KVM_RUN return and will see it's still 0, correctly
        // indicating that no command was processed yet.
        syscall(SYS_write, 1, "\n", 1);
    }

    return 0;
}
