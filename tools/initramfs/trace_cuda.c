#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>

extern int mbind(void *, unsigned long, int, const unsigned long *, unsigned long, unsigned);
extern int set_mempolicy(int, const unsigned long *, unsigned long);
extern int get_mempolicy(int *, unsigned long *, unsigned long, void *, unsigned long);
extern int move_pages(int, unsigned long, void *const *, const int *, int *, int);

static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static int (*real_ioctl)(int, unsigned long, void *) = NULL;
static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
static int (*real_munmap)(void *, size_t) = NULL;
static int (*real_prctl)(int, unsigned long, unsigned long, unsigned long, unsigned long) = NULL;
static int (*real_madvise)(void *, size_t, int) = NULL;
static int (*real_mprotect)(void *, size_t, int) = NULL;
static long (*real_syscall)(long, ...) = NULL;
static int (*real_read)(int, void *, size_t) = NULL;
static int (*real_write)(int, const void *, size_t) = NULL;
static ssize_t (*real_pread)(int, void *, size_t, off_t) = NULL;
static ssize_t (*real_pread64)(int, void *, size_t, off_t) = NULL;
static int (*real_close)(int) = NULL;
static int (*real_poll)(struct pollfd *, nfds_t, int) = NULL;
static int (*real_socket)(int, int, int) = NULL;
static int (*real_eventfd)(unsigned int, int) = NULL;
static int (*real_memfd_create)(const char *, unsigned int) = NULL;
static int (*real_mlock)(const void *, size_t) = NULL;
static int (*real_mlock2)(const void *, size_t, int) = NULL;
static int (*real_mlockall)(int) = NULL;
static void *(*real_mremap)(void *, size_t, size_t, int, ...) = NULL;
static int (*real_msync)(void *, size_t, int) = NULL;
static int (*real_membarrier)(int, int) = NULL;
static int (*real_mbind)(void *, unsigned long, int, const unsigned long *, unsigned long, unsigned) = NULL;
static int (*real_set_mempolicy)(int, const unsigned long *, unsigned long) = NULL;
static int (*real_get_mempolicy)(int *, unsigned long *, unsigned long, void *, unsigned long) = NULL;
static int (*real_move_pages)(int, unsigned long, void *const *, const int *, int *, int) = NULL;
static int (*real_setpriority)(__priority_which_t, id_t, int) = NULL;
static int (*real_sched_setaffinity)(pid_t, size_t, const cpu_set_t *) = NULL;
static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = NULL;

static int log_fd = -1;
/* Trace output goes ONLY to /tmp/utrace.log (an O_APPEND file: a write can
 * never block). The stdout-pipe relay is DROPPED: the UMD closes and
 * reuses its stdout fds mid-run (observed: it re-opens the drain pipe as
 * its own fd 4), so a trace write to the pipe fills it once the drain
 * stops and blocks the UMD inside our wrapper (observed deadlock: trace
 * threads stuck in anon_pipe_write on the drain pipe, sampler shows
 * write(4) from every blocked thread). init's flusher relays the log. */
static void w(const char *s, int len) {
  if (len > 0) {
    if (log_fd < 0) log_fd = real_open("/tmp/utrace.log", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (log_fd >= 0) syscall(SYS_write, log_fd, s, len);
  }
}
static void ws(const char *s) { if (s) w(s, strlen(s)); }

#define TRACE(...) do { char _b[256]; int _n = snprintf(_b, 256, __VA_ARGS__); if (_n > 0 && _n < 256) w(_b, _n); } while(0)

static int mem_fd = -1;
static void dump_mem(unsigned long addr, int len) {
  unsigned char buf[64];
  if (!addr || addr < 0x1000) { ws(" null"); return; }
  if (len > 64) len = 64;
  if (mem_fd < 0) mem_fd = open("/proc/self/mem", O_RDONLY);
  if (mem_fd < 0) { ws(" memfail"); return; }
  ssize_t n = pread(mem_fd, buf, len, (off_t)addr);
  if (n != len) { TRACE(" unmapped@0x%lx", addr); return; }
  for (int i = 0; i < len; i++) TRACE(" %02x", buf[i]);
}

static void trace_ioctl(int fd, unsigned long request, void *arg, int is_pre) {
  if (!arg) return;
  unsigned int nr = _IOC_NR(request);
  unsigned int sz = _IOC_SIZE(request);
  if (nr == 43 && sz == 48) {
    if (is_pre) {
      TRACE("PRE48:");
      dump_mem((unsigned long)arg, 48);
      unsigned long params = *(unsigned long *)((char *)arg + 16);
      TRACE("\nPARAMS-IN @0x%lx:", params);
      dump_mem(params, 64);
      ws("\n");
    } else {
      TRACE("REP48:");
      dump_mem((unsigned long)arg, 48);
      unsigned long params = *(unsigned long *)((char *)arg + 16);
      TRACE("\nPARAMS-OUT @0x%lx:", params);
      dump_mem(params, 64);
      ws("\n");
    }
  } else if (nr == 42 && sz == 32) {
    unsigned long p = *(unsigned long *)((char *)arg + 16);
    unsigned int psz = *(unsigned int *)((char *)arg + 24);
    unsigned int cmdc = *(unsigned int *)((char *)arg + 8);
    if (p && psz > 0 && psz <= 16384) {
      TRACE("%s cmd=0x%08x hObj=0x%08x psz=%u:", is_pre ? "CTRL-IN" : "CTRL-OUT",
            cmdc, *(unsigned int *)((char *)arg + 4), psz);
      dump_mem(p, psz > 64 ? 64 : (int)psz);
      ws("\n");
    }
  } else if (nr == 78 && sz == 56) {
    TRACE("MAP-IN:");
    dump_mem((unsigned long)arg, 56);
    ws("\n");
  }
}

__attribute__((constructor))
static void trace_init(void) {
  real_syscall = dlsym(RTLD_NEXT, "syscall");
  real_open = dlsym(RTLD_NEXT, "open");
  real_openat = dlsym(RTLD_NEXT, "openat");
  real_ioctl = dlsym(RTLD_NEXT, "ioctl");
  real_mmap = dlsym(RTLD_NEXT, "mmap");
  real_munmap = dlsym(RTLD_NEXT, "munmap");
  real_prctl = dlsym(RTLD_NEXT, "prctl");
  real_madvise = dlsym(RTLD_NEXT, "madvise");
  real_mprotect = dlsym(RTLD_NEXT, "mprotect");
  real_read = dlsym(RTLD_NEXT, "read");
  real_write = dlsym(RTLD_NEXT, "write");
  real_pread = dlsym(RTLD_NEXT, "pread");
  real_pread64 = dlsym(RTLD_NEXT, "pread64");
  real_close = dlsym(RTLD_NEXT, "close");
  real_poll = dlsym(RTLD_NEXT, "poll");
  real_socket = dlsym(RTLD_NEXT, "socket");
  real_eventfd = dlsym(RTLD_NEXT, "eventfd");
  real_memfd_create = dlsym(RTLD_NEXT, "memfd_create");
  real_mlock = dlsym(RTLD_NEXT, "mlock");
  real_mlock2 = dlsym(RTLD_NEXT, "mlock2");
  real_mlockall = dlsym(RTLD_NEXT, "mlockall");
  real_mremap = dlsym(RTLD_NEXT, "mremap");
  real_msync = dlsym(RTLD_NEXT, "msync");
  real_membarrier = dlsym(RTLD_NEXT, "membarrier");
  real_mbind = dlsym(RTLD_NEXT, "mbind");
  real_set_mempolicy = dlsym(RTLD_NEXT, "set_mempolicy");
  real_get_mempolicy = dlsym(RTLD_NEXT, "get_mempolicy");
  real_move_pages = dlsym(RTLD_NEXT, "move_pages");
  real_setpriority = dlsym(RTLD_NEXT, "setpriority");
  real_sched_setaffinity = dlsym(RTLD_NEXT, "sched_setaffinity");
  real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
  if (!real_ioctl) real_ioctl = dlsym(RTLD_NEXT, "__ioctl");
  TRACE("TINIT pid=%d\n", getpid());
}

int open(const char *pathname, int flags, ...) {
  if (!real_open) return -1;
  int fd = real_open(pathname, flags);
  TRACE("TOPN pid=%d fd=%d p=%s fl=0x%x err=%d\n", getpid(), fd, pathname ? pathname : "?", (unsigned)flags, errno);
  return fd;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
  if (!real_openat) return -1;
  int fd = real_openat(dirfd, pathname, flags);
  TRACE("TOPN pid=%d fd=%d dfd=%d p=%s fl=0x%x err=%d\n", getpid(), fd, dirfd, pathname ? pathname : "?", (unsigned)flags, errno);
  return fd;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
  if (!real_mmap) return MAP_FAILED;
  void *r = real_mmap(addr, len, prot, flags, fd, off);
  TRACE("mmap(0x%lx, %zu, prot=0x%x, flags=0x%x, fd=%d, off=0x%lx) = 0x%lx errno=%d\n",
        (unsigned long)addr, len, prot, flags, fd, (long)off, (unsigned long)r, errno);
  return r;
}

int munmap(void *addr, size_t len) {
  if (!real_munmap) return -1;
  TRACE("munmap(0x%lx, %zu) = 0 errno=%d\n", (unsigned long)addr, len, errno);
  return real_munmap(addr, len);
}

int ioctl(int fd, unsigned long request, ...) {
  if (!real_ioctl) return -1;
  void *arg; va_list ap; va_start(ap, request); arg = va_arg(ap, void *); va_end(ap);
  char link[256]; char fdpath[64];
  snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(fdpath, link, 255);
  int is_nv = 0;
  if (n > 0) { link[n] = 0; is_nv = strstr(link, "nvidia") != NULL; }
  if (is_nv) {
    unsigned int nr = _IOC_NR(request);
    unsigned int sz = _IOC_SIZE(request);
    TRACE("TIOCTL pid=%d fd=%d p=%s r=0x%lx nr=%u sz=%u\n", getpid(), fd, link, request, nr, sz);
    trace_ioctl(fd, request, arg, 1);
  } else {
    TRACE("IOTC2 pid=%d fd=%d r=0x%lx nr=%lu sz=%lu\n", getpid(), fd, request,
          (unsigned long)_IOC_NR(request), (unsigned long)_IOC_SIZE(request));
  }
  int ret = real_ioctl(fd, request, arg);
  if (is_nv) {
    trace_ioctl(fd, request, arg, 0);
    TRACE("RET ret=%d err=%d\n", ret, errno);
  } else {
    TRACE("RET2 ret=%d err=%d\n", ret, errno);
  }
  return ret;
}

int prctl(int op, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5) {
  int ret = real_prctl(op, a2, a3, a4, a5);
  TRACE("prctl(op=0x%x, a2=0x%lx, a3=0x%lx, a4=0x%lx, a5=0x%lx) = %d errno=%d\n",
        op, a2, a3, a4, a5, ret, errno);
  return ret;
}

int madvise(void *addr, size_t len, int advice) {
  int ret = real_madvise(addr, len, advice);
  TRACE("madvise(0x%lx, %zu, 0x%x) = %d errno=%d\n",
        (unsigned long)addr, len, (unsigned)advice, ret, errno);
  return ret;
}

int mprotect(void *addr, size_t len, int prot) {
  int ret = real_mprotect(addr, len, prot);
  TRACE("mprotect(0x%lx, %zu, 0x%x) = %d errno=%d\n",
        (unsigned long)addr, len, (unsigned)prot, ret, errno);
  return ret;
}

static __thread int in_sys_trace = 0;

long syscall(long number, ...) {
  if (!real_syscall) return -1;
  va_list ap; va_start(ap, number);
  long a1 = va_arg(ap, long), a2 = va_arg(ap, long), a3 = va_arg(ap, long),
       a4 = va_arg(ap, long), a5 = va_arg(ap, long), a6 = va_arg(ap, long);
  va_end(ap);
  if (number == 1 && a1 != log_fd && a1 != mem_fd && a1 >= 0) {
    static __thread int swc = 0;
    swc++;
    if ((swc % 128) == 0 || swc <= 32) {
      TRACE("SW fd=%ld n=%ld:", a1, a3);
      const unsigned char *b = (const unsigned char *)a2;
      int i, n = (a3 < 16) ? (int)a3 : 16;
      for (i = 0; i < n && b; i++) TRACE(" %02x", b[i]);
      ws("\n");
    }
  }
  long r = real_syscall(number, a1, a2, a3, a4, a5, a6);
  if (!in_sys_trace && (r < 0 || number != 1)) {
    in_sys_trace = 1;
    TRACE("SYSCL nr=%ld a1=0x%lx a2=0x%lx a3=0x%lx a4=0x%lx = 0x%lx err=%d\n",
          number, a1, a2, a3, a4, r, errno);
    in_sys_trace = 0;
  }
  return r;
}

ssize_t read(int fd, void *buf, size_t count) {
  if (!real_read) return -1;
  ssize_t r = real_read(fd, buf, count);
  if (r < 0) TRACE("READ! fd=%d err=%d\n", fd, errno);
  else if (fd != log_fd && fd != log_fd && fd != mem_fd) {
    static __thread int rcnt = 0;
    char lp[64], lr[128];
    lr[0] = 0;
    snprintf(lp, sizeof(lp), "/proc/self/fd/%d", fd);
    ssize_t ln = readlink(lp, lr, sizeof(lr) - 1);
    if (ln > 0) lr[ln] = 0;
    if (strstr(lr, "pipe")) {
      rcnt++;
      if ((rcnt % 256) == 0 || rcnt <= 8) {
        TRACE("PR fd=%d (%s) n=%zd:", fd, lr, r);
        const unsigned char *b = buf;
        int i, n = r < 16 ? (int)r : 16;
        for (i = 0; i < n; i++) TRACE(" %02x", b[i]);
        ws("\n");
      }
    }
  }
  return r;
}

ssize_t write(int fd, const void *buf, size_t count) {
  if (!real_write) return -1;
  if (fd != log_fd && fd != log_fd && fd != mem_fd) {
    static __thread int wcnt = 0;
    char lp[64], lr[128];
    lr[0] = 0;
    snprintf(lp, sizeof(lp), "/proc/self/fd/%d", fd);
    ssize_t ln = readlink(lp, lr, sizeof(lr) - 1);
    if (ln > 0) lr[ln] = 0;
    if (strstr(lr, "pipe")) {
      wcnt++;
      if ((wcnt % 256) == 0 || wcnt <= 16) {
        TRACE("PW fd=%d (%s) n=%zu:", fd, lr, count);
        const unsigned char *b = buf;
        int i, n = count < 16 ? (int)count : 16;
        for (i = 0; i < n; i++) TRACE(" %02x", b[i]);
        ws("\n");
      }
    }
  }
  ssize_t r = real_write(fd, buf, count);
  if (r < 0) TRACE("WRITE! fd=%d err=%d\n", fd, errno);
  return r;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
  if (!real_pread) return -1;
  ssize_t r = real_pread(fd, buf, count, offset);
  if (r < 0) TRACE("PREAD! fd=%d err=%d\n", fd, errno);
  return r;
}

ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
  if (!real_pread64) return -1;
  ssize_t r = real_pread64(fd, buf, count, offset);
  if (r < 0) TRACE("PREAD! fd=%d err=%d\n", fd, errno);
  return r;
}

int close(int fd) {
  if (!real_close) return -1;
  int r = real_close(fd);
  if (r < 0) TRACE("CLOSE! fd=%d err=%d\n", fd, errno);
  return r;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  if (!real_poll) return -1;
  TRACE("POLL-IN pid=%d(%.64s) nfds=%zu t=%d\n", getpid(), fds ? "?" : "-", nfds, timeout);
  for (nfds_t i = 0; i < nfds; i++) {
    TRACE("  pfd[%zu]=fd%d ev=0x%x\n", i, fds[i].fd, fds[i].events);
    if (fds[i].fd >= 0) {
      char lp[64], lr[128];
      snprintf(lp, sizeof(lp), "/proc/self/fd/%d", fds[i].fd);
      ssize_t ln = readlink(lp, lr, sizeof(lr) - 1);
      if (ln > 0) { lr[ln] = 0; TRACE("    = %s\n", lr); }
      else TRACE("    = ?\n");
    }
  }
  int r = real_poll(fds, nfds, timeout);
  TRACE("POLL-OUT pid=%d = %d err=%d\n", getpid(), r, errno);
  for (nfds_t i = 0; i < nfds; i++) TRACE("  re[%zu]=fd%d rev=0x%x\n", i, fds[i].fd, fds[i].revents);
  return r;
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo, const sigset_t *sigmask) {
  static int (*real_ppoll)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *) = NULL;
  if (!real_ppoll) real_ppoll = dlsym(RTLD_NEXT, "ppoll");
  if (!real_ppoll) return -1;
  TRACE("PPOLL-IN(%.64s) nfds=%zu\n", fds ? "?" : "-", nfds);
  for (nfds_t i = 0; i < nfds; i++) TRACE("  pfd[%zu]=fd%d ev=0x%x\n", i, fds[i].fd, fds[i].events);
  int r = real_ppoll(fds, nfds, tmo, sigmask);
  TRACE("PPOLL-OUT = %d err=%d\n", r, errno);
  for (nfds_t i = 0; i < nfds; i++) TRACE("  re[%zu]=fd%d rev=0x%x\n", i, fds[i].fd, fds[i].revents);
  return r;
}

int select(int nfds, fd_set *rd, fd_set *wr, fd_set *e, struct timeval *tv) {
  static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = NULL;
  if (!real_select) real_select = dlsym(RTLD_NEXT, "select");
  if (!real_select) return -1;
  int r = real_select(nfds, rd, wr, e, tv);
  if (r != 0) TRACE("SELECT nfds=%d = %d err=%d\n", nfds, r, errno);
  return r;
}

int pselect6(int nfds, fd_set *rd, fd_set *wr, fd_set *e, const struct timespec *tmo, const void *sig) {
  static int (*real_pselect6)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const void *) = NULL;
  if (!real_pselect6) real_pselect6 = dlsym(RTLD_NEXT, "pselect6");
  if (!real_pselect6) real_pselect6 = dlsym(RTLD_NEXT, "pselect");
  if (!real_pselect6) return -1;
  int r = real_pselect6(nfds, rd, wr, e, tmo, sig);
  if (r != 0) TRACE("PSELECT6 nfds=%d = %d err=%d\n", nfds, r, errno);
  return r;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
  static int (*real_nanosleep)(const struct timespec *, struct timespec *) = NULL;
  if (!real_nanosleep) real_nanosleep = dlsym(RTLD_NEXT, "nanosleep");
  if (!real_nanosleep) return -1;
  int r = real_nanosleep(req, rem);
  if (req) TRACE("NANOSLEEP %ld.%09lds\n", req->tv_sec, req->tv_nsec);
  return r;
}

int socket(int domain, int type, int protocol) {
  if (!real_socket) return -1;
  int r = real_socket(domain, type, protocol);
  TRACE("socket(domain=%d, type=0x%x, proto=%d) = %d err=%d\n", domain, type, protocol, r, errno);
  return r;
}

int eventfd(unsigned int initval, int flags) {
  if (!real_eventfd) return -1;
  int r = real_eventfd(initval, flags);
  TRACE("eventfd(0x%x, 0x%x) = %d err=%d\n", initval, flags, r, errno);
  return r;
}

int pipe(int pfd[2]) {
  static int (*real_pipe)(int[2]) = NULL;
  if (!real_pipe) real_pipe = dlsym(RTLD_NEXT, "pipe");
  if (!real_pipe) return -1;
  int r = real_pipe(pfd);
  TRACE("pipe() = %d -> [%d,%d] err=%d\n", r, r == 0 ? pfd[0] : -1, r == 0 ? pfd[1] : -1, errno);
  return r;
}

int pipe2(int pfd[2], int flags) {
  static int (*real_pipe2)(int[2], int) = NULL;
  if (!real_pipe2) real_pipe2 = dlsym(RTLD_NEXT, "pipe2");
  if (!real_pipe2) return -1;
  int r = real_pipe2(pfd, flags);
  TRACE("pipe2(0x%x) = %d -> [%d,%d] err=%d\n", flags, r, r == 0 ? pfd[0] : -1, r == 0 ? pfd[1] : -1, errno);
  return r;
}

int memfd_create(const char *name, unsigned int flags) {
  if (!real_memfd_create) return -1;
  int r = real_memfd_create(name, flags);
  TRACE("memfd_create(%s, 0x%x) = %d err=%d\n", name ? name : "?", flags, r, errno);
  return r;
}

int mlock(const void *addr, size_t len) {
  if (!real_mlock) return -1;
  int r = real_mlock(addr, len);
  TRACE("mlock(0x%lx, %zu) = %d err=%d\n", (unsigned long)addr, len, r, errno);
  return r;
}

int mlock2(const void *addr, size_t len, unsigned int flags) {
  if (!real_mlock2) return -1;
  int r = real_mlock2(addr, len, flags);
  TRACE("mlock2(0x%lx, %zu, 0x%x) = %d err=%d\n", (unsigned long)addr, len, flags, r, errno);
  return r;
}

int mlockall(int flags) {
  if (!real_mlockall) return -1;
  int r = real_mlockall(flags);
  TRACE("mlockall(0x%x) = %d err=%d\n", flags, r, errno);
  return r;
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...) {
  if (!real_mremap) return (void *)-1;
  void *r = real_mremap(old_address, old_size, new_size, flags);
  TRACE("mremap(0x%lx, %zu, %zu, 0x%x) = 0x%lx err=%d\n",
        (unsigned long)old_address, old_size, new_size, flags, (unsigned long)r, errno);
  return r;
}

int msync(void *addr, size_t len, int flags) {
  if (!real_msync) return -1;
  int r = real_msync(addr, len, flags);
  TRACE("msync(0x%lx, %zu, 0x%x) = %d err=%d\n", (unsigned long)addr, len, flags, r, errno);
  return r;
}

int membarrier(int cmd, int flags) {
  if (!real_membarrier) return -1;
  int r = real_membarrier(cmd, flags);
  TRACE("membarrier(cmd=%d, flags=%d) = %d err=%d\n", cmd, flags, r, errno);
  return r;
}

int mbind(void *start, unsigned long len, int mode, const unsigned long *nodemask, unsigned long maxnode, unsigned flags) {
  if (!real_mbind) return -1;
  int r = real_mbind(start, len, mode, nodemask, maxnode, flags);
  TRACE("mbind(0x%lx, %lu, mode=%d, mask=%p, maxnode=%lu, fl=0x%x) = %d err=%d\n",
        (unsigned long)start, len, mode, (void *)nodemask, maxnode, flags, r, errno);
  return r;
}

int set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode) {
  if (!real_set_mempolicy) return -1;
  int r = real_set_mempolicy(mode, nodemask, maxnode);
  TRACE("set_mempolicy(mode=%d, mask=%p, maxnode=%lu) = %d err=%d\n",
        mode, (void *)nodemask, maxnode, r, errno);
  return r;
}

int get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags) {
  if (!real_get_mempolicy) return -1;
  int r = real_get_mempolicy(mode, nodemask, maxnode, addr, flags);
  TRACE("get_mempolicy(mode=%p, mask=%p, maxnode=%lu, addr=%p, fl=0x%lx) = %d err=%d\n",
        (void *)mode, (void *)nodemask, maxnode, addr, flags, r, errno);
  return r;
}

int move_pages(int pid, unsigned long count, void *const *pages, const int *nodes, int *status, int flags) {
  if (!real_move_pages) return -1;
  int r = real_move_pages(pid, count, pages, nodes, status, flags);
  TRACE("move_pages(pid=%d, n=%lu, fl=%d) = %d err=%d\n", pid, count, flags, r, errno);
  return r;
}

int setpriority(__priority_which_t which, id_t who, int prio) {
  if (!real_setpriority) return -1;
  int r = real_setpriority(which, who, prio);
  TRACE("setpriority(which=%d, who=%u, prio=%d) = %d err=%d\n", which, who, prio, r, errno);
  return r;
}

int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *cpuset) {
  if (!real_sched_setaffinity) return -1;
  int r = real_sched_setaffinity(pid, cpusetsize, cpuset);
  TRACE("sched_setaffinity(pid=%d, sz=%zu) = %d err=%d\n", pid, cpusetsize, r, errno);
  return r;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
  if (!real_pthread_create) return -1;
  int r = real_pthread_create(thread, attr, start_routine, arg);
  TRACE("pthread_create = %d err=%d\n", r, errno);
  return r;
}
