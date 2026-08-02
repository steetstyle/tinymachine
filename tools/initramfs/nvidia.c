// SPDX-License-Identifier: GPL-2.0-only
/* tinymachine stub NVIDIA driver — intercepts RMAPI ioctls */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/eventfd.h>
#include <linux/unaligned.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tinymachine");
MODULE_DESCRIPTION("Fake NVIDIA driver stub for QEMU VFIO GPU");
MODULE_VERSION("595.71.05");

/* NV2080_CTRL_CMD_GR_GET_INFO reply captured from real 595.84 driver
 * (host GRINFO dump, 59 entries x 8 bytes + slack). */
#include "shm_2mb_content.h"
static const __u8 host_gr_get_info[1024] = {
    0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x02,0x00,0x00,
    0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x10,0x00,0x00,0x00,
    0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
    0x08,0x00,0x00,0x00,0x3a,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x1d,0x00,0x00,0x00,
    0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x0c,0x00,0x00,0x00,0x09,0x08,0x00,0x00,0x0d,0x00,0x00,0x00,0x30,0x00,0x00,0x00,
    0x0e,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0xa0,0x00,0x00,0x00,
    0x10,0x00,0x00,0x00,0xa0,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x20,0x00,0x00,0x00,
    0x12,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x14,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x15,0x00,0x00,0x00,0x06,0x00,0x00,0x00,
    0x16,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x17,0x00,0x00,0x00,0x06,0x00,0x00,0x00,
    0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x19,0x00,0x00,0x00,0x08,0x00,0x00,0x00,
    0x1a,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x1b,0x00,0x00,0x00,0x06,0x00,0x00,0x00,
    0x1c,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x1d,0x00,0x00,0x00,0x00,0x1d,0x00,0x00,
    0x1e,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x1f,0x00,0x00,0x00,0x08,0x00,0x00,0x00,
    0x20,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x21,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
    0x22,0x00,0x00,0x00,0x3a,0x00,0x00,0x00,0x23,0x00,0x00,0x00,0xe8,0x00,0x00,0x00,
    0x24,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x25,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,
    0x26,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x27,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
    0x28,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x29,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
    0x2a,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x2b,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
    0x2c,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x2d,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
    0x2e,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x2f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x32,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x34,0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x35,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
    0x36,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x37,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
    0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x39,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x3a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xb8,0x2a,0xe7,0xe9,0xfd,0x7f,0x00,0x00,0xc0,0x94,0xde,0x1f,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x27,0xe7,0xe9,0xfd,0x7f,0x00,0x00,
};
#define NV_IOCTL_MAGIC 'F'
#define NV_IOCTL_BASE       200
#define NV_ESC_CARD_INFO_NR             (NV_IOCTL_BASE + 0)  /* 200 */
#define NV_ESC_REGISTER_FD_NR           (NV_IOCTL_BASE + 1)  /* 201 */
#define NV_ESC_ALLOC_OS_EVENT_NR        (NV_IOCTL_BASE + 6)  /* 206 */
#define NV_ESC_FREE_OS_EVENT_NR         (NV_IOCTL_BASE + 7)  /* 207 */
#define NV_ESC_STATUS_CODE_NR           (NV_IOCTL_BASE + 9)  /* 209 */
#define NV_ESC_CHECK_VERSION_STR_NR     (NV_IOCTL_BASE + 10) /* 210 */
#define NV_ESC_IOCTL_XFER_CMD_NR        (NV_IOCTL_BASE + 11) /* 211 */
#define NV_ESC_ATTACH_GPUS_TO_FD_NR     (NV_IOCTL_BASE + 12) /* 212 */
#define NV_ESC_QUERY_DEVICE_INTR_NR     (NV_IOCTL_BASE + 13) /* 213 */
#define NV_ESC_SYS_PARAMS_NR            (NV_IOCTL_BASE + 14) /* 214 */
#define NV_ESC_EXPORT_TO_DMABUF_FD_NR   (NV_IOCTL_BASE + 17) /* 217 */
#define NV_ESC_WAIT_OPEN_COMPLETE_NR    (NV_IOCTL_BASE + 18) /* 218 */
#define NV_ESC_NUMA_INFO_NR             (NV_IOCTL_BASE + 15) /* 215 */
#define NV_ESC_SET_NUMA_STATUS_NR       (NV_IOCTL_BASE + 16) /* 216 */

#define NV_ESC_REGISTER_FD        _IOWR(NV_IOCTL_MAGIC, NV_ESC_REGISTER_FD_NR, int)
#define NV_ESC_CARD_INFO          _IOWR(NV_IOCTL_MAGIC, NV_ESC_CARD_INFO_NR, struct nv_ioctl_card_info)
#define NV_ESC_CHECK_VERSION_STR  _IOWR(NV_IOCTL_MAGIC, NV_ESC_CHECK_VERSION_STR_NR, int)
#define NV_ESC_SYS_PARAMS         _IOWR(NV_IOCTL_MAGIC, NV_ESC_SYS_PARAMS_NR, __u64)
#define NV_ESC_ATTACH_GPUS_TO_FD  _IOWR(NV_IOCTL_MAGIC, NV_ESC_ATTACH_GPUS_TO_FD_NR, __u32)
#define NV_ESC_IOCTL_XFER_CMD     _IOWR(NV_IOCTL_MAGIC, NV_ESC_IOCTL_XFER_CMD_NR, struct nv_ioctl_xfer)
#define NV_ESC_WAIT_OPEN_COMPLETE _IOWR(NV_IOCTL_MAGIC, NV_ESC_WAIT_OPEN_COMPLETE_NR, struct nv_ioctl_wait_open_complete)
/* RM allocation/control commands (NVIF-style, nr = 0x80-0x87) */
#define NV_ESC_RM_ALLOC_NR        0x80
#define NV_ESC_RM_ALLOC_OBJECT_NR 0x81
#define NV_ESC_RM_CONTROL_NR      0x82
#define NV_ESC_RM_FREE_NR         0x83
#define NV_ESC_RM_MAP_MEMORY_NR   0x84
static const __u8 host_ctl_4096[4096] = {
  0x26,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x01,0x00,0xf2,0xff,0x00,
  0x26,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x42,0xe6,0x02,0x00,0x00,0x00,
  0x00,0x00,0x14,0xe6,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,
};
static const __u8 host_ctl_65536[65536] = {
  0x61,0xc5,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x54,0x2a,0xb7,0xa5,0x98,0xc7,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

#define NV_ESC_RM_MAP_MEMORY_DMA_NR 0x85
#define NV_ESC_RM_UNMAP_MEMORY_NR 0x86
#define NV_ESC_RM_DUP_OBJECT_NR   0x87

/* ── ioctl structs (lifted from nvidia‑linux‑open) ── */

/* Must match the real nv-ioctl.h layout (natural alignment) */
struct nv_pci_info {
  __u32 domain;       /* 4 bytes */
  __u8  bus;          /* 1 byte */
  __u8  slot;         /* 1 byte */
  __u8  function;     /* 1 byte */
  __u16 vendor_id;    /* 2 bytes */
  __u16 device_id;    /* 2 bytes */
}; /* naturally aligned: 4+1+1+1+1pad+2+2 = 12 bytes */

struct nv_ioctl_card_info {
  __u32            valid;          /* NvBool = 4 bytes */
  struct nv_pci_info pci_info;     /* 12 bytes (naturally aligned) */
  __u32            gpu_id;         /* 4 bytes */
  __u16            interrupt_line; /* 2 bytes */
  __u64            reg_address;    /* 8 bytes */
  __u64            reg_size;       /* 8 bytes */
  __u64            fb_address;     /* 8 bytes */
  __u64            fb_size;        /* 8 bytes */
  __u32            minor_number;   /* 4 bytes */
  __u8             dev_name[10];   /* 10 bytes */
}; /* 4+12+4+2+2pad+8+8+8+8+4+10+2pad = 72 bytes */

struct nv_os21_params {
  __u32 hRoot;
  __u32 hObjectParent;
  __u32 hObjectNew;
  __u32 hClass;
  __u64 pAllocParms;
  __u32 paramsSize;
  __u32 status;
};

struct stub_evfd {
  __u32 hParent;
  int fd;
};

/* Per-open-file RM event state (mirrors nv_linux_file_private_t's
 * dataless_event_pending + event_data list). */
struct stub_file_event {
  wait_queue_head_t wq;
  bool pending;
  bool ev_queued;
  __u32 ev_hObject;
  __u32 ev_notifyIndex;
  __u32 ev_info32;
  __u16 ev_info16;
};

struct nv_os54_params {
  __u32 hClient;
  __u32 hObject;
  __u32 cmd;
  __u32 flags;
  __u64 params;
  __u32 paramsSize;
  __u32 status;
};

struct nv_os33_params_with_fd {
  __u32 hClient;
  __u32 hObject;
  __u32 status;
  __u32 pad;
  __u64 offset;
  __u64 length;
  __s64 fd;
};

/* NVIDIA RM‑control structs (reverse‑engineered) */

struct nv_ctrl_gpu_get_id_info_v2 {
  __u32 gpuId;
  __u32 gpuFlags;
  __u32 deviceInstance;
  __u32 subDeviceInstance;
  __u32 sliStatus;
  __u32 boardId;
  __u32 gpuInstance;
  __s32 numaId;
};

struct nv_ctrl_gpu_get_classlist_v2 {
  __u32 numClasses;
  __u32 classList[100];
};

struct nv_ctrl_gpu_get_classlist_v1 {
  __u32 numClasses;
  __u64 classList;
};

struct nv_ctrl_system_get_build_version_v2 {
  __u8  driverVersionBuffer[256];
  __u8  versionBuffer[256];
  __u8  driverBranch[256];
  __u8  titleBuffer[256];
  __u32 changelistNumber;
  __u32 officialChangelistNumber;
};

struct nv_ctrl_gr_get_info {
  __u32 grInfoListSize;
  __u64 grInfoList;
  __u32 status;
};

/* ── handle management ── */

struct rm_handle {
  struct list_head list;
  __u32 handle;
  __u32 parent;
  __u32 hClass;
  void *mem;          /* allocated kernel memory for this handle (mmap‑able) */
  size_t mem_size;
};

static struct class *nvidia_class;
static dev_t nvidia_dev;
static struct cdev nvidia_cdev;
static struct proc_dir_entry *nvidia_proc_dir;
static struct proc_dir_entry *nvidia_proc_gpus;
static struct proc_dir_entry *nvidia_proc_params;
static struct proc_dir_entry *nvidia_proc_caps;
static struct proc_dir_entry *nvidia_proc_caps_mig;

static int nvidia_proc_params_show(struct seq_file *m, void *v) {
  seq_printf(m, "NVreg_EnableGpuFirmware: 0\n");
  seq_printf(m, "NVreg_InitializeSystemMemoryAllocations: 1\n");
  seq_printf(m, "NVreg_EnablePCIeGen3: 1\n");
  seq_printf(m, "NVreg_EnableMSI: 1\n");
  seq_printf(m, "NVreg_IgnoreMMIOCheck: 1\n");
  seq_printf(m, "NVreg_CheckPCIConfig: 0\n");
  seq_printf(m, "NVreg_ResmanDebugLevel: 0\n");
  seq_printf(m, "NVreg_Mobile: 0\n");
  seq_printf(m, "NVreg_EnableStreamMemOPs: 1\n");
  seq_printf(m, "NVreg_UsePageTableDirectly: 1\n");
  seq_printf(m, "NVreg_RmMsg: 0\n");
  seq_printf(m, "NVreg_RegistryDwords: \n");
  seq_printf(m, "NVreg_UpdateMemoryType: 0\n");
  seq_printf(m, "NVreg_DmaPoolSize: 256\n");
  seq_printf(m, "NVreg_GPUTestFence: 0\n");
  seq_printf(m, "NVreg_EnableUserClientGpuBlacklist: 0\n");
  seq_printf(m, "NVreg_EnableS0ixPowerManagement: 0\n");
  seq_printf(m, "NVreg_S0ixPowerManagementTimer: 200\n");
  seq_printf(m, "NVreg_TCEBypassMode: 0\n");
  seq_printf(m, "NVreg_UseIbmm: 0\n");
  seq_printf(m, "NVreg_MemPoolSize: 0\n");
  seq_printf(m, "NVreg_EnableAPE: 1\n");
  seq_printf(m, "NVreg_EnableGpuFirmwareVsec: 0\n");
  return 0;
}
static int nvidia_proc_params_open(struct inode *inode, struct file *file) {
  return single_open(file, nvidia_proc_params_show, NULL);
}
static int nvidia_proc_version_show(struct seq_file *m, void *v) {
  seq_printf(m, "NVRM version: NVIDIA UNIX x86_64 Kernel Module  595.84\n");
  return 0;
}
static int nvidia_proc_version_open(struct inode *inode, struct file *file) {
  return single_open(file, nvidia_proc_version_show, NULL);
}
static const struct proc_ops nvidia_proc_params_fops = {
  .proc_open    = nvidia_proc_params_open,
  .proc_read    = seq_read,
  .proc_lseek   = seq_lseek,
  .proc_release = single_release,
};
static const struct proc_ops nvidia_proc_version_fops = {
  .proc_open    = nvidia_proc_version_open,
  .proc_read    = seq_read,
  .proc_lseek   = seq_lseek,
  .proc_release = single_release,
};

static LIST_HEAD(rm_handles);
static DEFINE_MUTEX(rm_mutex);
static __u32 next_rm_handle = 1;
static __u32 root_handle;

/* NV50A0 (VMM) windowed write-back state: the real kernel bumps a cursor
 * down from the top of the VA space (start = limit + 1), decrementing it
 * by spatial-X on every windowed alloc; the cursor is keyed by limit
 * (2^40-1 and 2^46-1 observed in the host cuCtxCreate trace). */
#define NV50A0_CURSOR_ENTRIES 4
static struct { __u64 limit; __u64 cursor; } nv50a0_cur[NV50A0_CURSOR_ENTRIES];

static __u32 stub_alloc_handle(void)
{
  __u32 h;
  mutex_lock(&rm_mutex);
  h = next_rm_handle++;
  mutex_unlock(&rm_mutex);
  return h;
}

static void stub_add_handle(__u32 handle, __u32 parent, __u32 hClass)
{
  struct rm_handle *h = kmalloc(sizeof(*h), GFP_KERNEL);
  if (!h) return;
  h->handle = handle;
  h->parent = parent;
  h->hClass = hClass;
  h->mem = NULL;
  h->mem_size = 0;
  mutex_lock(&rm_mutex);
  list_add(&h->list, &rm_handles);
  mutex_unlock(&rm_mutex);
}

static struct rm_handle *stub_find_handle(__u32 handle)
{
  struct rm_handle *pos;
  mutex_lock(&rm_mutex);
  list_for_each_entry(pos, &rm_handles, list) {
    if (pos->handle == handle) {
      mutex_unlock(&rm_mutex);
      return pos;
    }
  }
  mutex_unlock(&rm_mutex);
  return NULL;
}

/* Allocate a page of kernel memory for a handle and map for user access */
static int stub_alloc_handle_mem(__u32 handle, size_t size)
{
  struct rm_handle *h = stub_find_handle(handle);
  unsigned long page;
  if (!h || size == 0) return -EINVAL;
  if (h->mem) return 0; /* already allocated */
  page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
  if (!page) return -ENOMEM;
  h->mem = (void *)page;
  h->mem_size = PAGE_SIZE;
  /* Fill with zeros — NVIF protocol uses mapped memory for cmd/resp */
  memset(h->mem, 0, PAGE_SIZE);
  return 0;
}

#define NV_GPU_ID 0x100   /* real driver reports gpu_id=0x100 */
static int gpu_in_use;    /* set once a client attaches the GPU */

#include "stub_ctrl_table.h"

static void stub_write_build_version(void __user *params_ptr)
{
  /* NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION: the real driver writes the
   * version strings into the caller's buffers. */
  static const char drv[] = "595.84";
  static const char ver[] = "rel/gpu_drv/r595/r595_00-298";
  static const char tit[] = "Private r595_00 rel/gpu_drv/r595/r595_00-298 unknown";
  const char *strs[3] = { drv, ver, tit };
  __u64 bufs[3];
  int i;
  if (copy_from_user(bufs, params_ptr + 8, sizeof(bufs)))
    return;
  for (i = 0; i < 3; i++) {
    char __user *dst = (char __user *)(unsigned long)bufs[i];
    if (!dst)
      continue;
    if (copy_to_user(dst, strs[i], strlen(strs[i]) + 1))
      continue;
    if (clear_user(dst + strlen(strs[i]) + 1, 0x50 - strlen(strs[i]) - 1))
      continue;
  }
}

/* ── ioctl handlers ── */

static void fab_open_file_add(struct file *f);
static void fab_open_file_del(struct file *f);

static int nvidia_open(struct inode *inode, struct file *file) {
  struct stub_file_event *s = kzalloc(sizeof(*s), GFP_KERNEL);
  pr_info("stub: OPEN minor=%d pid=%d comm=%s\n", iminor(inode), current->pid, current->comm);
  if (s)
    init_waitqueue_head(&s->wq);
  file->private_data = s;
  fab_open_file_add(file);
  return 0;
}
static int nvidia_release(struct inode *inode, struct file *file) {
  pr_info("stub: CLOSE minor=%d pid=%d comm=%s\n", iminor(inode), current->pid, current->comm);
  fab_open_file_del(file);
  kfree(file->private_data);
  file->private_data = NULL;
  return 0;
}

/* Zero-page mapping support for offset-0 mmaps (RM_MAP_MEMORY path). */
#define MAX_OFF0_MAPS 32
static struct stub_vma_pages *g_off0_maps[MAX_OFF0_MAPS];
struct stub_vma_pages {
  struct page **pages;
  unsigned long npages;
  int is_ctl;
  int is_shm;
  unsigned long shm_logged;
  struct vm_area_struct *vma;  /* for PTE zapping (poll read tracking) */
  struct stub_vma_pages *next;   /* all offset-0 mappings, for fabrication */
};

static void off0_map_add(struct stub_vma_pages *p)
{
  int i;
  for (i = 0; i < MAX_OFF0_MAPS; i++)
    if (!g_off0_maps[i]) {
      g_off0_maps[i] = p;
      return;
    }
}
static void off0_map_del(struct stub_vma_pages *p)
{
  int i;
  for (i = 0; i < MAX_OFF0_MAPS; i++)
    if (g_off0_maps[i] == p)
      g_off0_maps[i] = NULL;
}

/* Mirror of real nvidia_poll(): POLLIN when an RM event is pending;
 * the pending flag is consumed by the poll like dataless_event_pending. */
static struct stub_vma_pages *g_shm_pages;
static void stub_eventfd_signal(struct stub_file_event *s);
static unsigned long g_shm_touched_max;
static bool g_shm_written;
static int g_shm_fab_prints;
static bool g_fab_armed;
/* v71: PTE zap loop removed (see fab_work_fn) — g_zap_ticks dropped. */
/* Pages written by the UMD (recorded on the FIRST write fault of each
 * page) + the in-page offset of that first write. The completion fence
 * for the current phase sits in one of these. Filling WHOLE pages
 * corrupted the UMD (a notify-array page holds hundreds of 16B entries —
 * 0xff on the whole page = hundreds of spurious completions, flooding the
 * UMD's internal task pipe: writers blocked in anon_pipe_write while the
 * consumer waits on a futex). Fill only a 64B window at the actual write
 * address. Completions are also DELAYED (~10ms) so the UMD's internal
 * queue drains between phases, mirroring real copy latency. */
#define MAX_FAB_PAGES 32
static void fab_dump_if_written(struct stub_vma_pages *p, unsigned long off);
static struct stub_vma_pages *g_fab_pages[MAX_FAB_PAGES];
static unsigned long g_fab_offs[MAX_FAB_PAGES];
static unsigned long g_fab_inpage[MAX_FAB_PAGES];
static int g_fab_n;
static void fab_page_record(struct stub_vma_pages *p, unsigned long off,
                            unsigned long inpage)
{
  int i;
  if (!p || p->is_ctl || off >= p->npages || !p->pages[off])
    return;
  for (i = 0; i < g_fab_n; i++)
    if (g_fab_pages[i] == p && g_fab_offs[i] == off)
      return;
  if (g_fab_n < MAX_FAB_PAGES) {
    g_fab_pages[g_fab_n] = p;
    g_fab_offs[g_fab_n] = off;
    g_fab_inpage[g_fab_n] = inpage;
    g_fab_n++;
  } else {
    memmove(&g_fab_pages[0], &g_fab_pages[1],
            (MAX_FAB_PAGES - 1) * sizeof(g_fab_pages[0]));
    memmove(&g_fab_offs[0], &g_fab_offs[1],
            (MAX_FAB_PAGES - 1) * sizeof(g_fab_offs[0]));
    memmove(&g_fab_inpage[0], &g_fab_inpage[1],
            (MAX_FAB_PAGES - 1) * sizeof(g_fab_inpage[0]));
    g_fab_pages[MAX_FAB_PAGES - 1] = p;
    g_fab_offs[MAX_FAB_PAGES - 1] = off;
    g_fab_inpage[MAX_FAB_PAGES - 1] = inpage;
  }
}

/* Deferred fabrication: runs on the system workqueue (no fd table), so it
 * fills the fence windows and wakes the poll waitqueues of all open device
 * fds. The immediate poll-context eventfd signals stay (event machinery
 * tolerates spurious wakes; the flood came from the fill scope). */
static struct delayed_work g_fab_work;
static struct file *g_open_files[16];
static DEFINE_MUTEX(g_open_mutex);
static void fab_open_file_add(struct file *f)
{
  int i;
  mutex_lock(&g_open_mutex);
  for (i = 0; i < 16; i++)
    if (!g_open_files[i]) {
      get_file(f);
      g_open_files[i] = f;
      break;
    }
  mutex_unlock(&g_open_mutex);
}
static void fab_open_file_del(struct file *f)
{
  int i;
  mutex_lock(&g_open_mutex);
  for (i = 0; i < 16; i++)
    if (g_open_files[i] == f) {
      fput(g_open_files[i]);
      g_open_files[i] = NULL;
      break;
    }
  mutex_unlock(&g_open_mutex);
}
static void fab_after_dump(void);
static void fab_work_fn(struct work_struct *ws)
{
  int i;
  (void)ws;
  /* Fill EVERY offset-0 mapping and every handle mem page. The fence the
   * UMD waits on sits in one of these; the write-fault window tracking
   * proved unreliable (fence pages are faulted once early, then evicted
   * from the 32-page window). The earlier "flood deadlock" from this
   * approach was actually the TRACE's own output blocking on the full
   * drain pipe — fixed in libtrace_cuda.so (file-only logging). The UMD
   * tolerates the extra completed fences; only the pacing matters, and
   * the 10ms delay provides that. */
  /* v66: replay the EXACT host state (ctl_4096_0.bin / ctl_65536_0.bin).
   * v64 (all 0x01) PASSED the poll but FAILED validation (cuCtxCreate=719);
   * v65 (real record + [0]=0x01) STUCK the poll with only 7 fabricates:
   * its zeros at [1..0xf] left the marker words (u32@4=0xff000000,
   * u32@8=0x01000000, u32@0xc=0x00fff200) zero, and the poll does a
   * masked-nonzero check on them (v64's 0x01010101 passed; v63/v65's 0
   * stuck; the real driver re-arms the block to the captured host state).
   * The UMD's submit zeroes exactly 14 bytes (v62 ndiff=14); re-arming
   * with the true host content is the completion. */
  for (i = 0; i < MAX_OFF0_MAPS; i++) {
    struct stub_vma_pages *mp = g_off0_maps[i];
    unsigned long j;
    if (!mp || !mp->is_ctl)
      continue;
    for (j = 0; j < mp->npages; j++) {
      u8 *v = mp->pages[j] ? page_address(mp->pages[j]) : NULL;
      if (!v)
        continue;
      if (mp->npages == 1)
        memcpy(v, host_ctl_4096, PAGE_SIZE);
      else
        memcpy(v, host_ctl_65536, PAGE_SIZE);
    }
  }
  /* v71: REMOVED the PTE zap loop (previously unmap_mapping_pages every
   * 5th fire). The shm vma is a private mapping: after unmap the guest's
   * re-fault lands in a COW copy, so the UMD's channel writes (methods,
   * pushbuffers, GET/PUT at +0x40) got discarded — its maps closed as
   * zeros and cuCtxCreate=719 followed. Content now persists in the
   * pages; direct page_address writes (ctl re-arm, shm notify) remain
   * visible without re-faulting. */
  for (i = 0; i < MAX_OFF0_MAPS; i++) {
    struct stub_vma_pages *mp = g_off0_maps[i];
    unsigned long j;
    if (!mp || !(mp->is_shm))
      continue;
    for (j = 0; j < mp->npages; j++) {
      struct page *pg = mp->pages[j];
      if (pg)
        fab_dump_if_written(mp, j);
    }
  }
  mutex_lock(&g_open_mutex);
  for (i = 0; i < 16; i++) {
    struct stub_file_event *es;
    if (!g_open_files[i])
      continue;
    es = g_open_files[i]->private_data;
    if (es) {
      es->pending = true;
      es->ev_queued = true;
      es->ev_hObject = 0x5c000003;
      es->ev_notifyIndex = 0;
      es->ev_info32 = 0;
      es->ev_info16 = 0;
      wake_up_interruptible(&es->wq);
    }
  }
  mutex_unlock(&g_open_mutex);
  fab_after_dump();
}
/* v68: CE completion notify for the channel-init shm submissions.
 * The UMD writes its submission records into the 2MB shm at
 * pages {2,5,8,11,14} (pgoff 0x2000+0x3000k), offset +0x40..0x67:
 * [GET/addr][GET/addr][0][0xff][notify...][0xff]. The host capture
 * (host_map_06) shows the real CE's completion = writing 0x000000ff
 * at +0x4c and +0x60. The UMD waits on the eventfd interrupt and
 * re-reads those bytes, so the notify must be written BEFORE the
 * signal (the old code signaled first and filled 10ms later - the
 * UMD's check read 0 and failed fast with cuCtxCreate=719). */
static void fab_shm_notify(void)
{
  static const unsigned int cpg[] = { 2, 5, 8, 11, 14 };
  int i, k;
  for (i = 0; i < MAX_OFF0_MAPS; i++) {
    struct stub_vma_pages *mp = g_off0_maps[i];
    if (!mp || !mp->is_shm || mp->npages != 512)
      continue;
    for (k = 0; k < (int)ARRAY_SIZE(cpg); k++) {
      struct page *pg;
      u8 *v;
      if (cpg[k] >= mp->npages)
        continue;
      pg = mp->pages[cpg[k]];
      if (!pg)
        continue;
      v = page_address(pg);
      put_unaligned_le32(0x000000ff, v + 0x4c);
      put_unaligned_le32(0x000000ff, v + 0x60);
    }
  }
}
/* v69: pre-check shm state dump. The UMD fails INSTANTLY after the first
 * poll of the new ctx-shm (teardown right after; close dumps = post-
 * cleanup zeros). Dump the shm pages in the poll handler BEFORE signaling
 * so the UMD's check-time content is captured (methods at 0x360+). */
static int g_poll_dump_left = 3;
static void fab_poll_dump(void)
{
  int i;
  if (g_poll_dump_left <= 0)
    return;
  g_poll_dump_left--;
  for (i = 0; i < MAX_OFF0_MAPS; i++) {
    struct stub_vma_pages *mp = g_off0_maps[i];
    unsigned long j;
    if (!mp || !mp->is_shm)
      continue;
    pr_info("stub: POLLDUMP vma=0x%lx npages=%lu",
            mp->vma ? mp->vma->vm_start : 0UL, mp->npages);
    for (j = 0; j < mp->npages && j < 16; j++) {
      const u8 *v = mp->pages[j] ? page_address(mp->pages[j]) : NULL;
      unsigned long k;
      if (!v)
        continue;
      printk(KERN_CONT "\n  pg%lu:", j);
      for (k = 0; k < 0x400; k++) {
        if (k % 64 == 0)
          printk(KERN_CONT "\n   %03lx:", k);
        printk(KERN_CONT " %02x", v[k]);
      }
    }
    printk(KERN_CONT "\n");
  }
}
static int g_afdump_left = 60;
static void fab_after_dump(void)
{
  int i;
  if (g_afdump_left <= 0)
    return;
  g_afdump_left--;
  for (i = 0; i < MAX_OFF0_MAPS; i++) {
    struct stub_vma_pages *mp = g_off0_maps[i];
    unsigned long j, k;
    static const unsigned int comp_pg[] = { 2, 5, 8, 11, 14 };
    if (!mp)
      continue;
    if (mp->is_ctl) {
      const u8 *v = mp->pages[0] ? page_address(mp->pages[0]) : NULL;
      if (!v)
        continue;
      pr_info("stub: AFCTL n=%lu p0=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
              mp->npages, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
              v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
    }
    if (!mp->is_shm || mp->npages != 512)
      continue;
    pr_info("stub: AFSHM vma=0x%lx", mp->vma ? mp->vma->vm_start : 0UL);
    for (j = 0; j < ARRAY_SIZE(comp_pg); j++) {
      const u8 *v;
      if (comp_pg[j] >= mp->npages)
        continue;
      v = mp->pages[comp_pg[j]] ? page_address(mp->pages[comp_pg[j]]) : NULL;
      if (!v)
        continue;
      printk(KERN_CONT "\n  cp%d:", comp_pg[j]);
      for (k = 0; k < 0x80; k++) {
        if (k % 16 == 0)
          printk(KERN_CONT "\n   %02lx:", k);
        printk(KERN_CONT " %02x", v[k]);
      }
    }
    printk(KERN_CONT "\n");
  }
}

static unsigned int nvidia_poll(struct file *file, poll_table *wait) {
  struct stub_file_event *s = file->private_data;
  unsigned int mask = 0;
  if (!s)
    return 0;
  /* The UMD's completion wait polls the /dev/nvidia0 fds after submitting
   * work to the shm window — fabricate the CE completion there: fill the
   * 64B windows the UMD wrote this phase with 0xffffffff (fence/GET
   * "done") so the UMD's fence re-check (no ioctls in the wait loop —
   * pure mapped reads) passes. Fires ONCE per ioctl burst (armed in
   * nvidia_ioctl), DELAYED ~10ms to pace the completions. */
  if (g_fab_armed && g_fab_n > 0) {
    g_fab_armed = false;
    if (g_shm_fab_prints < 8) {
      g_shm_fab_prints++;
      pr_info("stub: POLL fabricate completion (%d windows, delayed)\n",
              g_fab_n);
    }
    schedule_delayed_work(&g_fab_work, msecs_to_jiffies(10));
    /* CE completion notify FIRST, then wake: the UMD's wait polls the
     * eventfds and re-reads the shm notify bytes right after waking. */
    fab_poll_dump();
    fab_shm_notify();
    stub_eventfd_signal(s);
  }
  poll_wait(file, &s->wq, wait);
  if (s->pending) {
    mask = POLLPRI | POLLIN;
    s->pending = false;
  }
  return mask;
}
static ssize_t nvidia_read(struct file *file, char __user *buf, size_t count, loff_t *off) {
  pr_info("stub: READ minor=%d pid=%d comm=%s count=%zu\n", iminor(file_inode(file)), current->pid, current->comm, count);
  return 0;
}

static struct vm_area_struct *g_ctl_vma;
static bool g_ctl_active;

/* ctx-shm (2MB) fence fabrication: the UMD submits work by writing the
 * pushbuffer into the shm window, then waits (poll loop) for the CE to
 * complete — which in the real GPU writes the fence/GET into the same
 * window. The stub patches the window with "completed" values (0xffffffff)
 * once the submit has been observed, so the UMD's fence re-checks pass. */

static int g_ref_dumps;
#define MAX_REF_LOGGED 128
static struct stub_vma_pages *g_ref_pages[MAX_REF_LOGGED];
static unsigned long g_ref_offs[MAX_REF_LOGGED];
static void fab_dump_if_written(struct stub_vma_pages *p, unsigned long off)
{
  const u8 *v;
  const u8 *host = NULL;
  unsigned long i;
  if (g_ref_dumps >= MAX_REF_LOGGED || !p->pages[off])
    return;
  for (i = 0; i < g_ref_dumps; i++)
    if (g_ref_pages[i] == p && g_ref_offs[i] == off)
      return;
  v = page_address(p->pages[off]);
  if (p->is_ctl && p->npages == 1)
    host = host_ctl_4096;
  else if (p->is_ctl)
    host = host_ctl_65536 + off * PAGE_SIZE;
  else if (p->is_shm && off < 16)
    host = host_rm_shm_2mb + off * PAGE_SIZE;
  if (host) {
    for (i = 0; i < PAGE_SIZE; i++)
      if (v[i] != host[i])
        break;
    if (i == PAGE_SIZE)
      return;
  } else {
    for (i = 0; i < PAGE_SIZE; i++)
      if (v[i])
        break;
    if (i == PAGE_SIZE)
      return;
  }
  g_ref_pages[g_ref_dumps] = p;
  g_ref_offs[g_ref_dumps] = off;
  g_ref_dumps++;
  pr_info("stub: REF pgoff=0x%lx %s", off << PAGE_SHIFT,
          p->is_shm ? "shm" : "ctl");
  if (host) {
    unsigned long n = 0, nd = 0;
    for (i = 0; i < PAGE_SIZE; i++)
      if (v[i] != host[i])
        nd++;
    printk(KERN_CONT " ndiff=%lu", nd);
    if (p->is_shm && off < 16) {
      char buf[256];
      unsigned long b = 0;
      for (i = 0; i < 0x80 && b < sizeof(buf) - 1; i++) {
        if (v[i] != host[i]) {
          b += scnprintf(buf + b, sizeof(buf) - b, " %04lx:%02x/%02x",
                         i, v[i], host[i]);
          if (n++ >= 31)
            break;
        }
      }
      if (b)
        printk(KERN_CONT " g/h:%s", buf);
    }
  } else {
    unsigned long n = 0, nd = 0;
    for (i = 0; i < PAGE_SIZE; i++)
      if (v[i])
        nd++;
    printk(KERN_CONT " nz=%lu", nd);
    for (i = 0; i < PAGE_SIZE && n < 24; i++) {
      if (v[i]) {
        printk(KERN_CONT " [%04lx]=%02x", i, v[i]);
        n++;
      }
    }
  }
  printk(KERN_CONT "\n");
}

static void stub_vma_close(struct vm_area_struct *vma)
{
  struct stub_vma_pages *p = vma->vm_private_data;
  unsigned long i;
  if (!p)
    return;
  off0_map_del(p);
  if (p->is_ctl) {
    unsigned long nb = 0;
    pr_info("stub: CTLCLOSE npages=%lu\n", p->npages);
    for (i = 0; i < p->npages && i < 16; i++) {
      unsigned long j, nz = 0;
      const u8 *v = p->pages[i] ? page_address(p->pages[i]) : NULL;
      if (!v)
        continue;
      for (j = 0; j < PAGE_SIZE; j++)
        if (v[j])
          nz++;
      nb += nz;
    }
    pr_info("stub: CTLNONZERO total=%lu", nb);
    for (i = 0; i < p->npages && i < 16; i++) {
      unsigned long j, nz = 0;
      const u8 *v = p->pages[i] ? page_address(p->pages[i]) : NULL;
      if (!v)
        continue;
      for (j = 0; j < PAGE_SIZE; j++)
        if (v[j])
          nz++;
      printk(KERN_CONT " pg%lu=%lu", i, nz);
    }
    printk(KERN_CONT "\n");
    if (p->npages >= 1 && p->pages[0]) {
      const u8 *v = page_address(p->pages[0]);
      pr_info("stub: CTLDUMP pg0:");
      for (i = 0; i < 256; i++)
        printk(KERN_CONT " %02x", v[i]);
      printk(KERN_CONT "\n");
    }
    if (vma == g_ctl_vma) {
      g_ctl_vma = NULL;
      g_ctl_active = false;  /* stop scanning; pages are about to be freed */
    }
  } else if (p->is_shm && p->npages >= 1 && p->pages[0]) {
    unsigned long pi;
    pr_info("stub: SHMDUMP npages=%lu flags=0x%lx%s",
            p->npages,
            p->vma ? (p->vma->vm_flags & (VM_SHARED | VM_WRITE | VM_MAYSHARE)) : 0UL,
            p->vma ? "" : " (novma)");
    if (p->vma)
      pr_info("stub: SHMDUMPVMA vma=0x%lx size=0x%lx", p->vma->vm_start, p->vma->vm_end - p->vma->vm_start);
    for (pi = 0; pi < p->npages && pi < 6; pi++) {
      const u8 *v = p->pages[pi] ? page_address(p->pages[pi]) : NULL;
      unsigned long j;
      if (!v)
        continue;
      printk(KERN_CONT "\n  pg%lu:", pi);
      for (j = 0; j < 0x80; j++)
        printk(KERN_CONT " %02x", v[j]);
    }
    printk(KERN_CONT "\n");
  }
  for (i = 0; i < p->npages; i++)
    if (p->pages[i])
      __free_page(p->pages[i]);
  kfree(p->pages);
  kfree(p);
  vma->vm_private_data = NULL;
}

static vm_fault_t stub_vma_fault(struct vm_fault *vmf)
{
  struct vm_area_struct *vma = vmf->vma;
  struct stub_vma_pages *p = vma->vm_private_data;
  unsigned long off = vmf->pgoff;
  struct page *pg;
  if (!p || off >= p->npages || !p->pages[off])
    return VM_FAULT_SIGBUS;
  pg = p->pages[off];
  if (p->is_ctl) {
    pr_info("stub: CTLRW pid=%d addr=0x%lx off=0x%lx %s\n",
            current->pid, vmf->address, off << PAGE_SHIFT,
            (vmf->flags & FAULT_FLAG_WRITE) ? "WR" : "RD");
  }
  if (p->is_shm && p->shm_logged < 2000) {
    p->shm_logged++;
    pr_info("stub: SHMRD pid=%d addr=0x%lx off=0x%lx %s fl=0x%lx\n",
            current->pid, vmf->address, off << PAGE_SHIFT,
            (vmf->flags & FAULT_FLAG_WRITE) ? "WR" : "RD",
            vma->vm_flags & (VM_SHARED | VM_WRITE));
    if (off < 20)
      pr_info("stub: FAULTPG off=0x%lx cur[0..7]=%*ph pg=%px",
              off << PAGE_SHIFT, 8, page_address(p->pages[off]),
              p->pages[off]);
    if (vmf->flags & FAULT_FLAG_WRITE) {
      g_shm_pages = p;
      g_shm_written = true;
      if ((off << PAGE_SHIFT) + PAGE_SIZE > g_shm_touched_max)
        g_shm_touched_max = (off << PAGE_SHIFT) + PAGE_SIZE;
    }
  }
  if (vmf->flags & FAULT_FLAG_WRITE)
    fab_page_record(p, off, vmf->address & (PAGE_SIZE - 1));
  if (p->is_ctl || p->is_shm)
    fab_dump_if_written(p, off);
  get_page(pg);
  vmf->page = pg;
  return 0;
}

static const struct vm_operations_struct stub_vm_ops = {
  .close = stub_vma_close,
  .fault = stub_vma_fault,
};

/* ── control-area write scanner ──
 * Observes what the UMD writes into the mapped RM control pages so the
 * stub can learn the RM mapped-ctrl protocol. Logs changes vs the
 * initial (host-captured) content. */
#define CTL_SCAN_INTERVAL_MS 50
#define CTL_SCAN_RUNS 400

static struct delayed_work g_ctl_scan_work;
static struct page *g_ctl_pages[16];
static unsigned long g_ctl_npages;
static u8 *g_ctl_shadow;
static unsigned long g_ctl_runs_left;

static void ctl_scan_worker(struct work_struct *ws)
{
  unsigned long i;
  (void)ws;
  if (!g_ctl_active || g_ctl_runs_left == 0) {
    g_ctl_active = false;
    return;
  }
  g_ctl_runs_left--;
  for (i = 0; i < g_ctl_npages; i++) {
    struct page *pg = g_ctl_pages[i];
    u8 *va;
    unsigned long j;
    if (!pg)
      continue;
    va = page_address(pg);
    if (!memcmp(va, g_ctl_shadow + i * PAGE_SIZE, PAGE_SIZE))
      continue;
    for (j = 0; j < PAGE_SIZE; j += 32) {
      if (!memcmp(va + j, g_ctl_shadow + i * PAGE_SIZE + j, 32))
        continue;
      {
        int k;
        pr_info("stub: CTLWR pg%lu +%04lx:", i, j);
        for (k = 0; k < 32; k++)
          printk(KERN_CONT " %02x", va[j + k]);
        printk(KERN_CONT " | was");
        for (k = 0; k < 32; k++)
          printk(KERN_CONT " %02x", g_ctl_shadow[i * PAGE_SIZE + j + k]);
        printk(KERN_CONT "\n");
      }
      memcpy(g_ctl_shadow + i * PAGE_SIZE + j, va + j, 32);
    }
  }
  schedule_delayed_work(&g_ctl_scan_work, msecs_to_jiffies(CTL_SCAN_INTERVAL_MS));
}

static void ctl_scan_start(struct vm_area_struct *vma, struct page **pages,
                           unsigned long npages, const u8 *initial)
{
  unsigned long i;
  if (g_ctl_active)
    return;
  g_ctl_vma = vma;
  for (i = 0; i < npages; i++)
    g_ctl_pages[i] = pages[i];
  g_ctl_npages = npages;
  g_ctl_shadow = vzalloc(npages * PAGE_SIZE);
  if (!g_ctl_shadow)
    return;
  for (i = 0; i < npages; i++)
    memcpy(g_ctl_shadow + i * PAGE_SIZE, initial + i * PAGE_SIZE, PAGE_SIZE);
  g_ctl_runs_left = CTL_SCAN_RUNS;
  g_ctl_active = true;
  INIT_DELAYED_WORK(&g_ctl_scan_work, ctl_scan_worker);
  schedule_delayed_work(&g_ctl_scan_work, msecs_to_jiffies(CTL_SCAN_INTERVAL_MS));
}

static int nvidia_mmap(struct file *file, struct vm_area_struct *vma) {
  /* The RM UMD maps memory objects with mmap offset 0; the real driver
   * maps the mapping context previously registered via the
   * RM_MAP_MEMORY ioctl (nr=78). We provide zeroed pages instead.
   * Non-zero offsets encode the RM handle in bits 12+ as a fallback. */
  unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
  __u32 handle = (__u32)(offset >> 12);  /* handle embedded in upper bits of offset */
  struct rm_handle *h = stub_find_handle(handle);
  unsigned long pfn;
  pr_info("stub: MMAP minor=%d handle=0x%x pid=%d comm=%s size=%lu pgoff=%lu\n",
          iminor(file_inode(file)), handle, current->pid, current->comm,
          vma->vm_end - vma->vm_start, vma->vm_pgoff);
  if (handle == 0) {
    unsigned long npages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
    struct stub_vma_pages *p;
    unsigned long i;
    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p)
      return -ENOMEM;
    p->pages = kcalloc(npages, sizeof(struct page *), GFP_KERNEL);
    if (!p->pages) {
      kfree(p);
      return -ENOMEM;
    }
    p->npages = npages;
    for (i = 0; i < npages; i++) {
      struct page *pg = alloc_page(GFP_USER);
      if (!pg)
        goto fail;
      p->pages[i] = pg;
      clear_page(page_address(pg));
    }
    /* Replay the real driver's control-area contents (captured from the
     * host): the 4096B page on nvidiactl holds the RM control version/caps
     * block; the 65536B page on nvidia0 holds the control magic + token. */
    if (npages == 1) {
      void *dst = page_address(p->pages[0]);
      memcpy(dst, host_ctl_4096, min_t(size_t, sizeof(host_ctl_4096), PAGE_SIZE));
      pr_info("stub: MMAP offset-0 control page (4096B, real content)\n");
      p->is_ctl = 1;
      ctl_scan_start(vma, p->pages, npages, host_ctl_4096);
    } else if (npages == 16) {
      for (i = 0; i < 16; i++)
        memcpy(page_address(p->pages[i]), host_ctl_65536 + i * PAGE_SIZE, PAGE_SIZE);
      pr_info("stub: MMAP offset-0 control area (64KB, real content)\n");
      p->is_ctl = 1;
      ctl_scan_start(vma, p->pages, npages, host_ctl_65536);
    } else if (npages == 512) {
      /* 2MB RM shared-memory mapping (ctx shm) — replay the real driver's
       * content captured on the host during cuCtxCreate (first 64KB
       * nonzero, rest zero). */
      for (i = 0; i < 16; i++)
        memcpy(page_address(p->pages[i]), host_rm_shm_2mb + i * PAGE_SIZE, PAGE_SIZE);
      pr_info("stub: MMINJ npages=%lu p0[0..7]=%*ph", npages, 8,
              page_address(p->pages[0]));
      p->is_shm = 1;
      pr_info("stub: MMAP offset-0 RM shm (2MB, real host content)\n");
    } else {
      pr_info("stub: MMAP offset-0 zero-page mapping: %lu pages\n", npages);
    }
    vma->vm_ops = &stub_vm_ops;
    vma->vm_private_data = p;
    p->vma = vma;
    /* v72: force VM_SHARED so WRITE faults map the page directly (no COW
     * copy): the UMD's private shm mappings were COW'd at first write,
     * so its channel writes (methods/pushbuffers/GET+PUT) landed in anon
     * copies that died with the process — its map closed as zeros and
     * cuCtxCreate=719 followed. With shared PTEs the writes persist in
     * the stub's pages and stay visible on later reads. */
    vm_flags_set(vma, VM_SHARED | VM_MAYSHARE);
    pr_info("stub: MMAFFLAGS npages=%lu flags=0x%lx", npages,
            vma->vm_flags & (VM_SHARED | VM_WRITE | VM_MAYSHARE));
    off0_map_add(p);
    return 0;
fail:
    stub_vma_close(vma);
    return -EAGAIN;
  }
  if (!h || !h->mem) {
    pr_info("stub: MMAP no memory for handle, returning ENOMEM\n");
    return -ENOMEM;
  }
  pfn = virt_to_phys(h->mem) >> PAGE_SHIFT;
  if (remap_pfn_range(vma, vma->vm_start, pfn, h->mem_size, vma->vm_page_prot))
    return -EAGAIN;
  return 0;
}

static int nvidia_rm_alloc(struct nv_os21_params *p)
{
  __u32 hNew = stub_alloc_handle();

  /* NV01_ROOT_CLIENT — root handle */
  if (p->hClass == 0x1) {
    root_handle = hNew;
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* NV01_DEVICE_0 — device object */
  if (p->hClass == 0x82) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* NV20_SUBDEVICE_0 — subdevice */
  if (p->hClass == 0x2080) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* FERMI_VASPACE_A — virtual address space */
  if (p->hClass == 0x90f1) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    return 0;
  }

  /* TURING_USERMODE_A / AMPERE_USERMODE_A */
  if (p->hClass == 0xc561 || p->hClass == 0xc5b7) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* KEPLER_CHANNEL_GROUP_A */
  if (p->hClass == 0xa6c0) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    return 0;
  }

  /* FERMI_CONTEXT_SHARE_A */
  if (p->hClass == 0xa6ce) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* AMPERE_CHANNEL_GPFIFO_A / BLACKWELL_CHANNEL_GPFIFO_A */
  if (p->hClass == 0xc36f || p->hClass == 0xc56b) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* AMPERE_DMA_COPY_B / ADA_COMPUTE_A / video decoder classes */
  if (p->hClass == 0xc0b5 || p->hClass == 0xc561 || p->hClass == 0xc5b7 ||
      p->hClass == 0xc9b0 || p->hClass == 0xcfb0) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* NV01_MEMORY_VIRTUAL */
  if (p->hClass == 0x9017) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    return 0;
  }

  /* NV1_MEMORY_SYSTEM / NV1_MEMORY_USER */
  if (p->hClass == 0x9002 || p->hClass == 0x9001) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    return 0;
  }

  /* GT200_DEBUGGER */
  if (p->hClass == 0x5a) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    return 0;
  }

  /* MAXWELL_PROFILER_DEVICE */
  if (p->hClass == 0xb0cc) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* NV01_ROOT (client root) */
  if (p->hClass == 0x0) {
    p->hObjectNew = hNew;
    p->status = 0;
    stub_add_handle(hNew, p->hObjectParent, p->hClass);
    stub_alloc_handle_mem(hNew, PAGE_SIZE);
    return 0;
  }

  /* Generic fallback: accept any class, allocate handle, return success */
  p->hObjectNew = hNew;
  p->status = 0;
  stub_add_handle(hNew, p->hObjectParent, p->hClass);
  stub_alloc_handle_mem(hNew, PAGE_SIZE);
  pr_debug("stub: RM_ALLOC (generic) hClass=0x%x handle=0x%x\n", p->hClass, hNew);
  return 0;
}

static void stub_eventfd_signal(struct stub_file_event *s);
static int nvidia_rm_control(struct nv_os54_params *p, void __user *argp,
                             struct stub_file_event *s)
{
  void __user *params_ptr = (void __user *)(unsigned long)p->params;

  if (!params_ptr)
    return 0;

  /* NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS (0x20801702): the UMD polls this
   * after submitting work (e.g. copy completion) — the stub has no real
   * interrupts, so fabricate the completion: queue the RM event, wake the
   * device fd poll waitqueue; the UMD's event thread wakes and fetches the
   * notification via NV_ESC_RM_GET_EVENT_DATA. */
  if (p->cmd == 0x20801702) {
    __u32 engines = 0xffffffff;
    if (p->paramsSize >= 4) {
      if (copy_from_user(&engines, params_ptr, 4))
        return -EFAULT;
    }
    pr_info("stub: MC_SERVICE_INTERRUPTS engines=0x%x -> fabricate event\n", engines);
    stub_eventfd_signal(s);
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV2080_CTRL_CMD_GR_GET_INFO (0x20801201): must be handled before the
   * table rules (the table only captured a 32-byte snapshot of this reply).
   * Replay the full 59-entry x 8-byte reply captured from the real driver. */
  if (p->cmd == 0x20801201) {
    struct nv_ctrl_gr_get_info gi;
    if (copy_from_user(&gi, params_ptr, sizeof(gi)))
      return -EFAULT;
    pr_info("stub: GR_GET_INFO pid=%d size=%u\n", current->pid, gi.grInfoListSize);
    if (gi.grInfoListSize > 0) {
      size_t zs = min_t(size_t, gi.grInfoListSize * 8, sizeof(host_gr_get_info));
      if (copy_to_user((void __user *)(unsigned long)gi.grInfoList,
                       host_gr_get_info, zs))
        return -EFAULT;
    }
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE (0xd01): the reply (address
   * space type) depends on the (hObject, mapFlags) inputs, NOT on call order.
   * Captured from the real 595.84 driver:
   *   {0x5c000005, 0x00080002} -> REGMEM(3)
   *   {0x5c000006, 0x00080001} -> SYSMEM(1)
   *   {0x5c000012, 0x00000000} -> VIDMEM(2)
   *   {0x5c000014, 0x00000000} -> SYSMEM(1)
   *   everything else            -> SYSMEM(1) */
  if (p->cmd == 0x00000d01) {
    __u32 in[3] = {};
    __u32 asType = 1;
    if (p->paramsSize >= 12) {
      if (copy_from_user(in, params_ptr, 12))
        return -EFAULT;
      if (in[0] == 0x5c000005 && in[1] == 0x00080002)
        asType = 3;
      else if (in[0] == 0x5c000012 && in[1] == 0x00000000)
        asType = 2;
      pr_info("stub: GET_ADDR_SPACE_TYPE hObj=0x%x mapFlags=0x%x -> %u\n",
              in[0], in[1], asType);
      if (copy_to_user(params_ptr + 8, &asType, 4))
        return -EFAULT;
    }
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV2080_CTRL_CMD_GPU_GET_CAPS_V2 (0x20803002): real driver replies with a
   * fully zeroed params block (verified against host capture: 13864 bytes of
   * zeros). The table rule for this command is stale; zero-fill instead. */
  if (p->cmd == 0x20803002) {
    if (p->paramsSize > 0) {
      char *zbuf;
      if (p->paramsSize > (1u << 16))
        return -EINVAL;
      zbuf = vzalloc(p->paramsSize);
      if (!zbuf)
        return -ENOMEM;
      if (copy_to_user(params_ptr, zbuf, p->paramsSize)) {
        vfree(zbuf);
        return -EFAULT;
      }
      vfree(zbuf);
    }
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* Table-driven responses captured from a real 595.84 driver (stub_ctrl_table.h).
   * Only driver-written bytes are overwritten patch-in-place; all other bytes are
   * caller input echo and are left untouched. Multi-call commands are served in
   * captured order, sticky on the last response for any further calls. */
  {
    int ri;
    for (ri = 0; ri < STUB_CTRL_RULES; ri++)
      if (stub_ctrl_rules[ri].cmd == p->cmd)
        break;
    if (ri < STUB_CTRL_RULES) {
      static __u32 stub_seq[STUB_CTRL_RULES];
      __u16 pbase = stub_ctrl_rules[ri].off;
      __u16 sbase = stub_ctrl_seq_starts[pbase];
      __u32 nseq = stub_ctrl_rules[ri].nseq;
      __u32 seq = stub_seq[ri];
      __u8 np;
      __u32 i;
      if (seq >= nseq)
        seq = nseq - 1;               /* sticky last */
      else
        stub_seq[ri] = seq + 1;
      np = stub_ctrl_seq_npairs[pbase + seq];
      pr_debug("stub: CTRL tbl cmd=0x%x hObj=0x%x seq=%u/%u np=%u sz=%u\n",
               p->cmd, p->hObject, seq, nseq, np, p->paramsSize);
      for (i = 0; i < np; i++) {
        __u16 off = stub_ctrl_offs[sbase + i];
        __u8 val = stub_ctrl_vals[sbase + i];
        if (off >= p->paramsSize)
          continue;
        if (copy_to_user(params_ptr + off, &val, 1))
          return -EFAULT;
      }
      /* NV0000_CTRL_CMD_GPU_ATTACH_IDS: record attach side effect and
       * confirm success (failedId = 0) */
      if (p->cmd == 0x215) {
        __u32 failedId = 0;
        __u32 in[4] = {};
        __u32 inFailed = 0;
        gpu_in_use = 1;
        if (p->paramsSize >= 132) {
          if (copy_from_user(in, params_ptr, 16) == 0)
            copy_from_user(&inFailed, params_ptr + 128, 4);
          pr_info("stub: ATTACH in=%08x %08x %08x %08x inFailed=%08x\n",
                  in[0], in[1], in[2], in[3], inFailed);
          if (copy_to_user(params_ptr + 128, &failedId, 4))
            return -EFAULT;
        }
      }
      /* NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION: write version strings */
      if (p->cmd == 0x101)
        stub_write_build_version(params_ptr);
      p->status = 0;
      if (copy_to_user(argp, p, sizeof(*p)))
        return -EFAULT;
      return 0;
    }
  }

  /* NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 (0x205) */
  if (p->cmd == 0x205) {
    struct nv_ctrl_gpu_get_id_info_v2 id;
    if (copy_from_user(&id, params_ptr, sizeof(id)))
      return -EFAULT;
    pr_info("stub: GET_ID_INFO_V2 gpuId=0x%x\n", id.gpuId);
    id.gpuFlags = 0x4 | (gpu_in_use ? 0x1 : 0); /* MOBILE (+IN_USE when attached) */
    id.deviceInstance = 0;
    id.subDeviceInstance = 0;
    id.sliStatus = 0x41; /* GPU_NOT_SUPPORTED|INVALID_GPU_COUNT, as on real driver */
    id.boardId = NV_GPU_ID;
    id.gpuInstance = 0;
    id.numaId = -1;
    if (copy_to_user(params_ptr, &id, sizeof(id)))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_GET_ID_INFO (0x202) */
  if (p->cmd == 0x202) {
    __u32 id[10];
    if (copy_from_user(&id, params_ptr, sizeof(id)))
      return -EFAULT;
    pr_info("stub: GET_ID_INFO gpuId=0x%x szName=0x%llx\n", id[0], ((__u64)id[5] << 32) | id[4]);
    id[1] = 0x4 | (gpu_in_use ? 0x1 : 0); /* MOBILE (+IN_USE when attached) */
    id[2] = 0;                 /* deviceInstance = 0, as on real driver */
    id[3] = 0;                 /* subDeviceInstance = 0 */
    /* id[4],id[5] = NvP64 szName — real driver returns NULL here, no name */
    id[4] = 0;
    id[5] = 0;
    id[6] = 0x41;              /* sliStatus, as on real driver */
    id[7] = NV_GPU_ID;         /* boardId */
    id[8] = 0;                 /* gpuInstance = 0 */
    id[9] = -1;                /* numaId = -1 (no NUMA) */
    if (copy_to_user(params_ptr, &id, sizeof(id)))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2 (0x800292) */
  if (p->cmd == 0x800292) {
    struct nv_ctrl_gpu_get_classlist_v2 cl;
    if (copy_from_user(&cl, params_ptr, sizeof(cl)))
      return -EFAULT;
    pr_info("stub: GET_CLASSLIST_V2 pid=%d numClasses=%u\n", current->pid, cl.numClasses);
    cl.numClasses = 0;
    if (copy_to_user(params_ptr, &cl, sizeof(cl)))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V1 (0x80029201) */
  if (p->cmd == 0x80029201) {
    struct nv_ctrl_gpu_get_classlist_v1 cl;
    if (copy_from_user(&cl, params_ptr, sizeof(cl)))
      return -EFAULT;
    cl.numClasses = 0;
    if (copy_to_user(params_ptr, &cl, sizeof(cl)))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS (0x201) */
  if (p->cmd == 0x201) {
    __u32 sz = min_t(__u32, p->paramsSize, 128);
    __u32 gpuIds[32] = {};
    gpuIds[0] = NV_GPU_ID; /* return the real gpu_id as attached */
    for (int i = 1; i < 32; i++)
      gpuIds[i] = 0xFFFFFFFF; /* INVALID_ID */
    if (copy_to_user(params_ptr, gpuIds, sz))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_GET_GID_INFO (0x21a) */
  if (p->cmd == 0x21a) {
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* Conf compute commands (0x83de...) */
  if (p->cmd == 0x83de0101 || p->cmd == 0x83de0102) {
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* Profiler commands */
  if (p->cmd >= 0xb0cc0101 && p->cmd <= 0xb0cc0108) {
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV2080_CTRL_CMD_INTERNAL_STATIC_KGR_GET_CONTEXT_BUFFERS_INFO */
  if (p->cmd == 0x20801220) {
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_SYSTEM_GET_FEATURES (0x1f0) */
  if (p->cmd == 0x1f0) {
    __u32 featuresMask;
    if (copy_from_user(&featuresMask, params_ptr, sizeof(featuresMask)))
      return -EFAULT;
    pr_info("stub: GET_FEATURES input=0x%x pid=%d comm=%s\n", featuresMask, current->pid, current->comm);
    featuresMask = 0x8;  /* real driver reports features mask 0x8 */
    if (copy_to_user(params_ptr, &featuresMask, sizeof(featuresMask)))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_DISCOVER (0x27a) */
  if (p->cmd == 0x27a) {
    __u8 params[8];
    if (copy_from_user(&params, params_ptr, sizeof(params)))
      return -EFAULT;
    pr_info("stub: GPU_DISCOVER domain=%u bus=%u slot=%u func=%u pid=%d comm=%s\n",
            *(int *)&params[0], params[4], params[5], params[6],
            current->pid, current->comm);
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY (0xd04) */
  if (p->cmd == 0xd04) {
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_GET_PROBED_IDS (0x214) */
  if (p->cmd == 0x214) {
    __u32 sz = min_t(__u32, p->paramsSize, 512);
    __u32 buf[128] = {};
    if (copy_from_user(buf, params_ptr, min(16u, sz)) == 0)
      pr_info("stub: GET_PROBED_IDS sz=%u in=%08x...\n", sz, buf[0]);
    for (int i = 0; i < 32; i++)
      buf[i] = (i == 0) ? NV_GPU_ID : 0xFFFFFFFF; /* gpuIds */
    for (int i = 32; i < 64; i++)
      buf[i] = 0xFFFFFFFF;                 /* excludedGpuIds */
    for (int i = 64; i < 128; i++)
      buf[i] = 0;   /* gpuFlags for each probed GPU */
    if (copy_to_user(params_ptr, buf, sz))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_ATTACH_IDS (0x215) */
  if (p->cmd == 0x215) {
    __u32 sz = min_t(__u32, p->paramsSize, 132);
    __u32 gpuIds[32] = {};
    __u32 failedId = 0;  /* real driver reports attach success */
    if (copy_from_user(gpuIds, params_ptr, min(sz, 128u)) == 0)
      pr_info("stub: ATTACH_IDS sz=%u gpuIds[0]=0x%x [1]=0x%x attach_all=%d\n",
              sz, gpuIds[0], gpuIds[1],
              (gpuIds[0] == 0x0000ffff) ? 1 : 0);
    gpu_in_use = 1;
    /* Write failedId at offset 128 */
    if (sz >= 132) {
      if (copy_to_user(params_ptr + 128, &failedId, 4))
        return -EFAULT;
    }
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_OS_GET_GPU_INFO (0x3d07) */
  if (p->cmd == 0x3d07) {
    __u32 inout[2] = {};
    if (copy_from_user(inout, params_ptr, min(8u, p->paramsSize)) == 0)
      pr_info("stub: OS_GET_GPU_INFO gpuId=0x%x\n", inout[0]);
    inout[1] = 0; /* minorNum = 0 */
    if (copy_to_user(params_ptr, inout, min(8u, p->paramsSize)))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES (0xcb330101) */
  if (p->cmd == 0xcb330101) {
    __u8 caps[16] = {};
    pr_info("stub: CONF_COMPUTE_CAPS all-zero\n");
    if (copy_to_user(params_ptr, caps, min(sizeof(caps), p->paramsSize)))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_GPUS_STATE (0xcb330104) */
  if (p->cmd == 0xcb330104) {
    __u8 in = 0;
    if (copy_from_user(&in, params_ptr, min(1u, p->paramsSize)) == 0)
      pr_info("stub: CC_GPU_STATE sz=%u bAcceptClientRequest(in)=%u\n",
              p->paramsSize, in);
    __u8 accept = 1; /* NvBool TRUE */
    if (copy_to_user(params_ptr, &accept, min(1u, p->paramsSize)))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS (0x288) */
  if (p->cmd == 0x288) {
    __u32 numDevices = 1;
    if (copy_to_user(params_ptr, &numDevices, min(4u, p->paramsSize)))
      return -EFAULT;
    /* devices[0]: gpuId=NV_GPU_ID, gpuInstanceId=INVALID, computeInstanceId=INVALID */
    if (p->paramsSize >= 16) {
      __u32 dev[3] = { NV_GPU_ID, 0xFFFFFFFF, 0xFFFFFFFF };
      if (copy_to_user(params_ptr + 4, dev, 12))
        return -EFAULT;
    }
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS (0x201) */
  if (p->cmd == 0x201) {
    __u32 sz = min_t(__u32, p->paramsSize, 128);
    __u32 gpuIds[32] = {};
    gpuIds[0] = NV_GPU_ID; /* return the real gpu_id as attached */
    for (int i = 1; i < 32; i++)
      gpuIds[i] = 0xFFFFFFFF; /* INVALID_ID */
    if (copy_to_user(params_ptr, gpuIds, sz))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_GPU_DETACH_IDS (0x216) */
  if (p->cmd == 0x216) {
    __u32 gpuIds[4];
    if (copy_from_user(gpuIds, params_ptr, min(16u, p->paramsSize)) == 0)
    pr_info("stub: DETACH_IDS pid=%d gpuIds[0]=0x%x [1]=0x%x\n",
            current->pid, gpuIds[0], gpuIds[1]);
    gpu_in_use = 0;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_SYNC_GPU_BOOST (0xa04) */
  if (p->cmd == 0xa04) {
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION (0x101) — BUILD_V1 */
  if (p->cmd == 0x101) {
    /* Layout: u32 sizeOfStrings, u32 pad, u64 pDriver, u64 pVersion, u64 pTitle, u32 cl, u32 officialCL */
    __u32 sz;
    __u64 ptrs[3];
    __u32 cl[2];
    if (copy_from_user(&sz, params_ptr, 4))
      return -EFAULT;
    if (copy_from_user(ptrs, params_ptr + 8, 24))
      return -EFAULT;
    if (copy_from_user(cl, params_ptr + 32, 8))
      return -EFAULT;
    pr_info("stub: BUILD_V1 sz=%u ptrs=0x%llx 0x%llx 0x%llx cl=%u %u\n",
            sz, ptrs[0], ptrs[1], ptrs[2], cl[0], cl[1]);
    {
      char drv_str[] = "595.84";
      char ver_str[] = "595.84";
      char title_str[] = "NVIDIA UNIX x86_64 Kernel Module";
      if (ptrs[0] && sz >= sizeof(drv_str)) {
        if (copy_to_user((void __user *)ptrs[0], drv_str, sizeof(drv_str)))
          return -EFAULT;
      }
      if (ptrs[1] && sz >= sizeof(ver_str)) {
        if (copy_to_user((void __user *)ptrs[1], ver_str, sizeof(ver_str)))
          return -EFAULT;
      }
      if (ptrs[2] && sz >= sizeof(title_str)) {
        if (copy_to_user((void __user *)ptrs[2], title_str, sizeof(title_str)))
          return -EFAULT;
      }
    }
    /* keep caller's changelist numbers as-is */
    if (copy_to_user(params_ptr + 32, cl, 8))
      return -EFAULT;
    p->status = 0;
    if (copy_to_user(argp, p, sizeof(*p)))
      return -EFAULT;
    return 0;
  }

  /* All unknown cmds — log params and return success */
  if (params_ptr && p->paramsSize > 0 && p->paramsSize <= 512) {
    __u32 dump[4] = {};
    if (copy_from_user(dump, params_ptr, min(16u, p->paramsSize)) == 0)
      pr_info("stub: RM_C c=0x%x hO=0x%x sz=%u d=%08x %08x %08x %08x\n",
              p->cmd, p->hObject, p->paramsSize, dump[0], dump[1], dump[2], dump[3]);
  }
  p->status = 0;
  if (copy_to_user(argp, p, sizeof(*p)))
    return -EFAULT;
  return 0;
}

/* RM OS-event stand-in. In the real driver NV_ESC_ALLOC_OS_EVENT merely
 * records the (hParent, fd) pair — the fd is the UMD's own device fd, used
 * as an RM-side token only. Notifications are delivered by waking the
 * device fd's poll waitqueue (nv_post_event → wake_up_interruptible on
 * nvlfp->waitqueue) and fetched via NV_ESC_RM_GET_EVENT_DATA. The stub
 * mirrors that: MC_SERVICE_INTERRUPTS fabricates a completion, wakes the
 * device fd poll, and RM_GET_EVENT_DATA returns the queued event. */
#define MAX_EVFD 8
static struct stub_evfd *g_evfds[MAX_EVFD];
static struct file_operations nvidia_fops;

static void stub_eventfd_signal(struct stub_file_event *s)
{
  int i;
  for (i = 0; i < MAX_EVFD; i++)
    if (g_evfds[i]) {
      /* The UMD registers its OWN device fds via ALLOC_OS_EVENT (the fd
       * token is the device fd). Mirror real nv_post_event(): wake the
       * registered fd's poll waitqueue (event->nvfp in the real driver). */
      struct file *f = fget(g_evfds[i]->fd);
      if (f && f->f_op == &nvidia_fops) {
        struct stub_file_event *es = f->private_data;
        if (es) {
          es->pending = true;
          es->ev_queued = true;
          es->ev_hObject = 0x5c000003;
          es->ev_notifyIndex = 0;
          es->ev_info32 = 0;
          es->ev_info16 = 0;
          wake_up_interruptible(&es->wq);
        }
      }
      fput(f);
    }
  /* The UMD polls whichever device fd it holds (observed: it polls an
   * unregistered /dev/nvidia0 fd for copy completion). Wake EVERY nvidia
   * fd in the caller's fd table so the poll returns POLLIN regardless. */
  if (current->files) {
    struct fdtable *fdt;
    rcu_read_lock();
    fdt = files_fdtable(current->files);
    for (i = 0; i < fdt->max_fds; i++) {
      struct file *f = fdt->fd[i];
      if (!f)
        continue;
      if (f->f_op == &nvidia_fops && f->private_data) {
        struct stub_file_event *es = f->private_data;
        es->pending = true;
        es->ev_queued = true;
        es->ev_hObject = 0x5c000003;
        es->ev_notifyIndex = 0;
        es->ev_info32 = 0;
        es->ev_info16 = 0;
        wake_up_interruptible(&es->wq);
      } else if (f->f_op != &nvidia_fops) {
        /* The UMD's copy-completion wait polls an eventfd (observed:
         * anon_inode:[eventfd] fds 19/21/23). Signal it — mirror of the
         * real driver where the RM posts the event to the notify fd.
         * eventfd_ctx_fileget() returns ERR_PTR for non-eventfd files. */
        struct eventfd_ctx *ctx = eventfd_ctx_fileget(f);
        if (!IS_ERR(ctx)) {
          eventfd_signal(ctx);
          eventfd_ctx_put(ctx);
        }
      }
    }
    rcu_read_unlock();
  }
  if (!s)
    return;
  s->pending = true;
  s->ev_queued = true;
  s->ev_hObject = 0x5c000003; /* the device object */
  s->ev_notifyIndex = 0;
  s->ev_info32 = 0;
  s->ev_info16 = 0;
  wake_up_interruptible(&s->wq);
}

static long nvidia_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  unsigned int nr = _IOC_NR(cmd);
  void __user *argp = (void __user *)arg;

  /* Arm the completion fabrication: the UMD's flow = ioctl bursts
   * (channel alloc / copy setup) followed by a poll-only wait. Fire the
   * fabrication on the first poll after each burst. */
  g_fab_armed = true;

  switch (nr) {
  case NV_ESC_REGISTER_FD_NR:
    pr_info("stub: REGISTER_FD pid=%d comm=%s\n", current->pid, current->comm);
    return 0;

  case 87: { /* NV_ESC_REGISTER_FD (real driver, sz=64): envelope + fd
                {hRoot,hParent,hObject,hClass,status} + fd/u32s — RM just
                associates the fd; keep buffer, set status=0, return 0. */
    __u8 b[64];
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(b));
    if (copy_from_user(b, argp, sz)) return -EFAULT;
    memset(b + 16, 0, 4);
    pr_info("stub: REGISTER_FD64 pid=%d comm=%s fd=0x%llx\n", current->pid,
            current->comm, *(unsigned long long *)(b + 24));
    if (copy_to_user(argp, b, sz)) return -EFAULT;
    return 0;
  }

  case 88: { /* NV_ESC_UNREGISTER_FD (real driver, sz=48) */
    __u8 b[48];
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(b));
    if (copy_from_user(b, argp, sz)) return -EFAULT;
    memset(b + 16, 0, 4);
    pr_info("stub: UNREGISTER_FD pid=%d comm=%s\n", current->pid, current->comm);
    if (copy_to_user(argp, b, sz)) return -EFAULT;
    return 0;
  }

  case NV_ESC_CARD_INFO_NR: {
    struct nv_ioctl_card_info info[64];
    __u32 buf_size = _IOC_SIZE(cmd);
    /* If user passed a single struct, only fill one; otherwise fill 64 entries */
    int max_gpus = 1; /* Always report exactly 1 GPU */
    memset(info, 0, sizeof(info));
    info[0].valid = 1;
    info[0].pci_info.domain = 0;
    info[0].pci_info.bus = 0;
    info[0].pci_info.slot = 1;
    info[0].pci_info.function = 0;
    info[0].pci_info.vendor_id = 0x10de;
    info[0].pci_info.device_id = 0x27e0;
    info[0].gpu_id = NV_GPU_ID;
    info[0].reg_address = 0x86000000ULL;      /* actual guest BAR0 */
    info[0].reg_size = 0x1000000;              /* 16 MB */
    info[0].fb_address = 0x6000000000ULL;      /* actual guest BAR1 */
    info[0].fb_size = 0x400000000ULL;          /* 16 GB */
    info[0].minor_number = 0;
    info[0].interrupt_line = 21;  /* IRQ 21 from ACPI (\_SB_.GSIF) */
    pr_info("stub: CARD_INFO cmd=0x%x pid=%d comm=%s buf_size=%u gpus=%d\n", cmd,
            current->pid, current->comm, buf_size, max_gpus);
    if (copy_to_user(argp, &info, min_t(size_t, sizeof(info), buf_size)))
      return -EFAULT;
    return 0;
  }

  case NV_ESC_CHECK_VERSION_STR_NR: {
    struct {
      __u32 cmd;
      __u32 reply;
      char versionString[64];
    } chk_ver;
    unsigned int chk_sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(chk_ver));
    if (copy_from_user(&chk_ver, argp, chk_sz)) return -EFAULT;
    pr_info("stub: CHECK_VERSION_STR cmd=%u pid=%d comm=%s\n", chk_ver.cmd, current->pid, current->comm);
    chk_ver.reply = 1; /* NV_RM_API_VERSION_REPLY_RECOGNIZED */
    /* Set version string to match libcuda */
    memset(chk_ver.versionString, 0, sizeof(chk_ver.versionString));
    snprintf(chk_ver.versionString, sizeof(chk_ver.versionString), "595.84");
    if (copy_to_user(argp, &chk_ver, chk_sz)) return -EFAULT;
    return 0;
  }

/* ── UVM device ioctls (nvidia-uvm) — reply like the real driver ──
 * All UVM ioctls pass the params struct BY VALUE (copy_from_user(&params, arg, ...)
 * in uvm_api.h __UVM_ROUTE_CMD_STACK), except INITIALIZE/DEINITIALIZE. */
  case 1: { /* UVM_INITIALIZE (cmd 0x30000001): {flags IN, rmStatus OUT@8} 16 B */
    __u8 b[16];
    if (copy_from_user(b, argp, sizeof(b)) == 0) {
      unsigned long long flags = 0;
      memcpy(&flags, b, 8);
      pr_info("stub: UVM_INITIALIZE flags=0x%llx -> rmStatus=NV_OK\n", flags);
      memset(b + 8, 0, 4);  /* rmStatus = NV_OK */
      if (copy_to_user(argp, b, sizeof(b))) return -EFAULT;
    }
    return 0;
  }
  case 2: /* UVM_DEINITIALIZE: real driver returns 0 without copying anything */
    pr_info("stub: UVM_DEINITIALIZE\n");
    return 0;
  case 23: { /* UVM_CREATE_RANGE_GROUP: {rangeGroupId OUT@0, rmStatus OUT@8} 16 B */
    static unsigned long long rg_counter = 1;
    __u8 b[16];
    if (copy_from_user(b, argp, sizeof(b)) == 0) {
      memset(b, 0, sizeof(b));
      memcpy(b, &rg_counter, 8);
      pr_info("stub: UVM_CREATE_RANGE_GROUP -> id=%llu\n", rg_counter);
      if (copy_to_user(argp, b, sizeof(b))) return -EFAULT;
      rg_counter++;
    }
    return 0;
  }
  case 24: { /* UVM_DESTROY_RANGE_GROUP: {rangeGroupId IN@0, rmStatus OUT@8} 16 B */
    __u8 b[16];
    if (copy_from_user(b, argp, sizeof(b)) == 0) {
      unsigned long long id = 0;
      memcpy(&id, b, 8);
      pr_info("stub: UVM_DESTROY_RANGE_GROUP id=%llu -> rmStatus=NV_OK\n", id);
      memset(b + 8, 0, 4);
      if (copy_to_user(argp, b, sizeof(b))) return -EFAULT;
    }
    return 0;
  }
  case 37: { /* UVM_REGISTER_GPU: {uuid[16] IN/OUT, numaEnabled OUT@16, numaNodeId OUT@20,
               rmCtrlFd@24, hClient@28, hSmcPartRef@32, rmStatus OUT@36} 40 B */
    __u8 b[40];
    if (copy_from_user(b, argp, sizeof(b)) == 0) {
      __u32 rmCtrlFd = 0, hClient = 0, hSmc = 0;
      memcpy(&rmCtrlFd, b + 24, 4);
      memcpy(&hClient, b + 28, 4);
      memcpy(&hSmc, b + 32, 4);
      pr_info("stub: UVM_REGISTER_GPU uuid=%02x%02x%02x%02x-%02x%02x%02x%02x rmCtrlFd=%d hClient=0x%x hSmc=0x%x -> rmStatus=NV_OK\n",
              b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], rmCtrlFd, hClient, hSmc);
      memset(b + 16, 0, 4);  /* numaEnabled=0 */
      memset(b + 20, 0xff, 8);  /* numaNodeId = NV_UVM_NUMA_NODE_ID_INVALID (-1) */
      memset(b + 24, 0, 12); /* rmCtrlFd=0, hClient=0, hSmcPartRef=0 */
      memset(b + 36, 0, 4);  /* rmStatus = NV_OK */
      if (copy_to_user(argp, b, sizeof(b))) return -EFAULT;
    }
    return 0;
  }
  case 38: { /* UVM_UNREGISTER_GPU: {uuid IN@0, rmStatus OUT@16} 20 B */
    __u8 b[20];
    if (copy_from_user(b, argp, sizeof(b)) == 0) {
      pr_info("stub: UVM_UNREGISTER_GPU uuid=%02x%02x%02x%02x-%02x%02x%02x%02x -> rmStatus=NV_OK\n",
              b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
      memset(b + 16, 0, 4);
      if (copy_to_user(argp, b, sizeof(b))) return -EFAULT;
    }
    return 0;
  }
  case 39: { /* UVM_PAGEABLE_MEM_ACCESS: {pageableMemAccess OUT@0, rmStatus OUT@4} 8 B */
    __u8 b[8] = {1, 0, 0, 0, 0, 0, 0, 0}; /* pageableMemAccess=NV_TRUE, rmStatus=NV_OK */
    if (copy_to_user(argp, b, sizeof(b)) == 0)
      pr_info("stub: UVM_PAGEABLE_MEM_ACCESS -> supported=1\n");
    return 0;
  }
  case 70: { /* UVM_PAGEABLE_MEM_ACCESS_ON_GPU: {uuid IN@0, pageableMemAccess OUT@16,
               rmStatus OUT@20} 24 B */
    __u8 b[24];
    if (copy_from_user(b, argp, sizeof(b)) == 0) {
      pr_info("stub: UVM_PAGEABLE_ON_GPU uuid=%02x%02x%02x%02x-%02x%02x%02x%02x -> supported=1\n",
              b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
      memset(b + 16, 0, 8);  /* rmStatus=NV_OK */
      b[16] = 1;             /* pageableMemAccess=NV_TRUE (host returns 1) */
      b[16] = 1;
      if (copy_to_user(argp, b, sizeof(b))) return -EFAULT;
    }
    return 0;
  }
  case 75: { /* UVM_MM_INITIALIZE: {uvmFd IN@0, rmStatus OUT@4} 8 B */
    __u8 b[8];
    if (copy_from_user(b, argp, sizeof(b)) == 0) {
      __u32 fd = 0;
      memcpy(&fd, b, 4);
      pr_info("stub: UVM_MM_INITIALIZE uvmFd=%d -> rmStatus=NV_OK\n", fd);
      memset(b + 4, 0, 4);  /* rmStatus = NV_OK */
      if (copy_to_user(argp, b, sizeof(b))) return -EFAULT;
    }
    return 0;
  }

/* NVIF protocol — log everything (UVM ioctls with dedicated cases above are excluded) */
  case 3 ... 22:
  case 25 ... 36:
  case 40:
  case 44 ... 51:
  case 53 ... 56:
    pr_info("stub: NVIF silent nr=%d cmd=0x%x pid=%d comm=%s\n", nr, cmd, current->pid, current->comm);
    return 0;
  case 43: {
    /* NVOS64_PARAMETERS format (48 bytes):
     *  0: hRoot(NvHandle 4) 4: hObjectParent(4) 8: hObjectNew(4, OUT) 12: hClass(NvV32 4)
     * 16: pAllocParms(NvP64 8) 24: pRightsRequested(NvP64 8)
     * 32: paramsSize(NvU32 4) 36: flags(NvU32 4) 40: status(NvV32 4) 44: pad(4) */
    __u32 buf[48 / 4];
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(buf));
    if (copy_from_user(buf, argp, sz)) return -EFAULT;
    __u32 hRoot           = buf[0];
    __u32 hObjectParent   = buf[1];
    __u32 suggested_handle= buf[2];  /* hObjectNew (input, 0 = allocate new) */
    __u32 hClass          = buf[3];  /* bytes 12-15 */
    pr_info("stub: RM_ALLOC nr=%d cmd=0x%x sz=%u hRoot=0x%x hParent=0x%x hClass=0x%x suggested=0x%x\n",
            nr, cmd, sz, hRoot, hObjectParent, hClass, suggested_handle);
    {
      pr_info("stub: ALLOC-IN:");
      for (int __i = 0; __i < sz; __i++) printk(KERN_CONT " %02x", ((__u8*)buf)[__i]);
      printk(KERN_CONT "\n");
    }
    {
      /* DEBUG: dump the guest's params buffer (pAllocParms at bytes 16-23) */
      unsigned long parms_ptr = buf[4] | ((unsigned long)buf[5] << 32);
      __u8 pbuf[0x90];
      if (parms_ptr && !access_ok((void __user *)parms_ptr, sizeof(pbuf))) {
        pr_info("stub: ALLOC parms ptr=%px INVALID\n", (void *)parms_ptr);
      } else if (parms_ptr) {
        if (copy_from_user(pbuf, (void __user *)parms_ptr, sizeof(pbuf)) == 0) {
          pr_info("stub: ALLOC parms[0x90] @%px:", (void *)parms_ptr);
          for (int __j = 0; __j < (int)sizeof(pbuf); __j++)
            printk(KERN_CONT " %02x", pbuf[__j]);
          printk(KERN_CONT "\n");
          /* NV50A0 (VMM): the real kernel writes back, for every 0x50a0
           * alloc, parms[0x1c]=0x10000516 (u32) and parms[0x20]=0x00000600
           * (u32); for WINDOWED allocs (parms[0x08..0x0b] == 0x000ac505) it
           * additionally commits the VA-window: parms[0x50..0x57] = endVA
           * (a per-limit bump cursor starting at limit+1, decremented by
           * spatial-X per alloc) and parms[0x58..0x5b] = spatialX - 1.
           * Mirror it exactly (host 595.84 cuCtxCreate trace). */
          if (hClass == 0x50a0) {
            const __u8 wb_const[8] = { 0x16, 0x05, 0x00, 0x10, 0x00, 0x06, 0x00, 0x00 };
            const int windowed = (pbuf[0x08] == 0x05 && pbuf[0x09] == 0xc5);
            __u64 limit = 0, spx = 0, endva = 0, spxm1 = 0;
            memcpy(pbuf + 0x1c, wb_const, 4);
            memcpy(pbuf + 0x20, wb_const + 4, 4);
            if (windowed) {
              int idx = -1, free_idx = -1, i;
              memcpy(&limit, pbuf + 0x38, 8);
              memcpy(&spx, pbuf + 0x40, 8);
              mutex_lock(&rm_mutex);
              for (i = 0; i < NV50A0_CURSOR_ENTRIES; i++) {
                if (nv50a0_cur[i].limit == limit) { idx = i; break; }
                if (free_idx < 0 && nv50a0_cur[i].limit == 0) free_idx = i;
              }
              if (idx < 0) {
                idx = free_idx >= 0 ? free_idx : 0;
                nv50a0_cur[idx].limit = limit;
                nv50a0_cur[idx].cursor = limit + 1;
              }
              endva = nv50a0_cur[idx].cursor - spx;
              nv50a0_cur[idx].cursor = endva;
              mutex_unlock(&rm_mutex);
              spxm1 = spx - 1;
              memcpy(pbuf + 0x50, &endva, 8);
              memcpy(pbuf + 0x58, &spxm1, 4);
            }
            if (copy_to_user((void __user *)parms_ptr, pbuf, sizeof(pbuf)) == 0) {
              if (!windowed)
                pr_info("stub: ALLOC 0x50a0 write-back [0x1c]=0x%08x [0x20]=0x%08x\n",
                        *(const __u32 *)(pbuf + 0x1c), *(const __u32 *)(pbuf + 0x20));
              else
                pr_info("stub: ALLOC 0x50a0 write-back [0x1c]=0x%08x [0x20]=0x%08x windowed limit=0x%016llx endVA=0x%016llx spX-1=0x%016llx\n",
                        *(const __u32 *)(pbuf + 0x1c), *(const __u32 *)(pbuf + 0x20),
                        limit, endva, spxm1);
            }
          }
        }
      }
    }
    /* Use suggested handle if non-zero, else allocate new */
    __u32 new_handle = suggested_handle ? suggested_handle : stub_alloc_handle();
    /* Register the handle */
    __u32 out_class = hClass ? hClass : 0x41; /* NV01_ROOT_CLIENT for root */
    stub_add_handle(new_handle, hObjectParent, out_class);
    stub_alloc_handle_mem(new_handle, PAGE_SIZE);
    pr_info("stub: ALLOC handle=0x%x class=0x%x parent=0x%x\n", new_handle, out_class, hObjectParent);
    /* NVOS64 output */
    buf[2] = new_handle;        /* hObjectNew at bytes 8-11 */
    buf[10] = 0;                /* status at bytes 40-43 */
    pr_info("stub: ALLOC-OUT: hRoot=%08x hParent=%08x hNew=%08x hClass=%08x status=%u\n",
            buf[0], buf[1], buf[2], buf[3], buf[10]);
    if (copy_to_user(argp, buf, sz)) return -EFAULT;
    return 0;
  }
  case 42: {
    /* RM_CONTROL (NVOS54_PARAMETERS format)
     * 32 bytes: hClient(4) + hObject(4) + cmd(4) + status(4) +
     *           params(8) + paramsSize(4) + pad(4) */
    __u32 buf[8];
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(buf));
    if (copy_from_user(buf, argp, sz)) return -EFAULT;
    __u32 hClient = buf[0];
    __u32 hObject = buf[1];
    __u32 ctrl_cmd = buf[2];
    unsigned long params_ptr = buf[4] | ((unsigned long)buf[5] << 32);
    __u32 paramsSize = buf[6];
    pr_info("stub: RM_CONTROL nr=%d cmd=0x%x sz=%u hClient=0x%x hObject=0x%x ctrl_cmd=0x%x\n",
            nr, cmd, sz, hClient, hObject, ctrl_cmd);
    {
      pr_info("stub: CTRL hdr:");
      for (int __i = 0; __i < 32; __i++) printk(KERN_CONT " %02x", ((__u8*)buf)[__i]);
      printk(KERN_CONT "\n");
    }
    /* Dispatch through nvidia_rm_control for all commands */
    struct nv_os54_params p;
    p.hClient = hClient;
    p.hObject = hObject;
    p.cmd = ctrl_cmd;
    p.flags = buf[3];
    p.params = params_ptr;
    p.paramsSize = paramsSize;
    p.status = 0;
    return nvidia_rm_control(&p, argp, file->private_data);
  }
  case 41: {
    /* NV_ESC_RM_FREE — NVOS00_PARAMETERS (16 bytes):
     * hRoot(4) + hObjectParent(4) + hObjectOld(4) + status(4) */
    __u32 nvif_buf[16];
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(nvif_buf));
    if (copy_from_user(nvif_buf, argp, sz)) return -EFAULT;
    __u32 free_handle = nvif_buf[2]; /* hObjectOld = handle to free */
    pr_info("stub: RM_FREE cmd=0x%x handle=0x%x hRoot=0x%x hParent=0x%x pid=%d sz=%u\n",
            cmd, free_handle, nvif_buf[0], nvif_buf[1], current->pid, sz);
    nvif_buf[3] = 0; /* real driver always reports NV_OK here */
    if (copy_to_user(argp, nvif_buf, sz)) return -EFAULT;
    return 0;
  }
  case 78: { /* RM_MAP_MEMORY (new style) — registers the mmap context */
    __u8 dbuf[64];
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(dbuf));
    __u32 *w = (__u32 *)dbuf;
    if (copy_from_user(dbuf, argp, sz)) return -EFAULT;
    pr_info("stub: RM_MAP_MEMORY nr=78 sz=%u pid=%d words: %08x %08x %08x %08x | %08x %08x %08x %08x | %08x %08x %08x %08x | %08x %08x\n",
            sz, current->pid, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
            w[8], w[9], w[10], w[11], w[12], w[13]);
    return 0;
  }

  case 79: { /* RM_UNMAP_MEMORY (new style) */
    __u8 dbuf[64];
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(dbuf));
    __u32 *w = (__u32 *)dbuf;
    if (copy_from_user(dbuf, argp, sz)) return -EFAULT;
    pr_info("stub: RM_UNMAP_MEMORY nr=79 sz=%u pid=%d words: %08x %08x %08x %08x | %08x %08x %08x %08x\n",
            sz, current->pid, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
    return 0;
  }

  case 94: { /* nr=0x5e cmd=0xc028465e sz=40 — RM_MAP_MEMORY_DMA-ish: issued
                right after mmap of the RM shared-memory region; passes
                {hClient,hDevice,hDma,pad,offset=0,flags,dmaOffset=mmap VA,pad}
                — real driver pins the pages at the VA and returns 0. */
    __u8 dbuf[64];
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(dbuf));
    if (copy_from_user(dbuf, argp, sz)) return -EFAULT;
    pr_info("stub: MAP_MEMORY_DMA nr=94 sz=%u pid=%d words: %08x %08x %08x %08x | %08x %08x %08x %08x | %08x %08x\n",
            sz, current->pid, *(u32 *)(dbuf + 0), *(u32 *)(dbuf + 4), *(u32 *)(dbuf + 8),
            *(u32 *)(dbuf + 12), *(u32 *)(dbuf + 16), *(u32 *)(dbuf + 20), *(u32 *)(dbuf + 24),
            *(u32 *)(dbuf + 28), *(u32 *)(dbuf + 32), *(u32 *)(dbuf + 36));
    if (copy_to_user(argp, dbuf, sz)) return -EFAULT;
    return 0;
  }

  case 82: { /* NV_ESC_RM_GET_EVENT_DATA — NVOS41_PARAMETERS
                { pEvent(8), MoreEvents(4), status(4) }; pEvent points to
                an NvUnixEvent { hObject, NotifyIndex, info32, info16 }.
                Mirrors real get_os_event_data()/nv_get_event(). */
    struct stub_file_event *s = file->private_data;
    struct { __u64 pEvent; __u32 MoreEvents; __u32 status; } p;
    if (copy_from_user(&p, argp, sizeof(p))) return -EFAULT;
    if (s && s->ev_queued) {
      struct { __u32 hObject; __u32 NotifyIndex; __u32 info32; __u16 info16; } ev;
      s->ev_queued = false;
      p.MoreEvents = 0;
      p.status = 0;
      ev.hObject = s->ev_hObject;
      ev.NotifyIndex = s->ev_notifyIndex;
      ev.info32 = s->ev_info32;
      ev.info16 = s->ev_info16;
      if (p.pEvent &&
          copy_to_user((void __user *)(unsigned long)p.pEvent, &ev, sizeof(ev)))
        return -EFAULT;
      pr_info("stub: RM_GET_EVENT_DATA hObject=0x%x idx=%u\n",
              ev.hObject, ev.NotifyIndex);
    } else {
      p.MoreEvents = 0;
      p.status = 0x67; /* NV_ERR_OPERATING_SYSTEM (no event) */
    }
    if (copy_to_user(argp, &p, sizeof(p))) return -EFAULT;
    return 0;
  }

  case 58 ... 64:
  case 66 ... 69:
  case 71 ... 73:
  case 76:
  case 80 ... 81:
  case 83:
  case 85 ... 86:
  case 90 ... 93:
  case 96 ... 127:
    pr_info("stub: NVIF unknown nr=%d cmd=0x%x dir=%d type=%d sz=%d pid=%d comm=%s\n",
            nr, cmd, _IOC_DIR(cmd), _IOC_TYPE(cmd), _IOC_SIZE(cmd),
            current->pid, current->comm);
    return 0;

  case NV_ESC_SYS_PARAMS_NR: {
    __u64 *sys_params = (__u64 __user *)argp;
    __u64 val = 0x08000000ULL;  /* real driver: 0x08000000 */
    if (copy_to_user(sys_params, &val, sizeof(val)))
      return -EFAULT;
    return 0;
  }

  case NV_ESC_NUMA_INFO_NR: {  /* 215 */
    /* nv_ioctl_numa_info_t — match real driver response */
    struct {
      __s32 nid;
      __s32 status;
      __u64 memblock_size;
      __u64 numa_mem_addr;
      __u64 numa_mem_size;
      __u8  use_auto_online;
      __u8  pad[7];
      __u64 offline_addresses[64];
      __u32 numEntries;
    } __attribute__((aligned(8))) numa;
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(numa));
    memset(&numa, 0, sizeof(numa));
    numa.nid = -1;
    numa.status = 0; /* NV_IOCTL_NUMA_STATUS_DISABLED */
    numa.memblock_size = 0x08000000ULL;
    pr_info("stub: NUMA_INFO pid=%d comm=%s sz=%u\n", current->pid, current->comm, sz);
    if (copy_to_user(argp, &numa, sz))
      return -EFAULT;
    return 0;
  }

  case NV_ESC_ATTACH_GPUS_TO_FD_NR: {  /* 212 */
    /* real driver just records the NvU32 array of minors; nothing to do */
    pr_info("stub: ATTACH_GPUS_TO_FD pid=%d comm=%s\n", current->pid, current->comm);
    return 0;
  }

  case NV_ESC_ALLOC_OS_EVENT_NR: {  /* 206 */
    /* nv_ioctl_alloc_os_event_t { hClient, hDevice, fd, Status } — the
     * real driver just RECORDS the (hParent=hClient, fd) pair (fd is the
     * UMD's own device fd, an RM-side token); notifications are delivered
     * via the device fd poll. Return success for first registration. */
    struct { __u32 hClient; __u32 hDevice; __u32 fd; __u32 Status; } ev;
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(ev));
    int i;
    bool dup = false;
    if (copy_from_user(&ev, argp, sz)) return -EFAULT;
    for (i = 0; i < MAX_EVFD; i++)
      if (g_evfds[i] && g_evfds[i]->hParent == ev.hClient &&
          g_evfds[i]->fd == (int)ev.fd)
        dup = true;
    if (!dup) {
      for (i = 0; i < MAX_EVFD; i++)
        if (!g_evfds[i])
          break;
      if (i < MAX_EVFD) {
        struct stub_evfd *e = kzalloc(sizeof(*e), GFP_KERNEL);
        if (e) {
          e->hParent = ev.hClient;
          e->fd = (int)ev.fd;
          g_evfds[i] = e;
        }
      }
    }
    ev.Status = 0;
    {
      /* Identify the registered fd's backing file for diagnostics. */
      struct file *evf = fget((int)ev.fd);
      if (evf) {
        char *p = (char *)__getname();
        if (p) {
          char *r = d_path(&evf->f_path, p, PATH_MAX);
          pr_info("stub: ALLOC_OS_EVENT hClient=0x%x hDevice=0x%x fd=%d -> %s status=0x%x pid=%d\n",
                  ev.hClient, ev.hDevice, ev.fd, r ? r : "?", ev.Status, current->pid);
          __putname(p);
        } else {
          pr_info("stub: ALLOC_OS_EVENT hClient=0x%x hDevice=0x%x fd=%d status=0x%x pid=%d\n",
                  ev.hClient, ev.hDevice, ev.fd, ev.Status, current->pid);
        }
        fput(evf);
      } else {
        pr_info("stub: ALLOC_OS_EVENT hClient=0x%x hDevice=0x%x fd=%d (no file) status=0x%x pid=%d\n",
                ev.hClient, ev.hDevice, ev.fd, ev.Status, current->pid);
      }
    }
    if (copy_to_user(argp, &ev, sz)) return -EFAULT;
    return 0;
  }

  case NV_ESC_FREE_OS_EVENT_NR: {  /* 207 */
    struct { __u32 hClient; __u32 hDevice; __u32 fd; __u32 Status; } ev;
    unsigned int sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(ev));
    int i;
    if (copy_from_user(&ev, argp, sz)) return -EFAULT;
    for (i = 0; i < MAX_EVFD; i++)
      if (g_evfds[i] && g_evfds[i]->hParent == ev.hClient &&
          g_evfds[i]->fd == (int)ev.fd) {
        kfree(g_evfds[i]);
        g_evfds[i] = NULL;
        break;
      }
    ev.Status = 0;
    pr_info("stub: FREE_OS_EVENT hClient=0x%x hDevice=0x%x fd=%d pid=%d\n",
            ev.hClient, ev.hDevice, ev.fd, current->pid);
    if (copy_to_user(argp, &ev, sz)) return -EFAULT;
    return 0;
  }

  case NV_ESC_RM_ALLOC_NR:
  case NV_ESC_RM_ALLOC_OBJECT_NR: {
    struct nv_os21_params p;
    int ret;
    if (copy_from_user(&p, argp, sizeof(p)))
      return -EFAULT;
    pr_info("stub: RM_ALLOC hClass=0x%x parent=0x%x root=0x%x pid=%d comm=%s\n",
            p.hClass, p.hObjectParent, p.hRoot, current->pid, current->comm);
    ret = nvidia_rm_alloc(&p);
    if (copy_to_user(argp, &p, sizeof(p)))
      return -EFAULT;
    return ret;
  }

  case NV_ESC_RM_CONTROL_NR: {
    struct nv_os54_params p;
    if (copy_from_user(&p, argp, sizeof(p)))
      return -EFAULT;
    pr_info("stub: RM_CONTROL cmd=0x%x hClient=0x%x hObject=0x%x pid=%d comm=%s\n",
            p.cmd, p.hClient, p.hObject, current->pid, current->comm);
    return nvidia_rm_control(&p, argp, file->private_data);
  }

  case NV_ESC_RM_FREE_NR:
    pr_info("stub: RM_FREE\n");
    return 0;

  case NV_ESC_RM_MAP_MEMORY_NR:
  case NV_ESC_RM_MAP_MEMORY_DMA_NR: {
    struct nv_os33_params_with_fd map_p;
    unsigned int buf_sz = min_t(size_t, _IOC_SIZE(cmd), sizeof(map_p));
    if (buf_sz > 0) {
      if (copy_from_user(&map_p, argp, buf_sz)) return -EFAULT;
      map_p.status = 0;
      if (copy_to_user(argp, &map_p, buf_sz)) return -EFAULT;
    }
    return 0;
  }

  case NV_ESC_RM_UNMAP_MEMORY_NR:
    pr_info("stub: RM_UNMAP_MEMORY pid=%d\n", current->pid);
    return 0;

  case NV_ESC_RM_DUP_OBJECT_NR:
    pr_info("stub: RM_DUP_OBJECT pid=%d\n", current->pid);
    return 0;

  default:
    pr_info("stub: UNKNOWN ioctl cmd=0x%x nr=0x%x type=0x%x pid=%d comm=%s\n", cmd, nr, _IOC_TYPE(cmd), current->pid, current->comm);
    return -ENOTTY;
  }
}

static struct file_operations nvidia_fops = {
  .owner   = THIS_MODULE,
  .open    = nvidia_open,
  .release = nvidia_release,
  .read    = nvidia_read,
  .poll    = nvidia_poll,
  .mmap    = nvidia_mmap,
  .unlocked_ioctl = nvidia_ioctl,
};

/* ── nvidia_get_rm_ops stub for nvidia-modeset.ko ── */

struct nvidia_stack_s;
typedef struct nvidia_stack_s *nvidia_modeset_stack_ptr;
typedef void (*rm_op_func_t)(nvidia_modeset_stack_ptr sp, void *ops_cmd);

struct nv_gpu_info {
  __u32 gpu_id;
};

struct nvidia_modeset_callbacks {
  void (*suspend)(__u32 gpu_id);
  void (*resume)(__u32 gpu_id);
  void (*remove)(__u32 gpu_id);
  void (*probe)(const struct nv_gpu_info *gpu_info);
};

struct nvidia_modeset_rm_ops {
  const char *version_string;
  struct { int allow_write_combining; } system_info;
  int (*alloc_stack)(nvidia_modeset_stack_ptr *sp);
  void (*free_stack)(nvidia_modeset_stack_ptr sp);
  __u32 (*enumerate_gpus)(struct nv_gpu_info *gpu_info);
  int (*open_gpu)(__u32 gpu_id, nvidia_modeset_stack_ptr sp, int reset_aware);
  void (*close_gpu)(__u32 gpu_id, nvidia_modeset_stack_ptr sp, int reset_aware);
  rm_op_func_t op;
  int (*set_callbacks)(const struct nvidia_modeset_callbacks *cb);
};

static int stub_alloc_stack(nvidia_modeset_stack_ptr *sp) { *sp = NULL; return 0; }
static void stub_free_stack(nvidia_modeset_stack_ptr sp) { }
static __u32 stub_enumerate_gpus(struct nv_gpu_info *gpu_info) { return 0; }
static int stub_open_gpu(__u32 gpu_id, nvidia_modeset_stack_ptr sp, int reset_aware) { return 0; }
static void stub_close_gpu(__u32 gpu_id, nvidia_modeset_stack_ptr sp, int reset_aware) { }
static void stub_op(nvidia_modeset_stack_ptr sp, void *ops_cmd) { }
static int stub_set_callbacks(const struct nvidia_modeset_callbacks *cb) { return 0; }

__u32 nvidia_get_rm_ops(struct nvidia_modeset_rm_ops *rm_ops) {
  if (!rm_ops) return 1;
  rm_ops->version_string = "595.71.05";
  rm_ops->system_info.allow_write_combining = 0;
  rm_ops->alloc_stack = stub_alloc_stack;
  rm_ops->free_stack = stub_free_stack;
  rm_ops->enumerate_gpus = stub_enumerate_gpus;
  rm_ops->open_gpu = stub_open_gpu;
  rm_ops->close_gpu = stub_close_gpu;
  rm_ops->op = stub_op;
  rm_ops->set_callbacks = stub_set_callbacks;
  return 0;
}
EXPORT_SYMBOL(nvidia_get_rm_ops);

/* ── PCI stub — match any NVIDIA device, claim it, register a /dev/nvidiaN ── */

#define MAX_PCI_GPUS 8

struct pci_gpu {
  struct pci_dev *pdev;
  int minor;
  dev_t dev;
  struct cdev cdev;
  struct device *device;
  struct proc_dir_entry *proc_gpu_dir;
};

static struct pci_gpu pci_gpus[MAX_PCI_GPUS];
static int num_pci_gpus;
static struct class *nvidia_front_class;

/* Called once per probed NVIDIA device */
static int stub_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
  int idx, ret;
  dev_t devno;

  pr_info("stub/pci: probe 0x%x:0x%x @ %04x:%02x:%02x.%d\n",
          id ? id->vendor : 0, id ? id->device : 0,
          pci_domain_nr(pdev->bus), pdev->bus->number,
          PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

  if (num_pci_gpus >= MAX_PCI_GPUS)
    return -ENODEV;
  idx = num_pci_gpus++;

  ret = pcim_enable_device(pdev);
  if (ret < 0) return ret;
  pci_set_master(pdev);
  if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64)))
    return -EIO;

  /* Use minor = idx (0-based, minor 255 is reserved for control) */
  devno = MKDEV(MAJOR(nvidia_dev), idx);
  cdev_init(&pci_gpus[idx].cdev, &nvidia_fops);
  pci_gpus[idx].cdev.owner = THIS_MODULE;
  ret = cdev_add(&pci_gpus[idx].cdev, devno, 1);
  if (ret < 0) return ret;

  pci_gpus[idx].device = device_create(nvidia_front_class, NULL, devno, NULL,
                                        "nvidia%d", idx);
  if (IS_ERR(pci_gpus[idx].device))
    return PTR_ERR(pci_gpus[idx].device);

  pci_gpus[idx].pdev = pdev;
  pci_gpus[idx].minor = idx;
  pci_set_drvdata(pdev, &pci_gpus[idx]);

  /* Create /proc/driver/nvidia/gpus/XXXX:XX:XX.X/ entry */
  if (nvidia_proc_gpus) {
    char gpu_name[32];
    snprintf(gpu_name, sizeof(gpu_name), "%04x:%02x:%02x.%d",
             pci_domain_nr(pdev->bus), pdev->bus->number,
             PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
    pci_gpus[idx].proc_gpu_dir = proc_mkdir(gpu_name, nvidia_proc_gpus);
    if (pci_gpus[idx].proc_gpu_dir) {
      proc_create("numa_status", 0444, pci_gpus[idx].proc_gpu_dir, &nvidia_proc_params_fops);
      proc_create("information", 0444, pci_gpus[idx].proc_gpu_dir, &nvidia_proc_params_fops);
      proc_create("power", 0444, pci_gpus[idx].proc_gpu_dir, &nvidia_proc_params_fops);
    }
  }

  return 0;
}

static void stub_pci_remove(struct pci_dev *pdev)
{
  struct pci_gpu *gpu = pci_get_drvdata(pdev);
  if (!gpu) return;
  if (gpu->proc_gpu_dir) {
    remove_proc_entry("numa_status", gpu->proc_gpu_dir);
    remove_proc_entry("information", gpu->proc_gpu_dir);
    remove_proc_entry("power", gpu->proc_gpu_dir);
  }
  if (gpu->proc_gpu_dir && nvidia_proc_gpus) {
    char gpu_name[32];
    snprintf(gpu_name, sizeof(gpu_name), "%04x:%02x:%02x.%d",
             pci_domain_nr(pdev->bus), pdev->bus->number,
             PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
    remove_proc_entry(gpu_name, nvidia_proc_gpus);
  }
  device_destroy(nvidia_front_class, gpu->cdev.dev);
  cdev_del(&gpu->cdev);
}

static const struct pci_device_id stub_pci_table[] = {
  { PCI_DEVICE(PCI_VENDOR_ID_NVIDIA, PCI_ANY_ID) },
  {}
};
MODULE_DEVICE_TABLE(pci, stub_pci_table);

static struct pci_driver stub_pci_driver = {
  .name     = "nvidia",
  .id_table = stub_pci_table,
  .probe    = stub_pci_probe,
  .remove   = stub_pci_remove,
};

/* ── module init / exit ── */

static dev_t nvidia_uvm_dev;
static struct cdev nvidia_uvm_cdev;
static struct class *nvidia_uvm_class;

/* Major 195 is assigned to NVIDIA by the Linux kernel */
#define NVIDIA_MAJOR 195

static int __init nvidia_init(void)
{
  int ret;
  dev_t dev;

  INIT_DELAYED_WORK(&g_fab_work, fab_work_fn);

  /* Register at fixed major 195, matching the real NVIDIA driver.
   * Use non-overlapping ranges: minors 0-247 for GPUs, minor 255 for nvidiactl.
   * (Minor 254 is reserved for nvidia-modeset) */
  ret = register_chrdev_region(MKDEV(NVIDIA_MAJOR, 0), 248, "nvidia");
  if (ret == 0) {
    nvidia_dev = MKDEV(NVIDIA_MAJOR, 0);
    /* Register nvidiactl at minor 255 with its own /proc/devices entry */
    register_chrdev_region(MKDEV(NVIDIA_MAJOR, 255), 1, "nvidiactl");
  } else {
    /* Fallback to dynamic allocation if 195 is already taken */
    ret = alloc_chrdev_region(&dev, 0, 256, "nvidia");
    if (ret < 0) return ret;
    nvidia_dev = dev;
  }

  /* /sys/class/nvidia */
  nvidia_class = class_create("nvidia");
  if (IS_ERR(nvidia_class)) {
    ret = PTR_ERR(nvidia_class);
    goto fail_class;
  }

  /* /sys/class/nvidia-frontend */
  nvidia_front_class = class_create("nvidia-frontend");
  if (IS_ERR(nvidia_front_class)) {
    ret = PTR_ERR(nvidia_front_class);
    goto fail_front_class;
  }

  /* Control device: minor 255 (NVIDIA convention) */
  cdev_init(&nvidia_cdev, &nvidia_fops);
  nvidia_cdev.owner = THIS_MODULE;
  ret = cdev_add(&nvidia_cdev, MKDEV(MAJOR(nvidia_dev), 255), 1);
  if (ret < 0) goto fail_cdev;
  device_create(nvidia_class, NULL, MKDEV(MAJOR(nvidia_dev), 255), NULL, "nvidiactl");

  /* UVM stub device: separate class, separate major */
  ret = alloc_chrdev_region(&nvidia_uvm_dev, 0, 1, "nvidia-uvm");
  if (ret < 0) goto fail_uvm_region;
  nvidia_uvm_class = class_create("nvidia-uvm");
  if (IS_ERR(nvidia_uvm_class)) {
    ret = PTR_ERR(nvidia_uvm_class);
    goto fail_uvm_class;
  }
  cdev_init(&nvidia_uvm_cdev, &nvidia_fops);
  nvidia_uvm_cdev.owner = THIS_MODULE;
  ret = cdev_add(&nvidia_uvm_cdev, nvidia_uvm_dev, 1);
  if (ret < 0) goto fail_uvm_cdev;
  device_create(nvidia_uvm_class, NULL, nvidia_uvm_dev, NULL, "nvidia-uvm");

  /* /proc/driver/nvidia/ directory */
  nvidia_proc_dir = proc_mkdir("driver/nvidia", NULL);
  if (nvidia_proc_dir) {
    nvidia_proc_gpus = proc_mkdir("gpus", nvidia_proc_dir);
    nvidia_proc_params = proc_create("params", 0444, nvidia_proc_dir, &nvidia_proc_params_fops);
    proc_create("version", 0444, nvidia_proc_dir, &nvidia_proc_version_fops);
    nvidia_proc_caps = proc_mkdir("capabilities", nvidia_proc_dir);
    if (nvidia_proc_caps) {
      proc_create("fabric-imex-mgmt", 0444, nvidia_proc_caps, &nvidia_proc_params_fops);
      nvidia_proc_caps_mig = proc_mkdir("mig", nvidia_proc_caps);
      if (nvidia_proc_caps_mig) {
        proc_create("config", 0444, nvidia_proc_caps_mig, &nvidia_proc_params_fops);
        proc_create("monitor", 0444, nvidia_proc_caps_mig, &nvidia_proc_params_fops);
      }
    }
  }

  /* Claim any NVIDIA GPU via PCI stub */
  ret = pci_register_driver(&stub_pci_driver);
  if (ret < 0) goto fail_pci;

  /* Scan PCI bus and manually probe non-display NVIDIA devices */
  {
    struct pci_dev *pdev = NULL;
    while ((pdev = pci_get_device(PCI_VENDOR_ID_NVIDIA, PCI_ANY_ID, pdev))) {
      if ((pdev->class >> 16) == 0x03) {
        pr_info("stub: display device %s driver=%s, not unbinding\n",
                dev_name(&pdev->dev), pdev->driver ? pdev->driver->name : "none");
        continue;
      }
      if (pdev->driver) {
        pr_info("stub: NV dev %s already bound to %s\n",
                dev_name(&pdev->dev), pdev->driver->name);
        continue;
      }
      pr_info("stub: found NV dev %s class=0x%06x, probing directly\n",
              dev_name(&pdev->dev), pdev->class);
      device_set_driver_override(&pdev->dev, "nvidia");
      stub_pci_probe(pdev, NULL);
    }
  }

  pr_info("stub: nvidia stub loaded (major=%d)\n", MAJOR(nvidia_dev));
  return 0;

fail_pci:
  /* cleanup procfs, uvm, cdev, classes, regions in reverse order */
  if (nvidia_proc_caps) {
    if (nvidia_proc_caps_mig) {
      remove_proc_entry("config", nvidia_proc_caps_mig);
      remove_proc_entry("monitor", nvidia_proc_caps_mig);
    }
    remove_proc_entry("mig", nvidia_proc_caps);
    remove_proc_entry("fabric-imex-mgmt", nvidia_proc_caps);
  }
  remove_proc_entry("capabilities", nvidia_proc_dir);
  if (nvidia_proc_params) remove_proc_entry("params", nvidia_proc_dir);
  remove_proc_entry("version", nvidia_proc_dir);
  if (nvidia_proc_gpus) remove_proc_entry("gpus", nvidia_proc_dir);
  if (nvidia_proc_dir) remove_proc_entry("driver/nvidia", NULL);
fail_uvm_cdev:
  device_destroy(nvidia_uvm_class, nvidia_uvm_dev);
  cdev_del(&nvidia_uvm_cdev);
fail_uvm_class:
  class_destroy(nvidia_uvm_class);
fail_uvm_region:
  unregister_chrdev_region(nvidia_uvm_dev, 1);
fail_cdev:
  device_destroy(nvidia_class, MKDEV(MAJOR(nvidia_dev), 255));
  cdev_del(&nvidia_cdev);
fail_front_class:
  class_destroy(nvidia_front_class);
fail_class:
  class_destroy(nvidia_class);
  if (MAJOR(nvidia_dev) == NVIDIA_MAJOR) {
    unregister_chrdev_region(MKDEV(MAJOR(nvidia_dev), 255), 1);
    unregister_chrdev_region(nvidia_dev, 248);
  } else {
    unregister_chrdev_region(nvidia_dev, 256);
  }
  return ret;
}

static void __exit nvidia_exit(void)
{
  int i;
  cancel_delayed_work_sync(&g_fab_work);
  pci_unregister_driver(&stub_pci_driver);
  for (i = 0; i < num_pci_gpus; i++) {
    device_destroy(nvidia_front_class, pci_gpus[i].cdev.dev);
    cdev_del(&pci_gpus[i].cdev);
  }
  device_destroy(nvidia_uvm_class, nvidia_uvm_dev);
  cdev_del(&nvidia_uvm_cdev);
  class_destroy(nvidia_uvm_class);
  unregister_chrdev_region(nvidia_uvm_dev, 1);
  if (nvidia_proc_caps) {
    if (nvidia_proc_caps_mig) {
      remove_proc_entry("config", nvidia_proc_caps_mig);
      remove_proc_entry("monitor", nvidia_proc_caps_mig);
    }
    remove_proc_entry("mig", nvidia_proc_caps);
    remove_proc_entry("fabric-imex-mgmt", nvidia_proc_caps);
  }
  remove_proc_entry("capabilities", nvidia_proc_dir);
  if (nvidia_proc_params) remove_proc_entry("params", nvidia_proc_dir);
  remove_proc_entry("version", nvidia_proc_dir);
  if (nvidia_proc_gpus) remove_proc_entry("gpus", nvidia_proc_dir);
  if (nvidia_proc_dir) remove_proc_entry("driver/nvidia", NULL);
  device_destroy(nvidia_class, MKDEV(MAJOR(nvidia_dev), 255));
  cdev_del(&nvidia_cdev);
  class_destroy(nvidia_front_class);
  class_destroy(nvidia_class);
  if (MAJOR(nvidia_dev) == NVIDIA_MAJOR) {
    unregister_chrdev_region(MKDEV(MAJOR(nvidia_dev), 255), 1);
    unregister_chrdev_region(nvidia_dev, 248);
  } else {
    unregister_chrdev_region(nvidia_dev, 256);
  }

  /* Free any remaining handle memory */
  {
    struct rm_handle *pos, *tmp;
    list_for_each_entry_safe(pos, tmp, &rm_handles, list) {
      if (pos->mem) free_page((unsigned long)pos->mem);
      kfree(pos);
    }
  }
  pr_info("stub: nvidia stub unloaded\n");
}

module_init(nvidia_init);
module_exit(nvidia_exit);
