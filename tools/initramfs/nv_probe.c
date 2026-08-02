#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <errno.h>

#define NV_MAJOR 195
#define NVIDIA_CTL_MINOR 255

struct nv_ioctl_card_info {
  unsigned int gpu_id;
  unsigned int valid;
  unsigned int pci_device_id;
  unsigned int pci_vendor_id;
  unsigned int pci_subsystem_id;
  unsigned int pci_revision;
  unsigned char interrupt_line;
  unsigned char reserved[3];
  unsigned long long reg_address;
  unsigned long long reg_size;
  unsigned long long fb_address;
  unsigned long long fb_size;
  unsigned int minor_number;
  unsigned char dev_name[10];
};

struct nv_ioctl_register_fd {
  int ctl_fd;
};

#define NV_ESC_CARD_INFO_NR   200
#define NV_ESC_REGISTER_FD_NR 201

/* CUDA typedefs */
typedef void *CUdevice;
typedef int CUresult;
typedef unsigned int CUdevice_v1;

#define CUDA_SUCCESS 0
#define CUDA_ERROR_NO_DEVICE 100

int main(void) {
  int ctl_fd, dev_fd;

  printf("=== NV PROBE ===\n"); fflush(stdout);

  /* Step 1: Open /dev/nvidiactl */
  ctl_fd = open("/dev/nvidiactl", O_RDWR);
  if (ctl_fd < 0) {
    printf("CTL_OPEN_FAIL errno=%d\n", errno); fflush(stdout);
    return 1;
  }
  printf("CTL_OPEN_OK fd=%d\n", ctl_fd); fflush(stdout);

  /* Step 2: NV_ESC_CARD_INFO */
  {
    struct nv_ioctl_card_info info;
    memset(&info, 0, sizeof(info));
    int ret = ioctl(ctl_fd, _IOWR('N', NV_ESC_CARD_INFO_NR, struct nv_ioctl_card_info), &info);
    printf("CARD_INFO ret=%d errno=%d gpu_id=%u valid=%u pci_dev=0x%x pci_ven=0x%x minor=%u\n",
           ret, errno, info.gpu_id, info.valid, info.pci_device_id, info.pci_vendor_id, info.minor_number);
    fflush(stdout);
  }

  /* Step 3: Open /dev/nvidia0 */
  dev_fd = open("/dev/nvidia0", O_RDWR);
  if (dev_fd < 0) {
    printf("DEV0_OPEN_FAIL errno=%d\n", errno); fflush(stdout);
  } else {
    printf("DEV0_OPEN_OK fd=%d\n", dev_fd); fflush(stdout);
  }

  /* Step 4: NV_ESC_REGISTER_FD (associate /dev/nvidia0 with ctl) */
  {
    struct nv_ioctl_register_fd reg;
    reg.ctl_fd = ctl_fd;
    int ret = ioctl(dev_fd, _IOWR('N', NV_ESC_REGISTER_FD_NR, struct nv_ioctl_register_fd), &reg);
    printf("REGISTER_FD ret=%d errno=%d\n", ret, errno);
    fflush(stdout);
  }

  /* Step 5: Load libcuda.so */
  void *cuda_lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_GLOBAL);
  if (!cuda_lib) {
    printf("CUDA_DLOPEN_FAIL: %s\n", dlerror()); fflush(stdout);
    /* Try alternate name */
    cuda_lib = dlopen("libcuda.so", RTLD_NOW | RTLD_GLOBAL);
  }
  if (!cuda_lib) {
    printf("CUDA_DLOPEN_FAIL2: %s\n", dlerror()); fflush(stdout);
    return 1;
  }
  printf("CUDA_DLOPEN_OK\n"); fflush(stdout);

  /* Step 6: Call cuInit(0) */
  CUresult (*cuInit_p)(unsigned int) = dlsym(cuda_lib, "cuInit");
  if (!cuInit_p) {
    printf("CUDA_DLSYM_FAIL cuInit: %s\n", dlerror()); fflush(stdout);
    return 1;
  }
  printf("CUDA_cuInit_addr %p\n", cuInit_p); fflush(stdout);

  CUresult res = cuInit_p(0);
  printf("CUDA_cuInit ret=%d\n", (int)res); fflush(stdout);

  /* Step 7: cuDeviceGetCount */
  if (res == CUDA_SUCCESS) {
    CUresult (*cuDeviceGetCount_p)(int *) = dlsym(cuda_lib, "cuDeviceGetCount");
    if (cuDeviceGetCount_p) {
      int count = -1;
      res = cuDeviceGetCount_p(&count);
      printf("CUDA_DEV_COUNT ret=%d count=%d\n", (int)res, count);
      fflush(stdout);
    }
  }

  /* Step 8: cuDeviceGet */
  if (res == CUDA_SUCCESS) {
    CUresult (*cuDeviceGet_p)(CUdevice *, CUdevice_v1) = dlsym(cuda_lib, "cuDeviceGet");
    if (cuDeviceGet_p) {
      CUdevice dev;
      res = cuDeviceGet_p(&dev, 0);
      printf("CUDA_DEV_GET ret=%d\n", (int)res);
      fflush(stdout);
    }
  }

  /* Step 9: cuDeviceGetName */
  {
    CUresult (*cuDeviceGetName_p)(char *, int, CUdevice) = dlsym(cuda_lib, "cuDeviceGetName");
    if (cuDeviceGetName_p) {
      CUdevice dev;
      CUresult (*cuDeviceGet_p)(CUdevice *, CUdevice_v1) = dlsym(cuda_lib, "cuDeviceGet");
      if (cuDeviceGet_p && cuDeviceGet_p(&dev, 0) == CUDA_SUCCESS) {
        char name[128];
        res = cuDeviceGetName_p(name, sizeof(name), dev);
        printf("CUDA_DEV_NAME ret=%d name='%s'\n", (int)res, res == CUDA_SUCCESS ? name : "?");
        fflush(stdout);
      }
    }
  }

  dlclose(cuda_lib);
  close(dev_fd);
  close(ctl_fd);

  printf("=== NV PROBE END ===\n"); fflush(stdout);
  return 0;
}
