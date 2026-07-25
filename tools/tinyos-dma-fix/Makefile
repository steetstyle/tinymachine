#
# Makefile — tinyos-dma-fix kernel module
# Usage: make
#   or: make KDIR=/lib/modules/$(uname -r)/build
#

# Default kernel source tree
KDIR ?= /lib/modules/$(shell uname -r)/build

# Module name
obj-m += tinyos_dma_fix.o

# Verbose: V=1 for full output
export KBUILD_VERBOSE ?= 0

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules KBUILD_VERBOSE=$(KBUILD_VERBOSE)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod

# Convenience target: load with defaults (0000:01:00.0)
load:
	-sudo rmmod tinyos_dma_fix 2>/dev/null; true
	sudo insmod tinyos_dma_fix.ko domain=$(DOMAIN) bus=$(BUS) slot=$(SLOT) func=$(FUNC)

unload:
	-sudo rmmod tinyos_dma_fix 2>/dev/null; true

# Check dma_mask_bits after loading
check:
	@echo "dma_mask_bits for 0000:01:00.0:"
	@cat /sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0/dma_mask_bits 2>/dev/null || echo "device not found"
	@echo ""
	@echo "kernel messages:"
	@dmesg | tail -20 | grep -i "tinyos-dma-fix\|dma_mask" || echo "(no recent messages)"

.PHONY: all clean install load unload check
