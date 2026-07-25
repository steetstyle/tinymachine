// SPDX-License-Identifier: GPL-2.0-only
/* tinyos_dma_fix.c — Force NVIDIA GPU to D0 and set dma_mask=64
 *
 * Fixes VFIO dma_mask_bits=32 issue when GPU is in D3cold at boot.
 * vfio-pci never calls dma_set_mask(), so the PCI default of 32-bit
 * persists even after the device is transitioned to D0.
 *
 * Usage:
 *   sudo insmod tinyos_dma_fix.ko domain=0 bus=1 slot=0 func=0
 *   cat /sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0/dma_mask_bits
 *   # Should now show 64
 *
 * Then rebind vfio-pci (if not already bound):
 *   echo "0000:01:00.0" > /sys/bus/pci/drivers/vfio-pci/unbind
 *   echo "0000:01:00.0" > /sys/bus/pci/drivers/vfio-pci/bind
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/version.h>

/* Module parameters — default = AD104 at 0000:01:00.0 */
static int domain = 0;
static int bus = 1;
static int slot = 0;
static int func = 0;
static int verbose = 1;

module_param(domain, int, 0);
module_param(bus, int, 0);
module_param(slot, int, 0);
module_param(func, int, 0);
module_param(verbose, int, 0);

MODULE_PARM_DESC(domain, "PCI domain (default 0)");
MODULE_PARM_DESC(bus, "PCI bus (default 1)");
MODULE_PARM_DESC(slot, "PCI slot (default 0)");
MODULE_PARM_DESC(func, "PCI function (default 0)");
MODULE_PARM_DESC(verbose, "Verbose logging (default 1)");

/* Report current DMA mask in bits (e.g., 32, 64) */
static int dma_mask_bits(struct pci_dev *dev)
{
	if (!dev || !dev->dev.dma_mask)
		return 0;
	return __fls(*(dev->dev.dma_mask)) + 1;
}

static int __init tinyos_dma_fix_init(void)
{
	struct pci_dev *dev;
	int ret;
	int orig_bits, new_bits;

	dev = pci_get_domain_bus_and_slot(domain, bus, PCI_DEVFN(slot, func));
	if (!dev) {
		pr_err("tinyos-dma-fix: device %04x:%02x:%02x.%d NOT FOUND\n",
		       domain, bus, slot, func);
		return -ENODEV;
	}

	orig_bits = dma_mask_bits(dev);
	pr_info("tinyos-dma-fix: found %s (vendor=%04x device=%04x)\n",
		pci_name(dev), dev->vendor, dev->device);
	pr_info("tinyos-dma-fix: driver=%s dma_mask=%dbit "
		"coherent_mask=%dbit power_state=%d\n",
		dev->driver ? dev->driver->name : "(none)",
		orig_bits,
		(int)(dev->dev.coherent_dma_mask ? __fls(dev->dev.coherent_dma_mask) + 1 : 0),
		(int)dev->current_state);

	/* Step 1: Wake to D0 if in low-power state */
	if (dev->current_state != PCI_D0) {
		pr_info("tinyos-dma-fix: device in PCI_D%d, waking to D0...\n",
			(int)dev->current_state);
		ret = pci_set_power_state(dev, PCI_D0);
		if (ret < 0) {
			pr_warn("tinyos-dma-fix: pci_set_power_state(D0) = %d\n", ret);
		} else {
			pr_info("tinyos-dma-fix: power state -> D%d\n",
				(int)dev->current_state);
		}
	}

	/* Step 2: Enable PCI (should already be enabled by vfio-pci) */
	if (!pci_is_enabled(dev)) {
		ret = pci_enable_device(dev);
		if (ret < 0) {
			pr_err("tinyos-dma-fix: pci_enable_device = %d\n", ret);
			pci_dev_put(dev);
			return ret;
		}
		pr_info("tinyos-dma-fix: pci_enable_device OK\n");
	}

	/* Step 3: Set bus master */
	pci_set_master(dev);

	/* Step 4: Set DMA mask — try 64, fall back to 48, then 40 */
	ret = dma_set_mask(&dev->dev, DMA_BIT_MASK(64));
	if (ret == 0) {
		pr_info("tinyos-dma-fix: dma_set_mask(64) OK\n");
	} else {
		pr_warn("tinyos-dma-fix: dma_set_mask(64) = %d, trying 48\n", ret);
		ret = dma_set_mask(&dev->dev, DMA_BIT_MASK(48));
		if (ret == 0) {
			pr_info("tinyos-dma-fix: dma_set_mask(48) OK\n");
		} else {
			pr_warn("tinyos-dma-fix: dma_set_mask(48) = %d, trying 40\n", ret);
			ret = dma_set_mask(&dev->dev, DMA_BIT_MASK(40));
			if (ret == 0) {
				pr_info("tinyos-dma-fix: dma_set_mask(40) OK\n");
			} else {
				pr_warn("tinyos-dma-fix: dma_set_mask(40) = %d\n", ret);
			}
		}
	}

	/* Step 5: Set coherent DMA mask */
	ret = dma_set_coherent_mask(&dev->dev, DMA_BIT_MASK(64));
	if (ret == 0) {
		pr_info("tinyos-dma-fix: dma_set_coherent_mask(64) OK\n");
	} else {
		pr_warn("tinyos-dma-fix: dma_set_coherent_mask(64) = %d\n", ret);
	}

	/* Step 6: Report final state */
	new_bits = dma_mask_bits(dev);
	pr_info("tinyos-dma-fix: RESULT dma_mask=%dbit (was %dbit) "
		"coherent_mask=%dbit power_state=%d\n",
		new_bits, orig_bits,
		(int)(dev->dev.coherent_dma_mask ? __fls(dev->dev.coherent_dma_mask) + 1 : 0),
		(int)dev->current_state);

	/* Final verdict */
	if (new_bits < 64) {
		pr_warn("tinyos-dma-fix: PARTIAL FIX — only achieved %dbit DMA. "
			"64bit GPU DMA not available on this kernel/IOMMU config.\n",
			new_bits);
	} else {
		pr_info("tinyos-dma-fix: SUCCESS — 64bit DMA enabled\n");
	}

	pci_dev_put(dev);
	return 0;
}

static void __exit tinyos_dma_fix_exit(void)
{
	pr_info("tinyos-dma-fix: unloaded\n");
}

module_init(tinyos_dma_fix_init);
module_exit(tinyos_dma_fix_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TinyOS Team");
MODULE_DESCRIPTION("Force NVIDIA GPU to D0 and set dma_mask=64 for VFIO passthrough");
MODULE_VERSION("0.1.0");
