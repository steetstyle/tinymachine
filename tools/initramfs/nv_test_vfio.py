import os, sys, signal, time
sys.path.insert(0, "/usr/lib/python3.12/dist-packages")
os.environ["NV_DEBUG"] = "0"
exec(open("/usr/lib/python3.12/dist-packages/tinyos_nv_patch.py").read())
apply_patches()

from tinygrad.runtime.support.nv.nvdev import NVDev
from tinygrad.runtime.support.system import System
from tinygrad.runtime.ops_nv import NVDevice

print("STEP1: pci_probe"); sys.stdout.flush()
pci = System.pci_probe_device("NV", 0, 0x10de,
    ((0xff00, (0x2200,0x2400,0x2500,0x2600,0x2700,0x2800,0x2b00,0x2c00,0x2d00,0x2f00)),),
    base_class=0x03)
print("STEP2: PCI_OK", pci.pcibus, hex(pci.bar_info(0)[0])); sys.stdout.flush()

print("STEP3: NVDev init"); sys.stdout.flush()
nvdev = NVDev(pci)
print("STEP4: NVDEV_OK", nvdev.chip, nvdev.fw_name); sys.stdout.flush()

print("STEP5: PCIIface init"); sys.stdout.flush()
# Use NVDevice as the 'dev' parameter (like select_first_inited does)
dummy_nv = NVDevice.__new__(NVDevice)
dummy_nv.device_id = 0
from tinygrad.runtime.ops_nv import PCIIface
iface = PCIIface(dummy_nv, 0)
print("STEP6: PCIIFACE_OK", hex(iface.root), iface.gpu_instance); sys.stdout.flush()
