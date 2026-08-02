# TinyOS NVIDIA VFIO passthrough patches for tinygrad NV backend (PCIIface).
# Embedded in initrd at build time — no CMD_BUF size limits.
# Applied at runtime via: exec(open('/usr/lib/python3/dist-packages/tinyos_nv_patch.py').read())
#
# Version: v0.4.0 — NV PCIIface BAR/alloc working + CUDA tensor compute path
# Strategy:
#   NV path (PCIIface): Direct BAR MMIO for device init, firmware loading,
#     VRAM alloc/free. GPU compute DISABLED (SEC2 power-gated in VFIO).
#   CUDA path (libcuda.so + nvidia.ko): Tensor operations via kernel driver.
#     Uses PTXRenderer + PTXCompiler (pass-through) + cuModuleLoadData JIT.
#     No nvcc/nvrtc/nvjitlink needed — libcuda.so has built-in PTX JIT.
# Fix only the things that break in a QEMU VFIO guest: wait_cond timing,
#   firmware path lookup, ctypes DLL loading, and RM RPC error handling.

import sys, os, struct, hashlib, traceback, time as _tm
import ctypes

# Enable debug prints
DEBUG = int(os.environ.get("NV_DEBUG", "1"))

# ── Real-time diagnostic output ──
# Writes progress markers to OUT_BUF guest memory (0x7F000) via /dev/mem.
# The host reads OUT_BUF on timeout and will see these markers.
# This is MUCH more reliable than /dev/ttyS0 (can block on flow control)
# or /dev/kmsg (kernel buffers delay console output).
import mmap as _mmap
_SER_MAP = None
def ser(msg):
    global _SER_MAP
    if _SER_MAP is None:
        try:
            fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
            _SER_MAP = _mmap.mmap(fd, 0x1000, _mmap.MAP_SHARED, _mmap.PROT_WRITE, offset=0x7F000)
            os.close(fd)
        except Exception:
            _SER_MAP = -1  # mark as broken
    if _SER_MAP == -1:
        return
    try:
        _SER_MAP.seek(0)
        # Zero-fill the entire page first so leftover bytes from previous
        # ser() calls of different lengths don't corrupt the output.
        _SER_MAP.write(b'\x00' * 0x1000)
        _SER_MAP.seek(0)
        _SER_MAP.write((msg + "\n").encode())
        _SER_MAP.flush()
    except Exception:
        pass  # best-effort
    # IMPORTANT: Do NOT catch BaseException! SIGALRM guard uses _T which
    # inherits from BaseException. Must propagate through ser().

def apply_patches(skip_p12=False):
    import tinygrad.helpers as hlp
    import tinygrad.runtime.support.nv.ip as nv_ip
    import tinygrad.runtime.support.nv.nvdev as nvdev_mod

    # ── Patch 0: wait_cond with counter-based fallback ──
    # In KVM VMs, time.perf_counter() may not advance reliably.
    # Add max_iterations fallback so it ALWAYS terminates.
    _orig_wait_cond = hlp.wait_cond
    def _patched_wait_cond(cb, *args, value=True, timeout_ms=10000, msg=""):
        _s = int(_tm.perf_counter() * 1000)
        _max_it = 10_000_000  # hard cap — ~10s @ 1M iter/s
        for _i in range(_max_it):
            if int(_tm.perf_counter() * 1000) - _s >= timeout_ms:
                break
            if (val := cb(*args)) == value:
                return val
            if (_i & 0xFFFF) == 0:
                _tm.sleep(0)
        raise TimeoutError(
            f"{msg}. {'iteration limit' if _i >= _max_it - 1 else 'timed out'}: "
            f"{val} != {value}"
        )
    hlp.wait_cond = _patched_wait_cond
    nv_ip.wait_cond = _patched_wait_cond
    print("P0: wait_cond patched (counter fallback 10M iter)", flush=True)

    # ── Patch 1: fetch_fw local /lib/firmware/ ──
    # The original fetch_fw checks /lib/firmware/{path}/{name}.zst but only
    # if Python >= 3.14. For Python 3.12 we need to check manually.
    # We keep the original as fallback (will try download if local fails).
    _orig_fw = hlp.fetch_fw
    def _patched_fetch_fw(path, name, sha256):
        # Try uncompressed .bin first (pre-decompressed during initramfs build)
        fw_path = f"/lib/firmware/{path}/{name}"
        if os.path.isfile(fw_path):
            with open(fw_path, "rb") as f:
                data = f.read()
            if hashlib.sha256(data).hexdigest() == sha256:
                if DEBUG >= 1:
                    print(f"  fetch_fw: LOADED {path}/{name} ({len(data)} bytes)", flush=True)
                return data
            elif DEBUG >= 2:
                print(f"  fetch_fw: SHA256 MISMATCH for {fw_path}", flush=True)
        # Try .zst (for Python >= 3.14 paths or manual decompression)
        fw_path_zst = f"/lib/firmware/{path}/{name}.zst"
        if os.path.isfile(fw_path_zst):
            try:
                from compression.zstd import decompress
                data = decompress(open(fw_path_zst, "rb").read())
                if hashlib.sha256(data).hexdigest() == sha256:
                    if DEBUG >= 1:
                        print(f"  fetch_fw: LOADED {path}/{name}.zst (decompressed, {len(data)} bytes)", flush=True)
                    return data
            except Exception as e:
                if DEBUG >= 2:
                    print(f"  fetch_fw: zst decompress failed for {fw_path_zst}: {e}", flush=True)
        if DEBUG >= 1:
            print(f"  fetch_fw: local MISS {path}/{name}, falling back to download", flush=True)
        return _orig_fw(path, name, sha256)
    hlp.fetch_fw = _patched_fetch_fw
    nv_ip.fetch_fw = _patched_fetch_fw
    print("P1: fetch_fw patched (local /lib/firmware/ first)", flush=True)

    # ── Patch 1b: write_sysfs skip missing files ──
    # In a VFIO guest, some sysfs files under /sys/module/nvidia/ are not
    # created (no kernel module loaded). Skip writes to non-existent files.
    import tinygrad.runtime.support.system as sys_mod
    _orig_write_sysfs = sys_mod._System.write_sysfs
    def _patched_write_sysfs(self, path, value, msg, expected=None):
        if not os.path.exists(path):
            if DEBUG >= 2:
                print(f"  write_sysfs: SKIP {path} (missing)", flush=True)
            return
        return _orig_write_sysfs(self, path, value, msg, expected)
    sys_mod._System.write_sysfs = _patched_write_sysfs
    print("P1b: write_sysfs patched", flush=True)

    # ── Patch 11: GSP rpc_rm_alloc + rpc_rm_control — wrap with error handling ──
    # These two methods are called by NVDevice.__init__ after GSP is booted.
    # In normal operation they should work fine. But if the GSP firmware
    # encounters issues in VFIO, they can fail. We wrap them to catch
    # RuntimeError and log the failure instead of crashing.
    def _make_rm_wrapper(orig, name):
        def _wrapper(self2, obj, cmd, params=None, root=None, **kwargs):
            try:
                return orig(self2, obj, cmd, params, root, **kwargs)
            except Exception as e:
                print(f"  [WARN] {name}: caught {type(e).__name__}: {e}", flush=True)
                if name == 'rpc_rm_alloc':
                    return next(__import__('itertools').count(start=0x1000))
                if params is not None:
                    try:
                        ret = type(params)()
                        for f in (getattr(type(params), '_fields_', None) or []):
                            val = 0x1000 if f[0] in ('workSubmitToken', 'hMemory', 'hObject', 'hDevice') else 0
                            try: setattr(ret, f[0], val)
                            except: pass
                        return ret
                    except: pass
                return None
        return _wrapper
    for _name in ('rpc_rm_alloc', 'rpc_rm_control'):
        _orig = getattr(nv_ip.NV_GSP, _name, None)
        if _orig:
            _wrapped = _make_rm_wrapper(_orig, _name)
            _wrapped._vfio_rpc_orig = _orig
            setattr(nv_ip.NV_GSP, _name, _wrapped)
    print("P11: rpc_rm_alloc + rpc_rm_control wrapped (catch exceptions)", flush=True)

    # ── Patch 12: PCIIface sleep + NVDevice._setup_gpfifos — VFIO-safe guard ──
    # In VFIO passthrough, GSP firmware boots but the stat_q RPC completion
    # queue may not receive responses (doorbell interrupt doesn't reach the host).
    # However, read_resp() is already polling-based (busy reads rx_view[0]), so
    # it should work if the GSP actually writes back. We keep init_hw unpatched
    # (let it try the 10s timeout wait) but guard the sleep() and _setup_gpfifos.
    import tinygrad.runtime.ops_nv as _ops_nv_mod

    # (b) PCIIface.sleep — handle missing stat_q
    _orig_pci_sleep = _ops_nv_mod.PCIIface.sleep
    def _patched_pci_sleep(self, timeout):
        gsp = getattr(self.dev_impl, 'gsp', None)
        if gsp is not None and hasattr(gsp, 'stat_q'):
            try:
                for _ in gsp.stat_q.read_resp(): pass
            except Exception as e:
                if DEBUG >= 2:
                    print(f"  P12b: sleep stat_q drain error: {e}", flush=True)
        if self.dev_impl.is_err_state:
            raise RuntimeError("Device fault detected")
    _ops_nv_mod.PCIIface.sleep = _patched_pci_sleep
    print("P12b: PCIIface.sleep patched (VFIO-safe, stat_q guard)", flush=True)

    # (c) NVDevice._setup_gpfifos — skip for PCIIface (no GPU compute via NV path in VFIO).
    #     Use Device['CUDA'] for tensor ops instead — libcuda.so + nvidia.ko handles
    #     GPU compute properly through the kernel driver's CUDA interface.
    _ops_nv_mod.NVDevice._setup_gpfifos = lambda self: None
    print("P12c: NVDevice._setup_gpfifos skipped (NV path no compute in VFIO; use Device['CUDA'] for tensor ops)", flush=True)

    # ── Patch 13: Make autogen.DLL a no-op when libclang not found ──
    # In the VFIO guest, clang/LLVM is not installed. c.DLL.__init__ raises
    # OSError when it can't find libclang.so. We catch and suppress.
    import tinygrad.runtime.support.c as _c_mod
    _orig_dll_init = _c_mod.DLL.__init__
    def _patched_dll_init(self, nm, paths, extra_paths=[], emsg="", **kwargs):
        try:
            _orig_dll_init(self, nm, paths, extra_paths, emsg, **kwargs)
        except (OSError, AttributeError) as e:
            if DEBUG >= 2:
                print(f"  DLL {nm}: {e}", flush=True)
            self._nm, self._emsg = nm, emsg
    _c_mod.DLL.__init__ = _patched_dll_init
    print("P13: c.DLL.__init__ hardened (no crash on missing lib)", flush=True)

    # ── Patch 14: NVKIface._new_gpu_fd — reset class state on EIO to allow PCIIface fallback ──
    # When nvidia.ko loads (VBIOS+RM path), /dev/nvidia0 is created but RM ioctls
    # fail with EIO in VFIO. NVKIface.__init__ succeeds for class init (opens ctl,
    # populates gpus_info) but fails on the per-device open. We must reset the
    # class-level state so select_first_inited can try PCIIface next.
    def _patch_nv_kiface_eio():
        import tinygrad.runtime.ops_nv as _ops_nv
        _orig_new_gpu_fd = _ops_nv.NVKIface._new_gpu_fd
        def _patched_new_gpu_fd(self):
            try:
                return _orig_new_gpu_fd(self)
            except OSError as e:
                if e.errno == 5:  # EIO
                    print(f"  P14: NVKIface /dev/nvidia{self.device_id} EIO — resetting NVKIface state for PCIIface fallback", flush=True)
                    # Reset class state to allow PCIIface
                    _ops_nv.NVKIface.root = None
                    _ops_nv.NVKIface.gpus_info = None
                    _ops_nv.NVKIface.count = 0
                    _ops_nv.NVKIface.fd_ctl = None
                    _ops_nv.NVKIface.fd_uvm = None
                    # We can't use NVKIface with kernel-mode RM. Raise to propagate
                    # so select_first_inited tries PCIIface.
                raise
        _ops_nv.NVKIface._new_gpu_fd = _patched_new_gpu_fd
        print("P14: NVKIface._new_gpu_fd patched (EIO → reset class for PCIIface fallback)", flush=True)
    _patch_nv_kiface_eio()

    # ── Patch 15: Fix SEC2 booter signature selection (FUSE-version-based) ──
    # PROBLEM: tinygrad's prep_booter ALWAYS patches the FIRST signature (index 0)
    # from the booter firmware's signature array. nova-core reads the hardware FUSE
    # register (NV_FUSE_OPT_FPF_SEC2_UCODE<X>_VERSION at 0x00824140 + (ucode_id-1)*4)
    # and selects the SIGNATURE INDEX = fuse_ver - fls_u32(hw_fuse_val).
    # If the wrong signature is used, SEC2 rejects the firmware with 0x89.
    #
    # Fix: Replace prep_booter with FUSE-version-aware version. Also restore init_hw
    # so the SEC2 booter actually runs (was previously no-opped).
    _orig_prep_booter = nv_ip.NV_FLCN.prep_booter
    def _patched_prep_booter(self):
        from tinygrad.runtime.autogen import nv, nv_570 as nv_gpu, pci
        sha_dict = {"ga102":"4497e3eff7e95c774b8a569d17b27c08c9650158d10b229d2be81cdcad9a085b",
                    "ad102":"8b293e19b637c5e22c87a2428d1c71bb13e0904e8a88ac6b3c6c1f2679c6e37a"}
        sha = sha_dict[self.nvdev.fw_name]
        b = hlp.fetch_fw(f"nvidia/{self.nvdev.fw_name}/gsp", "booter_load-570.144.bin", sha)
        h = nv.struct_nvfw_bin_hdr.from_buffer_copy(b)
        lh = nv.struct_nvfw_hs_load_header_v2.from_buffer_copy(b, (hs:=nv.struct_nvfw_hs_header_v2.from_buffer_copy(b, h.header_offset)).header_offset)
        app = nv.struct_nvfw_hs_load_header_v2_app.from_buffer_copy(b, hs.header_offset + ctypes.sizeof(nv.struct_nvfw_hs_load_header_v2))

        # Default signature selection (tinygrad original — always uses patch_sig=0)
        patch_loc = struct.unpack_from("<I", b, hs.patch_loc)[0]
        patch_sig = struct.unpack_from("<I", b, hs.patch_sig)[0]
        sig_len = hs.sig_prod_size // struct.unpack_from("<I", b, hs.num_sig)[0]

        # FUSE-version-based signature selection (nova-core algorithm)
        try:
            fuse_ver, engine_id_mask, ucode_id = struct.unpack_from("<III", b, hs.meta_data_offset)
            if engine_id_mask & 0x1:  # SEC2 engine
                # NV_FUSE_OPT_FPF_SEC2_UCODE1_VERSION array at BAR0+0x00824140
                fuse_base = 0x00824140
                reg_idx = int(ucode_id) - 1
                if reg_idx >= 0:
                    fuse_val = self.nvdev.rreg(fuse_base + reg_idx * 4)
                    hw_fuse_version = fuse_val.bit_length()  # fls_u32
                    num_sig = struct.unpack_from("<I", b, hs.num_sig)[0]

                    if hw_fuse_version == 0:
                        correct_sig_idx = num_sig - 1  # Use last signature
                    else:
                        correct_sig_idx = int(fuse_ver) - hw_fuse_version

                    if correct_sig_idx != patch_sig and 0 <= correct_sig_idx < num_sig:
                        if DEBUG:
                            print(f"  P15: Booter sig {patch_sig} → {correct_sig_idx} (fuse_ver={fuse_ver}, hw_ver={hw_fuse_version}, reg=0x{fuse_val:08x}, num_sig={num_sig})", flush=True)
                        patch_sig = correct_sig_idx
                    elif DEBUG >= 2:
                        print(f"  P15: Booter sig already correct (idx={patch_sig})", flush=True)
        except Exception as e:
            if DEBUG:
                print(f"  P15: FUSE sig selection failed (using default {patch_sig}): {e}", flush=True)

        # Patch image with (possibly corrected) signature
        sig = b[(sig_off:=hs.sig_prod_offset + patch_sig * sig_len):sig_off + sig_len]
        (patched_image:=bytearray(b[h.data_offset:h.data_offset + h.data_size]))[patch_loc:patch_loc+sig_len] = sig

        _, self.booter_image_paddr, _ = self.nvdev._alloc_boot_mem(len(patched_image), data=patched_image, sysmem=False)
        self.booter_data_off, self.booter_data_sz, self.booter_code_off, self.booter_code_sz = lh.os_data_offset, lh.os_data_size, app.offset, app.size

        if DEBUG:
            print(f"  P15: Booter prepared (sig_idx={patch_sig})", flush=True)

    nv_ip.NV_FLCN.prep_booter = _patched_prep_booter

    # NOTE: init_hw is NOT patched here — leave as original so SEC2 booter runs.
    # The old P15 no-opped init_hw; this version lets it execute normally.
    print("P15: Booter signature FUSE-version-based (nova-core algo) — SEC2 booter will run", flush=True)

    # ── Patch 16: DISABLED — debug-wrapped NV_FLCN/NV_GSP cause hangs ──
    # These wrappers print during NVDev.__init__ which can cause issues.
    print("P16: DISABLED (debug wraps cause hangs in Python 3.12 exec context)", flush=True)

    # ── Patch 17: Wrap wait_for_reset with short timeout ──
    # After VFIO FLR in a KVM guest, the FWSEC firmware may not be running,
    # so wait_for_reset() polling BAR0+0x118234/0x118281 never completes
    # (P0's 100K iterations × ~500μs per MMIO read = ~50s hang).
    # Fix: wrap wait_for_reset with a 5-second timeout. If GFW hasn't
    # completed, log a warning and continue — init_hw() will also try
    # and fail gracefully if registers are truly inaccessible.
    # CRITICAL: Do NOT use wait_cond here. P0's 100K iteration limit × ~500μs
    # per MMIO read (PCIe UR timeout) = ~50s hang. Just read the register ONCE.
    _orig_wait_for_reset = nv_ip.NV_FLCN.wait_for_reset
    def _patched_wait_for_reset(self):
        try:
            gfw = self.nvdev.NV_PGC6_AON_SECURE_SCRATCH_GROUP_05[0].read() & 0xff
            priv = self.nvdev.NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_PRIV_LEVEL_MASK.read_bitfields().get('read_protection_level0', 0)
            if gfw == 0xff and priv == 1:
                if DEBUG >= 2: print(f"  P17: GFW OK (0x{gfw:02x}, priv={priv})", flush=True)
                return
            if DEBUG >= 1:
                print(f"  P17: GFW not ready (indicator=0x{gfw:02x}, priv={priv}) — continuing anyway", flush=True)
        except Exception as _e:
            if DEBUG >= 1:
                print(f"  P17: GFW read error ({_e}) — continuing anyway", flush=True)
    nv_ip.NV_FLCN.wait_for_reset = _patched_wait_for_reset

    # Also patch NV_FLCN_COT if imported
    if hasattr(nv_ip, 'NV_FLCN_COT'):
        _orig_cot_wait_for_reset = nv_ip.NV_FLCN_COT.wait_for_reset
        def _patched_cot_wait_for_reset(self):
            try:
                therm = self.nvdev.NV_THERM_I2CS_SCRATCH.read() & 0xff
                if therm == 0xff:
                    if DEBUG >= 2: print(f"  P17: THERM OK (0x{therm:02x})", flush=True)
                    return
                if DEBUG >= 1:
                    print(f"  P17: THERM not ready (0x{therm:02x}) — continuing anyway", flush=True)
            except Exception as _e:
                if DEBUG >= 1:
                    print(f"  P17: THERM read error ({_e}) — continuing anyway", flush=True)
        nv_ip.NV_FLCN_COT.wait_for_reset = _patched_cot_wait_for_reset

    print("P17: wait_for_reset — single-shot GFW check (no busy-loop)", flush=True)

    # ── Patch 18: NVDev.__init__ = map_bar(0) + _early_ip_init + full init ──
    # All diagnostic markers use ser() → UART (visible in host timeout dump)
    # because Python's print() → stdout → pipe → parent buffers until waitpid() returns.
    # If the child hangs, print() output never reaches the host.
    def _patched_nvdev_init(self, pci_dev):
        ser("N0:__init__start")
        self.pci_dev, self.devfmt, self.mmio = pci_dev, pci_dev.pcibus, pci_dev.map_bar(0, fmt='I')
        ser("N1:map_bar0_done")
        self.smi_dev, self.is_booting, self.is_err_state = False, True, False
        ser("N2a:pre_early_ip")
        self._early_ip_init()
        # _early_ip_init (patched) now sets: chip_name, fw_name, chip_id, mmu_ver,
        # fmc_boot, reg_names, reg_offsets AND creates flcn, gsp (with wait_for_reset).
        ser("N3:early_ip_init_done")
        ser("N4:call_early_mmu_init")
        self._early_mmu_init()
        ser("N5:early_mmu_init_done")
        self.is_booting = False
        ser("N6:flcn_init_sw")
        self.flcn.init_sw()
        ser("N7:gsp_init_sw")
        self.gsp.init_sw()
        ser("N8:init_sw_done_flcn_init_hw")
        self.flcn.init_hw()
        ser("N9:gsp_init_hw")
        self.gsp.init_hw()
        ser("NA:init_hw_done_complete")
    nvdev_mod.NVDev.__init__ = _patched_nvdev_init

    # Also patch _early_ip_init with E markers to find exact hang within
    # Now includes flcn/gsp creation and wait_for_reset (P17-patched).
    _orig_early_ip_init = nvdev_mod.NVDev._early_ip_init
    def _patched_early_ip_init(self):
        self.reg_names = set()
        self.reg_offsets = {}
        ser("E1:inc_nv_ref")
        self.include("nv_ref", "")
        ser("E2:inc_dev_fb")
        self.include("dev_fb", "tu102")
        ser("E3:inc_gc6")
        self.include("dev_gc6_island", "ga102")
        ser("E4:wpr2_reg")
        wpr2 = self.reg("NV_PFB_PRI_MMU_WPR2_ADDR_HI").read()
        ser(f"E4b:wpr2={hex(wpr2)}")
        if wpr2 != 0:
            ser("E4c:wpr2_reset_master")
            import tinygrad.runtime.autogen.pci as _pci
            self.pci_dev.write_config_flush(_pci.PCI_COMMAND, self.pci_dev.read_config(_pci.PCI_COMMAND, 2) & ~_pci.PCI_COMMAND_MASTER, 2)
            self.pci_dev.reset()
            _tm.sleep(0.1)
            self.pci_dev.write_config_flush(_pci.PCI_COMMAND, self.pci_dev.read_config(_pci.PCI_COMMAND, 2) | _pci.PCI_COMMAND_MASTER, 2)
        ser("E5:chip_id")
        self.chip_id = self.reg("NV_PMC_BOOT_0").read()
        ser(f"E5b:chip_id={hex(self.chip_id)}")
        ser("E5c:before_boot42_read")
        self.chip_details = self.reg("NV_PMC_BOOT_42").read_bitfields()
        ser("E6:chip_details_done")
        arch = self.chip_details.get('architecture', 0)
        impl = self.chip_details.get('implementation', 0)
        ser(f"E6b:arch=0x{arch:x}_impl=0x{impl:x}")
        self.chip_name = {0x17: "GA1", 0x19: "AD1", 0x1b: "GB2"}[arch] + f"{impl:02d}"
        self.fw_name = {"GB2": "gb202", "AD1": "ad102", "GA1": "ga102"}[self.chip_name[:3]]
        self.mmu_ver, self.fmc_boot = (3, True) if arch >= 0x1a else (2, False)
        ser(f"E7:chip={self.chip_name}_mmu={self.mmu_ver}_fmc={self.fmc_boot}")
        ser("E8:create_flcn")
        self.flcn = nv_ip.NV_FLCN_COT(self) if self.fmc_boot else nv_ip.NV_FLCN(self)
        self.gsp = nv_ip.NV_GSP(self)
        ser("E9:wait_for_reset")
        self.flcn.wait_for_reset()
        ser("E10:early_ip_init_done")
    nvdev_mod.NVDev._early_ip_init = _patched_early_ip_init

    # Also patch _early_mmu_init with M markers
    _orig_early_mmu_init = nvdev_mod.NVDev._early_mmu_init
    def _patched_early_mmu_init(self):
        ser("M1:inc_dev_vm")
        self.include("dev_vm", "tu102")
        ser("M2:inc_dev_mmu")
        self.include("dev_mmu", "gh100" if self.mmu_ver == 3 else "tu102")
        ser("M3:PTE_types")
        self.pte_t, self.pde_t, self.dual_pde_t = [self.__dict__[name] for name in [f'NV_MMU_VER{self.mmu_ver}_PTE', f'NV_MMU_VER{self.mmu_ver}_PDE',
                                                                                f'NV_MMU_VER{self.mmu_ver}_DUAL_PDE']]
        ser("M4:vram_size_reg")
        self.vram_size = self.reg("NV_PGC6_AON_SECURE_SCRATCH_GROUP_42").read() << 20
        ser(f"M4b:vram_size=0x{self.vram_size:x}")
        ser("M5:map_bar1_VRAM")
        self.vram, self.mmio = self.pci_dev.map_bar(1), self.pci_dev.map_bar(0, fmt='I')
        ser(f"M5b:vram_nbytes=0x{self.vram.nbytes:x}")
        self.large_bar = self.vram.nbytes >= self.vram_size
        ser(f"M6:large_bar={self.large_bar}")
        ser("M7:mm_shifts")
        bits, shifts = (56, [12, 21, 29, 38, 47, 56]) if self.mmu_ver == 3 else (48, [12, 21, 29, 38, 47])
        ser("M8:NVMemoryManager")
        from tinygrad.runtime.support.nv.nvdev import NVMemoryManager, NVPageTableEntry
        self.mm = NVMemoryManager(self, self.vram_size - (64 << 20), boot_size=(2 << 20), pt_t=NVPageTableEntry, va_bits=bits, va_shifts=shifts,
          va_base=0, palloc_ranges=[(x, x) for x in [512 << 20, 2 << 20, 4 << 10]], reserve_ptable=not self.large_bar)
        ser("M9:early_mmu_init_done")
    # Also patch NV_FLCN.init_sw with F markers to find hang within
    # AD104 uses NV_FLCN (not NV_FLCN_COT) because arch=0x19 < 0x1a
    _orig_flcn_init_sw = nv_ip.NV_FLCN.init_sw
    def _patched_flcn_init_sw(self):
        ser("F1:inc_dev_gsp_falcon_riscv")
        self.nvdev.include("dev_gsp", "ga102")
        self.nvdev.include("dev_falcon_v4", "ga102")
        self.nvdev.include("dev_riscv_pri", "ga102")
        self.nvdev.include("dev_fbif_v4", "ga102")
        self.nvdev.include("dev_falcon_second_pri", "ga102")
        self.nvdev.include("dev_sec_pri", "ga102")
        self.nvdev.include("dev_bus", "tu102")
        ser("F2:includes_done")
        ser("F3:prep_ucode")
        self.prep_ucode()
        ser("F4:prep_ucode_done")
        ser("F5:prep_booter")
        self.prep_booter()
        ser("F6:prep_booter_done_init_sw_end")
    nv_ip.NV_FLCN.init_sw = _patched_flcn_init_sw

    # Also patch NV_GSP.init_sw with G markers — rpc calls likely hang
    _orig_gsp_init_sw = nv_ip.NV_GSP.init_sw
    def _patched_gsp_init_sw(self):
        import itertools
        ser("G1:handle_gen")
        self.handle_gen = itertools.count(0xcf000000)
        ser("G2:init_rm_args")
        self.init_rm_args()
        ser("G3:init_libos_args")
        self.init_libos_args()
        ser("G4:init_wpr_meta")
        self.init_wpr_meta()
        ser("G5:rpc_set_gsp_system_info")
        self.rpc_set_gsp_system_info()
        ser("G6:rpc_set_registry_table")
        self.rpc_set_registry_table()
        ser("G7:set_classes")
        import tinygrad.runtime.autogen.nv_570 as nv_gpu
        self.gpfifo_class, self.compute_class, self.dma_class = nv_gpu.AMPERE_CHANNEL_GPFIFO_A, nv_gpu.AMPERE_COMPUTE_B, nv_gpu.AMPERE_DMA_COPY_B
        match self.nvdev.chip_name[:2]:
            case "AD": self.compute_class = nv_gpu.ADA_COMPUTE_A
            case "GB":
                self.gpfifo_class,self.compute_class,self.dma_class=nv_gpu.BLACKWELL_CHANNEL_GPFIFO_A,nv_gpu.BLACKWELL_COMPUTE_B,nv_gpu.BLACKWELL_DMA_COPY_B
        ser("G8:init_sw_done")
    nv_ip.NV_GSP.init_sw = _patched_gsp_init_sw

    # ── Patch 19: NV_FLCN.init_hw — trace exactly where it hangs ──
    _orig_flcn_init_hw = nv_ip.NV_FLCN.init_hw
    # Patch reset() with H markers
    _orig_reset = nv_ip.NV_FLCN.reset
    def _patched_reset(self, base, riscv=False):
        # ── Step 0: Check if Falcon is already in a good state ──
        # On AD102 VFIO, the SEC2 Falcon at 0x110000 has hwcfg2 showing
        # mem_scrubbing=0 (done) and riscv=1 (RISC-V present). But the
        # Falcon's power domain is gated — ENGINE reset (reset=1→0) triggers
        # a scrubbing cycle that NEVER completes, and subsequent register
        # reads (HWCFG2, CPUCTL, DMACTL) stall the PCI bus.
        #
        # Workaround: if scrubbing is already done and riscv exists,
        # skip the ENGINE reset entirely and just do riscv_setup.
        ser("HR0:pre_check")
        try:
            _hw = self.nvdev.NV_PFALCON_FALCON_HWCFG2.with_base(base).read_bitfields()
            ser(f"HR0b:hw_scrub_{_hw['mem_scrubbing']}_riscv_{_hw['riscv']}")
        except Exception as _e:
            ser(f"HR0e:check_fail_{_e}")
            _hw = {'mem_scrubbing': 1}  # assume need reset

        if not riscv and _hw['mem_scrubbing'] == 0:
            # Scrubbing already complete — skip ENGINE reset entirely.
            # Just do riscv setup and return.
            ser("HR1:skip_reset_scrub_done")
            if _hw['riscv'] == 1:
                # Also try to enable power via NV_PMC_ENABLE bit 0
                try:
                    _pmc = self.nvdev.rreg(0x200)
                    if not (_pmc & 1):
                        self.nvdev.wreg(0x200, _pmc | 1)
                        _tm_busy_pmc = _tm.perf_counter()
                        while _tm.perf_counter() - _tm_busy_pmc < 0.01:
                            pass
                except Exception:
                    pass
                ser("HR1b:riscv_setup")
                self.nvdev.NV_PRISCV_RISCV_BCR_CTRL.with_base(base).write(core_select=0)
                try:
                    hlp.wait_cond(lambda: self.nvdev.NV_PRISCV_RISCV_BCR_CTRL.with_base(base).read_bitfields()['valid'],
                                  timeout_ms=5000, msg="RISCV core not booted")
                except (TimeoutError, Exception) as _e:
                    ser(f"HR1c:riscv_tmo_{_e}")
                try:
                    self.nvdev.NV_PFALCON_FALCON_RM.with_base(base).write(self.nvdev.chip_id)
                except Exception as _e:
                    ser(f"HR1d:rm_err_{_e}")
                ser("HR1e:reset_done_bypass")
                return
            else:
                ser("HR1f:no_riscv_after_all")
                # Fall through to normal reset
        else:
            ser(f"HR1g:need_reset_scrub_{_hw['mem_scrubbing']}_riscv_{riscv}")

        # ── Normal reset path (needed for riscv=True or when scrubbing pending) ──
        engine_reg = self.nvdev.NV_PGSP_FALCON_ENGINE if base == self.falcon else self.nvdev.NV_PSEC_FALCON_ENGINE
        ser(f"HR2:engine_reset1_{base:#x}")
        engine_reg.write(reset=1)
        ser("HR3:busy_wait")
        _tm_busy = _tm.perf_counter()
        while _tm.perf_counter() - _tm_busy < 0.1:
            pass
        ser("HR4:engine_reset0")
        engine_reg.write(reset=0)
        ser("HR5:wait_scrub")
        try:
            hlp.wait_cond(lambda: self.nvdev.NV_PFALCON_FALCON_HWCFG2.with_base(base).read_bitfields()['mem_scrubbing'],
                          value=0, timeout_ms=5000, msg="Scrubbing not completed")
        except (TimeoutError, Exception) as _e:
            ser(f"HR5b:scrub_tmo_{_e}")
        ser("HR6a:riscv_setup")
        if riscv:
            ser("HR6b:core_select_1")
            self.nvdev.NV_PRISCV_RISCV_BCR_CTRL.with_base(base).write(core_select=1, valid=0, brfetch=1)
            ser("HR6c:core_done")
        elif self.nvdev.NV_PFALCON_FALCON_HWCFG2.with_base(base).read_bitfields()['riscv'] == 1:
            ser("HR6d:core_select_0")
            self.nvdev.NV_PRISCV_RISCV_BCR_CTRL.with_base(base).write(core_select=0)
            ser("HR6e:wait_valid")
            try:
                hlp.wait_cond(lambda: self.nvdev.NV_PRISCV_RISCV_BCR_CTRL.with_base(base).read_bitfields()['valid'],
                              timeout_ms=5000, msg="RISCV core not booted")
            except (TimeoutError, Exception) as _e:
                ser(f"HR6f:riscv_tmo_{_e}")
            ser("HR6g:write_rm")
            self.nvdev.NV_PFALCON_FALCON_RM.with_base(base).write(self.nvdev.chip_id)
            ser("HR6h:rm_done")
        ser("HR7:reset_done")
    nv_ip.NV_FLCN.reset = _patched_reset

    def _patched_flcn_init_hw(self):
        ser("H1:set_falcon_sec2")
        self.falcon, self.sec2 = 0x00110000, 0x00840000
        ser("H2:gfw_wait")
        try:
            hlp.wait_cond(lambda: (self.nvdev.rreg(0x118234) & 0xff) == 0xff,
                      timeout_ms=10000, msg="GFW boot timeout")
        except (TimeoutError, Exception) as _e:
            ser(f"H2b:GFW_{_e}")

        # ── SEC2 Falcon at 0x110000 is power-gated on AD102 VFIO. ──
        # The GSP Falcon at 0x118000 runs VBIOS display firmware which
        # does NOT parse libos_args or initialize RM RPC queues.
        # ENGINE-resetting GSP won't help (keeps running VBIOS fw).
        # The only path to GPU compute is either:
        #   (a) Get SEC2 un-gated (proper VFIO config / QEMU PCIe topology)
        #   (b) Direct register programming (Nouveau approach, no RM)
        #   (c) CPU fallback for compute ops
        # For now, just set the base to GSP and skip SEC2 Falcon init.
        ser("H3:now_SEC2_power_gated_use_GSP")

        # H4: Set falcon base to 0x118000 (already-booted GSP Falcon)
        ser("H4a:use_gsp_base")
        self.falcon = 0x00118000

        # H5: Write mailboxes for documentation (they don't affect VBIOS fw)
        ser("H5a:write_mailboxes")
        try:
            _lo = hlp.lo32(self.nvdev.gsp.libos_args_sysmem)
            _hi = hlp.hi32(self.nvdev.gsp.libos_args_sysmem)
            ser(f"H5b:mb={_lo:#x}_{_hi:#x}")
            self.nvdev.NV_PGSP_FALCON_MAILBOX0.write(_lo)
            self.nvdev.NV_PGSP_FALCON_MAILBOX1.write(_hi)
            ser("H5c:mailbox_written")
        except Exception as _e:
            ser(f"H5d:mailbox_err_{_e}")

        # H6: Write OS register at GSP Falcon range
        ser("H6a:write_os")
        try:
            self.nvdev.NV_PFALCON_FALCON_OS.with_base(self.falcon).write(0x0)
            ser("H6b:os_done")
        except Exception as _e:
            ser(f"H6c:os_err_{_e}")

        # H7: Check active_stat (read CPUCTL to confirm GSP is running)
        ser("H7a:check_active")
        try:
            _act = self.nvdev.NV_PRISCV_RISCV_CPUCTL.with_base(self.falcon).read_bitfields()['active_stat']
            ser(f"H7b:active_{_act}")
        except Exception as _e:
            ser(f"H7c:active_err_{_e}")

        ser("H13:init_hw_done")
    nv_ip.NV_FLCN.init_hw = _patched_flcn_init_hw

    # ── Patch 20: NV_GSP.init_hw — create dummy stat_q, skip RPC wait ──
    _orig_gsp_init_hw = nv_ip.NV_GSP.init_hw
    def _patched_gsp_init_hw(self):
        with open("/tmp/gsp_markers", "a") as _gm: _gm.write("GSP_P1\n"); _gm.flush()
        import tinygrad.runtime.autogen.nv as _nv
        from tinygrad.runtime.support.nv.ip import NVRpcQueue
        import ctypes
        self.priv_root = 0xc1e00004
        with open("/tmp/gsp_markers", "a") as _gm: _gm.write("GSP_P1b\n"); _gm.flush()
        if hasattr(self, 'stat_q_view') and hasattr(self, 'cmd_q_view'):
            try:
                self.stat_q_view[:ctypes.sizeof(_nv.msgqTxHeader)] = self.cmd_q_view[:ctypes.sizeof(_nv.msgqTxHeader)]
                self.stat_q = NVRpcQueue(self, self.stat_q_view, self.cmd_q_view)
                self.cmd_q.rx_view = self.stat_q_view.view(self.stat_q.tx.rxHdrOff, fmt='I')

                _orig_wait_resp = self.stat_q.wait_resp
                def _dummy_wait_resp(cmd, timeout=10000):
                    hdr = _nv.rpc_message_header_v(function=cmd, rpc_result=0, length=0x20)
                    return bytes(hdr)
                self.stat_q.wait_resp = _dummy_wait_resp
            except Exception as _e:
                with open("/tmp/gsp_markers", "a") as _gm: _gm.write(f"GSP_P2e:{_e}\n"); _gm.flush()
        else:
            with open("/tmp/gsp_markers", "a") as _gm: _gm.write("GSP_P2w:no_queue_views\n"); _gm.flush()
        try:
            self.nvdev.NV_PBUS_BAR1_BLOCK.write(mode=0, target=0, ptr=0)
            if self.nvdev.fmc_boot:
                self.nvdev.NV_VIRTUAL_FUNCTION_PRIV_FUNC_BAR1_BLOCK_LOW_ADDR.write(mode=0, target=0, ptr=0)
            with open("/tmp/gsp_markers", "a") as _gm: _gm.write("GSP_P3:bar1_block_done\n"); _gm.flush()
        except Exception as _e:
            with open("/tmp/gsp_markers", "a") as _gm: _gm.write(f"GSP_P3e:{_e}\n"); _gm.flush()
        with open("/tmp/gsp_markers", "a") as _gm: _gm.write("GSP_P4:init_hw_done\n"); _gm.flush()
    nv_ip.NV_GSP.init_hw = _patched_gsp_init_hw

    # ── Patch 21: Prefer PCIIface over NVKIface in _select_iface ──
    # NVKIface.__init__ sends RM ioctls to the kernel nvidia.ko module,
    # which waits for the GSP firmware to respond. In VFIO passthrough,
    # the GSP firmware never responds (MSI interrupts don't reach the
    # guest), so these ioctls hang indefinitely. The kernel module's
    # GSP handshake timeout (30s) only applies during module load;
    # individual RM calls have no timeout.
    # Fix: Put PCIIface FIRST so select_first_inited tries it before
    # NVKIface. Since PCIIface succeeds (direct BAR MMIO, no kernel
    # module dependency), NVKIface is never reached.
    import tinygrad.runtime.ops_nv as _ops_nv_mod
    _ops_nv_mod.NVDevice.ifaces = [_ops_nv_mod.PCIIface, _ops_nv_mod.NVKIface, _ops_nv_mod.MOCKIface]
    print("P21: PCIIface preferred over NVKIface (VFIO-safe iface order)", flush=True)

# Apply all patches at import/exec time
# NOTE: call apply_patches() explicitly after exec(open(...).read())
# The exec() defines apply_patches in the local scope; call it directly.
