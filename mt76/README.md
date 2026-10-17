# mt76 Out-of-Tree WiFi Driver Build Infrastructure

Build, install, and manage MediaTek mt76 WiFi drivers as out-of-tree kernel
modules. Supports DKMS, non-DKMS, Secure Boot, and kernels 6.12 through 7.2.
Kernels older than 7.0 are best effort.

Based on [openwrt/mt76](https://github.com/openwrt/mt76), adapted for
standalone out-of-tree building by the
[morrownr](https://github.com/morrownr) community.

Asked to try a fix? [TESTING.md](TESTING.md) is the one page you need:
install, test, report, go back.

For companies, organizations or individuals seeking an engineer to do professional contract work:

```
Devin Wittmayer
For adapter makers and companies shipping Linux devices with WiFi.
Driver fixes and new adapter support, taken into the mainline kernel.
MediaTek mt76 and Realtek rtw89, tested in my own lab.
lucid_duck@justthetip.ca
https://github.com/Lucid-Duck
```

## Quick Start

```sh
# Install
git clone https://github.com/morrownr/mt76.git
cd mt76
sudo sh install-driver.sh

# Check status (no root needed)
./check-driver.sh

# Edit module parameters (optional)
sudo ./edit-parameters.sh

# Update
git pull
sudo sh install-driver.sh

# Uninstall
sudo sh uninstall-driver.sh
```

## Supported Chipset Families

| Family | Chips | Bus | Modules | WiFi Generation |
|--------|-------|-----|---------|-----------------|
| MT76x0 | MT7610, MT7630, MT7650 | USB, PCIe | mt76x0u, mt76x0e | WiFi 5 (AC) |
| MT76x2 | MT7612, **MT7662** | USB, PCIe | mt76x2u, mt76x2e | WiFi 5 (AC) |
| MT7615 | MT7615, MT7663 | USB, PCIe, SDIO | mt7615e, mt7663u, mt7663s | WiFi 5 (AC) |
| MT7921 | MT7920, MT7921, MT7922, **MT7902** | USB, PCIe, SDIO | mt7921e, mt7921u, mt7921s | WiFi 6E (AXE) |
| MT7925 | MT7925, MT7927 | USB, PCIe | mt7925e, mt7925u | WiFi 7 (BE) |

### Inactive Families

| Family | Status |
|--------|--------|
| MT7603 | Source retained but not built by default. Old WiFi 4 chip, no user reports on this repo. Users with MT7603 hardware should rely on the in-kernel `mt7603e` driver. Reactivation is a one-line Makefile change if someone needs it. |
| MT7915 | Source retained but not built by default. PCIe-only AP/router silicon (MT7915, MT7906, MT7916). Users running this hardware are typically on routers with vendor BSPs; the in-kernel `mt7915e` driver covers desktop/laptop use. |
| MT7996 | Source retained but not built by default. PCIe-only WiFi 7 AP/router silicon (MT7990, MT7991, MT7992, MT7996). Same router/BSP audience as MT7915; the in-kernel `mt7996e` driver covers desktop/laptop use. |

## Supported USB Adapters

For specific adapter recommendations, the Plug and Play List, and vendor selection guidance, see [morrownr/USB-WiFi](https://github.com/morrownr/USB-WiFi).

The drivers auto-bind to many vendor VID:PIDs per family; run `lsusb` after plugging in to see what was detected. Reference VID:PIDs by chip family:

| Family | Reference VID:PID | WiFi Generation |
|--------|-------------------|-----------------|
| MT76x0 | 148f:7610 | WiFi 5 (AC) |
| MT76x2 | 0e8d:7612 | WiFi 5 (AC) |
| MT7615 / MT7663 | 0e8d:7663 | WiFi 5 (AC) |
| MT7921 | 0e8d:7961 | WiFi 6E (AXE) |
| MT7925 | 0e8d:7925 | WiFi 7 (BE) |

## Supported PCIe Devices

The drivers auto-bind to many vendor PCI IDs per family; run `lspci -nn` and look for MediaTek devices to see what was detected. Reference PCI IDs by chip family (vendor 14c3 unless noted):

| Family | PCI IDs |
|--------|-------|
| MT76x0 | 7610, 7630, 7650 |
| MT76x2 | 7662, 7612, 7602 |
| MT7615 | 7615, 7663, 7611 |
| MT7921 | 7961, 7922, 0608, 0616, 7920, 7902 (also 0b48:7922) |
| MT7925 | 7925, 0717 |

## Files

| File | Purpose |
|------|---------|
| `Makefile` | Kbuild out-of-tree Makefile for all 28 active modules across 7 chipset families |
| `install-driver.sh` | Full install with progress display, prerequisite checks, build, verify |
| `uninstall-driver.sh` | Clean removal of installed modules, DKMS entries, and config |
| `check-driver.sh` | No-root diagnostic: loaded modules, hardware, link status, firmware, dmesg |
| `edit-parameters.sh` | Open `/etc/modprobe.d/mt76_git.conf` in `$EDITOR` to tweak module parameters |
| `default-editor.txt` | Editor used by `edit-parameters.sh` if `$VISUAL` and `$EDITOR` are unset (default: `nano`) |
| `dkms.conf` | DKMS auto-rebuild on kernel updates, conditional PCI/SDIO support |
| `mt76_git.conf` | modprobe options and blacklist for the in-kernel mt76 modules this repo replaces |
| `compat-patches/` | Source compatibility patches for older kernel API changes |
| `mt7615/Makefile` | MT7615 family: common + PCIe + USB + SDIO (WiFi 5) |
| `mt7915/Makefile` | MT7915 PCIe with coredump support (WiFi 6) |
| `mt7921/Makefile` | MT7921 family: common + PCIe + USB + SDIO (WiFi 6E) |
| `mt7925/Makefile` | MT7925 family: common + PCIe + USB (WiFi 7) |
| `mt7996/Makefile` | MT7996 PCIe with NPU and coredump support (WiFi 7) |
| `mt76x0/Makefile` | MT76x0 family: common + USB + PCIe (WiFi 5) |
| `mt76x2/Makefile` | MT76x2 family: common + USB + PCIe (WiFi 5) |

## Module Map (28 active modules)

```
Core and transport:
  mt76_git              Core driver
  mt76_usb_git          USB transport
  mt76_sdio_git         SDIO transport (requires CONFIG_MMC)

Shared libraries:
  mt76x02_lib_git       Legacy shared (MT76x0/x2)
  mt76x02_usb_git       Legacy USB shared
  mt76_connac_lib_git   CONNAC shared
  mt792x_lib_git        MT792x shared
  mt792x_usb_git        MT792x USB shared

Chipset families:
  mt7615_common_git     MT7615 shared
  mt7615e_git           MT7615 PCIe
  mt7663_usb_sdio_common_git  MT7663 USB/SDIO shared
  mt7663u_git           MT7663 USB
  mt7663s_git           MT7663 SDIO (requires CONFIG_MMC)
  mt7915e_git           MT7915 PCIe
  mt7921_common_git     MT7921 shared
  mt7921e_git           MT7921 PCIe
  mt7921s_git           MT7921 SDIO
  mt7921u_git           MT7921 USB
  mt7925_common_git     MT7925 shared
  mt7925e_git           MT7925 PCIe
  mt7925u_git           MT7925 USB
  mt7996e_git           MT7996 PCIe
  mt76x0_common_git     MT76x0 shared
  mt76x0u_git           MT76x0 USB
  mt76x0e_git           MT76x0 PCIe
  mt76x2_common_git     MT76x2 shared
  mt76x2u_git           MT76x2 USB
  mt76x2e_git           MT76x2 PCIe
```

## How It Works

All out-of-tree modules are built with a `_git` suffix (e.g., `mt76_git.ko`
instead of `mt76.ko`). This allows them to coexist with the in-kernel mt76
modules. The blacklist in `mt76_git.conf` prevents the in-kernel versions
from loading, so the out-of-tree versions handle all hardware.

This means:
- **Safe to install** -- your in-kernel modules are untouched
- **Safe to uninstall** -- blacklist removal restores in-kernel behavior
- **Safe to update** -- just `git pull && sudo sh install-driver.sh`

## Prerequisites

The installer checks for all of these automatically:

- `gcc` -- C compiler
- `make` -- build tool
- `iw` -- wireless configuration tool
- Kernel header files for your running kernel
- Optional: `dkms` for automatic rebuilds on kernel updates
- With Secure Boot on and no dkms: `openssl` and `mokutil`, to sign the modules

**Kernels built with clang** (CachyOS, Chimera) need
their modules built with clang too. The Makefile detects this from the kernel's
config and switches to `LLVM=1` on its own, for `make`, `install-driver.sh` and
dkms alike. Install `clang`, `lld` and `llvm` first; the package names are the
same on Arch, Debian and Fedora. The tell that you are on such a kernel and the
tools are missing is gcc failing with `unrecognized command-line option
'-mstack-alignment=8'`.

## Secure Boot

A kernel with Secure Boot on loads only signed modules. Without dkms, the
installer runs `make sign-install`: the first time, it creates a Machine Owner
Key in this directory, signs every module with it, and asks for a one-time
password. On the next boot the MOK manager offers to enroll the key: pick
Enroll MOK, Continue, Yes, and type that password. The driver loads from then
on, and later updates reuse the key with no further prompts. Ubuntu's existing
key under `/var/lib/shim-signed/mok` is used when present.

## Reporting Issues

Run `check-driver.sh` and include the full output in your bug report:

```sh
./check-driver.sh 2>&1 | tee mt76-diag.txt
```

This captures loaded modules (in-kernel vs out-of-tree), hardware detection,
link status with signal strength, firmware presence, blacklist health, Secure
Boot status, and recent kernel messages. Everything a maintainer needs in one
command.

## Kernel Compatibility

Supported range: **6.12 through 7.x** (enforced by `BUILD_EXCLUSIVE_KERNEL`
in `dkms.conf`). Kernels older than 7.0 are best effort.

Compatibility patches in `compat-patches/`:
- `linux/unaligned.h` vs `asm/unaligned.h` header rename (kernel 6.12)
- `hrtimer_setup()` replacing `hrtimer_init()` (kernel 6.12/6.19)
- OpenWrt-specific EMLSR API isolation

## Design Decisions

- **_git suffix**: Follows the morrownr/rtw89 convention. Modules install to
  `extra/` or `updates/` directories which take priority over `kernel/` in
  depmod search order.
- **PCI conditional**: PCIe-only modules gated on `CONFIG_PCI`
- **SDIO conditional**: SDIO modules gated on `CONFIG_MMC`
- **USB unconditional**: USB modules always built
- **Git commit in modules**: `-DGIT_COMMIT` baked in at build time for traceability
- **Module compression**: Install target auto-matches distro compression (zstd/xz/gzip)
- **No SoC code**: MT7622_WMAC, MT798X_WMAC, NPU configs left as no-ops (never
  defined on desktop/laptop kernels, code compiles out)

## License

This program is free software; you can redistribute it and/or modify it under
the terms of version 2 of the GNU General Public License as published by the
Free Software Foundation.
