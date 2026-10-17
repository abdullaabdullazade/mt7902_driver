# mt7902-linux

Out-of-tree WiFi and Bluetooth drivers for the **MediaTek MT7902** M.2 PCIe wireless card on Linux.

> **On kernel 7.1 or newer you probably do not need this repo.**
> MT7902 (`14c3:7902`) support is merged into the in-tree `mt7921e` driver as of
> **Linux 7.1**, and the firmware ships in `linux-firmware`. Upstream handles the
> chip's quirks directly: it skips the MCU-WA ring, uses TXQ index 15 for MCU-WM
> with a larger shared RX Ring0, clears `wm2_complete_mask` in its own IRQ map,
> and leaves runtime PM disabled for this chip. Check your kernel with:
>
> ```sh
> modinfo mt7921e | grep 7902     # a match means your kernel already supports it
> ```
>
> `install.sh` performs this check and will use the in-tree driver instead of
> building anything. Pass `--force-custom` to override.

Older kernels (6.19 and earlier, including Ubuntu 24.04's 6.8) do **not** claim
the device — `mt7921e` there lists only `7920/0616/0608/7922/7961`, so the card
shows up as `UNCLAIMED`. This repo bundles community-maintained out-of-tree
drivers and forward-ports applicable upstream fixes so those kernels get both
WiFi and Bluetooth working today.

### What works on which kernel

| Kernel | What `install.sh` uses | Notes |
|--------|------------------------|-------|
| **7.1 and newer** | in-tree `mt7921e` + `btusb` | Nothing to install. `install.sh` detects this and exits early. |
| **6.12 – 7.0** | `mt7902e` ([hmtheboy154/mt7902](https://github.com/hmtheboy154/mt7902) + the fixes below), then [morrownr/mt76](https://github.com/morrownr/mt76) if that does not work | Ubuntu 24.04's HWE kernel is 7.0, which has no in-tree support. `--mt76` tries morrownr/mt76 first. |
| **6.6 – 6.11** | `mt7902e` | Includes Ubuntu 24.04's original 6.8. |
| **older than 6.6** | bundled `gen4-mt7902` | Vendor tree; frequently fails MCU init. Last resort. |

Every driver is built with DKMS, so it is rebuilt automatically on kernel
updates, and is bundled in this repository: the install works without a
network connection, which is the usual situation when WiFi is what is missing.

Firmware ships in `linux-firmware` as of its 20260309 release. If your system
already has it — compressed or not — `install.sh` leaves it alone and never
puts a copy in front of it. `firmware/` here holds the same files
(WiFi 20251212, Bluetooth 20250826) for systems that do not have them yet.

### Moving to the in-tree driver later

If you would rather run the driver the kernel ships than one from here, you
need kernel 7.1 or newer. How you get there depends on the distribution:

| Distribution | Path to 7.1 |
|---|---|
| Arch, openSUSE Tumbleweed | `sudo pacman -Syu` / `sudo zypper dup` — rolling, so it is probably there already |
| Fedora | Fedora ships new kernel series to existing releases, so `sudo dnf upgrade --refresh` gets you there once 7.1 lands for your release |
| Ubuntu / Debian stable | A release does not move to a new kernel series. Either upgrade to a release that ships 7.1, or install a mainline build with `sudo ./install.sh --upgrade-kernel` |
| Ubuntu LTS | The HWE stack tracks newer kernels, but only as far as the LTS provides |

`install.sh --upgrade-kernel` installs an **unsigned mainline** kernel. It will
not boot with Secure Boot enabled (the installer checks and refuses), it is not
supported by your distribution, and you update it by installing the next build
yourself. It suits testing more than a daily machine — a distribution that
ships 7.1 is the better long-term answer.

Once you are on 7.1, remove what this repo installed before relying on the
in-tree driver, otherwise the blacklist here keeps `mt7921e` from binding:

```sh
sudo ./uninstall.sh
sudo reboot
```

After the reboot `mt7921e` claims the card on its own. Running `install.sh`
again is harmless — it detects in-tree support and installs nothing.

| | Status | Notes |
|-|--------|-------|
| WiFi (2.4 GHz) | Working | Stable on most hardware |
| WiFi (5 GHz) | Partial | May not switch bands on dual-band SSIDs |
| WiFi (6 GHz / 6E) | Untested | Kernel 5.4+ required for 6G support |
| Bluetooth | Working | Patched `btusb` + `btmtk` modules |

## Install

```sh
git clone https://github.com/abdullaabdullazade/mt7902_driver
cd mt7902_driver
sudo ./install.sh            # installs both wifi + bluetooth, then reboots
```

The script installs the build dependencies itself (Debian/Ubuntu and
derivatives, Fedora/RHEL, Arch/CachyOS/Manjaro, openSUSE), including the
headers for the kernel that is actually running and clang for clang-built
kernels such as CachyOS.

```sh
sudo ./install.sh --wifi       # wifi driver + firmware only
sudo ./install.sh --bt         # bluetooth driver + firmware only
sudo ./install.sh --no-dkms    # build without DKMS (rebuild after kernel updates yourself)
sudo ./install.sh --no-reboot  # do not reboot at the end
```

### Automatic driver selection

1. **In-tree `mt7921e`**, if `modinfo mt7921e` shows the `14c3:7902` alias
   (kernel 7.1+, or a distribution kernel with the support backported).
   Nothing is built, nothing is blacklisted.
2. **`mt7902e`** from `mt7902/` on kernel 6.6 and newer.
3. **morrownr/mt76** from `mt76/` on kernel 6.12 and newer — the whole mainline
   mt76 family at kernel 7.3 level, built as `*_git` modules next to the
   in-kernel ones, with every MT7902 fix merged since 7.1.
4. **`gen4-mt7902`**, only if none of the above worked.

A driver counts as working when the card is bound to it, a wireless interface
appears, and the kernel log shows no MCU timeouts. Otherwise it is removed
again before the next one is tried, so only one driver is ever left installed.

```sh
sudo ./install.sh --mt76          # try morrownr/mt76 first
sudo ./install.sh --mt7902e       # mt7902e first (the default; --fallback is the old name)
sudo ./install.sh --gen4          # try the bundled vendor driver first
sudo ./install.sh --force-custom  # build even if the kernel has in-tree support
```

### Secure Boot

DKMS signs the modules, but with a key your firmware does not trust until you
enroll it once. If a module is rejected, the installer prints the exact
`mokutil --import` command; run it, reboot, and choose "Enroll MOK" in the
blue screen that appears.

### Stale firmware from older versions

Earlier versions of this installer copied uncompressed firmware even when the
distribution shipped it compressed. The kernel loads the uncompressed file
first, so those copies hide every later `linux-firmware` update (Bluetooth was
seen running a 2022 build next to a 2025 one). `install.sh` lists such files on
every run; remove them with:

```sh
sudo ./install.sh --clean-firmware
```

Only files no package owns, and only where the distribution has its own copy,
are removed.

## Uninstall

```sh
sudo ./uninstall.sh            # remove everything
sudo ./uninstall.sh --wifi     # wifi only
sudo ./uninstall.sh --bt       # bluetooth only
sudo ./uninstall.sh --keep-fw  # keep firmware files
sudo ./uninstall.sh --no-reboot
```

It removes every driver this repository can install (also ones from older
versions of it), puts back the Bluetooth modules older versions overwrote, and
never deletes a file a package owns. MT7902 firmware that is the only copy on
the system is kept, because the in-tree driver on 7.1+ needs it.

## How it works

**WiFi** — `mt7902/` is [hmtheboy154/mt7902](https://github.com/hmtheboy154/mt7902)
(mainline mt76 with MediaTek's MT7902 series, backported to 6.6+; archived
upstream) with the fixes listed below. `mt76/` is
[morrownr/mt76](https://github.com/morrownr/mt76). `gen4-mt7902/` is the vendor
driver from Xiaomi's BSP.

**Bluetooth** — `mt7902_temp/linux-X.Y/drivers/bluetooth` are patched `btusb` +
`btmtk` trees from [mt7902_temp](https://github.com/OnlineLearningTutorials/mt7902_temp).
`bluetooth-dkms/` packages them for DKMS: the modules go to `/updates/dkms`,
which the kernel prefers over its own, so the distribution's modules are never
overwritten. The tree is chosen per kernel; when a distribution kernel has
backported API changes the next trees are tried until one builds. It does not
build on 7.1+, which supports the chip itself.

**Firmware** — `firmware/`, identical to `linux-firmware`; installed only
where the system has none. Every file the installer adds is listed in
`/var/lib/mt7902-driver/installed-files`.

## Repository layout

```
├── install.sh / uninstall.sh / lib.sh
├── firmware/            # MT7902 WiFi + BT firmware (= linux-firmware)
├── mt7902/              # mt7902e: hmtheboy154/mt7902 + fixes   (default WiFi)
├── mt76/                # morrownr/mt76                         (WiFi, 6.12+)
├── gen4-mt7902/         # vendor driver                         (WiFi, last resort)
├── bluetooth-dkms/      # DKMS packaging for the Bluetooth trees
├── mt7902_temp/         # btusb + btmtk trees, linux-6.14 … linux-7.1
└── .github/workflows/
    ├── build.yml          # builds everything against Ubuntu 6.8 – 7.0
    └── sync-upstream.yml  # weekly sync of mt76/ and mt7902_temp/ (one PR)
```

## Known issues

- Can't switch to 5 GHz on SSIDs that broadcast both 2.4/5 GHz.
- WPA3 is broken when using `iwd`. Use `wpa_supplicant`.
- WiFi hotspot / repeater mode doesn't work.
- S3 suspend may cause a black screen on wake. s2idle (s0ix) works.
- Some kernel panics reported on ASUS boards with the AW-XB552NF card.
- If BT firmware conflicts with the WiFi driver, remove the duplicate:
  `sudo rm /lib/firmware/mediatek/mt7902/BT_RAM_CODE_MT7902_1_1_hdr.bin.zst`

### Kernel panic on some hardware

On certain devices (e.g. ASUS Vivobook with i3-1315U), the driver may cause a kernel panic during initialization when the MCU is in a "cold" (uninitialized) state. This has been partially mitigated with defensive patches in the driver code. If you still experience panics:

```sh
# Temporary workaround: blacklist the module to prevent loading
echo "blacklist mt7902" | sudo tee /etc/modprobe.d/blacklist-mt7902.conf
```

The driver includes multiple layers of protection against cold-MCU panics:
- **PCIe power cycle** at probe time forces MCU to re-initialize
- **Retry mechanism** with configurable attempts and delay (default: 3 retries, 2s apart)
- **Late-load service** (`mt7902-late.service`) defers loading until PCIe is stable
- **Extended timeouts** (8s for LP_OWN handshake instead of 2s)

To tune retry behavior for your hardware:
```sh
# Basic retry tuning
sudo modprobe mt7902 init_retry=5 init_delay_ms=5000

# Aggressive stability options (try if basic retry fails)
# 1. Disable Runtime PM (prevents sleep/wake crashes)
sudo modprobe mt7902 disable_rpm=1

# 2. Increase Command Timeout (prevents "No response from chip" errors)
sudo modprobe mt7902 cmd_timeout_ms=8000

# 3. Nuclear Option (Bypass MCU/Chip ID checks)
# Use this if the card is completely dead/unresponsive but you want to force load.
sudo modprobe mt7902 mcu_bypass=1
```

### Stock driver conflict

The kernel's built-in `mt7921e` / `mt7902e` / `mt76_connac_lib` drivers conflict with this driver. The installer blacklists them automatically, but if you installed manually, create the blacklist yourself:

```sh
sudo tee /etc/modprobe.d/blacklist-mt7921.conf > /dev/null <<'EOF'
blacklist mt7921e
blacklist mt7902e
blacklist mt7921_common
blacklist mt76_connac_lib
EOF
sudo update-initramfs -u   # or mkinitcpio -P (Arch) / dracut --force (Fedora)
```

### Hardware latchup (dead WiFi after crash)

If the driver crashes or hangs, the MT7902 PCIe controller can lock up completely. Symptoms:
- `modprobe mt7902` fails immediately
- `dmesg` shows BAR0 read errors
- Driver loads but WiFi interface never appears

**Recovery:** You must perform a full power drain:
1. Shut down the laptop completely
2. Unplug the AC adapter / charger
3. Hold the **Power button for 40 seconds**
4. Plug back in and boot

If WiFi becomes flaky, reload the module:

```sh
sudo rmmod mt7902 && sudo modprobe mt7902
```

## Tested hardware

- WMDM-257AX
- AW-XB552NF (see known issues above)

Should work on other MT7902-based PCIe cards. Minimum kernel: 5.4.

## Tested on

| System | Kernel | WiFi | Bluetooth |
|--------|--------|------|-----------|
| Arch Linux (x86_64) | 6.18.9-arch1-2 | ✅ Working | ✅ Working |

## Upstream Patch Integration

MediaTek officially submitted an 11-patch series for MT7902 to the `linux-wireless` mailing list on 2026-02-19 (author: `sean.wang@kernel.org`). The applicable fixes have been forward-ported into this out-of-tree driver:

| Patch | Description | Status |
|-------|-------------|--------|
| [PATCH 03/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-3-sean.wang@kernel.org/) | irq_map quirk (mutable copy) | Architecture differs — not applied |
| [PATCH 04/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-4-sean.wang@kernel.org/) | MT7902e DMA layout | ✅ Already correct in gen4 driver |
| [PATCH 05/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-5-sean.wang@kernel.org/) | Mark MT7902 as hw txp | ✅ Already enabled in gen4 driver |
| [PATCH 06/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-6-sean.wang@kernel.org/) | PSE buffer underflow barrier | ✅ **Applied** — `mgmt/rlm_domain.c` |
| [PATCH 07/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-7-sean.wang@kernel.org/) | Ensure MCU ready before ROM patch download | ✅ **Applied** — `chips/common/fw_dl.c` |
| [PATCH 08/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-8-sean.wang@kernel.org/) | MT7902 MCU support + firmware paths | ✅ Already present in gen4 driver |
| [PATCH 09/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-9-sean.wang@kernel.org/) | WFDMA prefetch configuration | ✅ Already correct in gen4 driver |
| [PATCH 10/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-10-sean.wang@kernel.org/) | MT7902 PCIe device support | Architecture differs — not applied |
| [PATCH 11/11](https://lore.kernel.org/linux-wireless/20260219004007.19733-11-sean.wang@kernel.org/) | MT7902 SDIO device support | Architecture differs — not applied |

### Key fixes applied

**PATCH-07 — MCU ready check** (`chips/common/fw_dl.c`)  
Before downloading the ROM patch, the driver now resets the MCU sync register and polls for the `FW_PWR_ON` bit (up to 1 s). This prevents cold-boot firmware download failures on affected systems.

**PATCH-06 — PSE barrier read** (`mgmt/rlm_domain.c`)  
After sending large txpower MCU commands, a dummy read from the PSE base register (`0x820c8000`) is performed. This prevents a hardware PSE buffer underflow that could silently corrupt MCU command delivery.

## Fixes on top of hmtheboy154/mt7902

hmtheboy154/mt7902 stopped at MediaTek's February 2026 series and was archived
in September 2026. `mt7902/` carries these on top, one commit each:

| Fix | Source | What it addresses |
|-----|--------|-------------------|
| associate on kernels < 6.15 | hmtheboy154/mt7902 PR #22 + #16 | `failed to insert STA entry for the AP (error -22)` |
| shutdown / rmmod oops < 6.9 | Payton9000/mt7902 `8715c7b4fc` | freeze at power-off on 6.8 |
| build on 6.11 | — | `pcim_iomap_region` only exists from 6.12 |
| `disable_aspm` works again | mainline `2dd788562234` | ASPM L1 could not be disabled on 6.9+ |
| keep join ROC until authorized | wireless tree `6f591a4bb5d9` | 4-way handshake timeouts (reason 15) |
| suspend/resume lock inversion | wireless tree `0e6472108d51`, `3dcb98c5cb51` | deadlock on resume |
| check drv_pmctrl on PCIe reset | wireless tree `75673ab3c0e4` | reset path |
| ACPI SAR fixes | mainline `45f53d98cbaa`, `af97bf5a7e72`, `7825de3f75d1` | slow 5 GHz on ASUS laptops, NULL dereference |
| CLC record validation | mainline `9417c5818a01`, `1a296bfd3e77` | malformed firmware country records |

The Bluetooth build adds the MT7902 USB IDs upstream has (`0489:e156`,
`0e8d:1ede`, `13d3:3579/3580/3594/3596`) to trees that lack them.

All of the above is compile-tested against Ubuntu 6.8, 6.11, 6.14, 6.17 and
7.0 headers in CI.

## Upstream sync

Once a week a workflow checks morrownr/mt76 and mt7902_temp. If either moved,
it updates the single `upstream-sync` branch and its pull request; the build
workflow then shows whether the result still compiles. `mt7902/` and
`gen4-mt7902/` are not synced — they carry local fixes.

## Credits

This project wouldn't exist without the work of:

- **[hmtheboy154](https://github.com/hmtheboy154)** — WiFi driver ([gen4-mt7902](https://github.com/hmtheboy154/gen4-mt7902)). Extracted the `gen4-mt79xx` driver from Xiaomi's rodin BSP and adapted it for MT7902. Also contributes to [BlissOS](https://blissos.org/).

- **[OnlineLearningTutorials](https://github.com/OnlineLearningTutorials)** — Bluetooth driver and firmware ([mt7902_temp](https://github.com/OnlineLearningTutorials/mt7902_temp)). Patched `btusb`/`btmtk` for MT7902 support and provides all the firmware files.

- **[morrownr](https://github.com/morrownr) and contributors** — [mt76](https://github.com/morrownr/mt76), the out-of-tree build of mainline mt76 bundled in `mt76/`.

- **Payton9000, antonionesta, EdinsonMoreno** — fixes for the archived hmtheboy154/mt7902 that are carried in `mt7902/`.

- **[MediaTek / sean.wang](https://lore.kernel.org/linux-wireless/?q=mt7902)** — Official upstream MT7902 patch series for the `mt76` kernel driver (Feb 2026); key fixes forward-ported into this driver.

Community discussion happens on [Discord](https://discord.gg/JGhjAxEFhz).

## License

See the individual subdirectories for license details. `mt7902_temp/`, `mt7902/` and `mt76/` are GPL v2.0; `firmware/` is under `firmware/LICENSE.mediatek`.
