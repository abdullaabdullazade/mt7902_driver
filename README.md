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

| Kernel | What to use | Notes |
|--------|-------------|-------|
| **7.1 and newer** | in-tree `mt7921e` | Nothing to install. `install.sh` detects this and exits early. |
| **6.6 – 7.0** | [hmtheboy154/mt7902](https://github.com/hmtheboy154/mt7902) | Mainline mt76 + MediaTek's MT7902 series, backported. `install.sh` uses it by default. Its README says 6.6~6.19, but the tree builds clean against 7.0 too — verified here against the `7.0.0-070000-generic` headers — which matters because 7.0 has no in-tree support either. |
| **older than 6.6** | bundled `gen4-mt7902` | Vendor tree; frequently fails MCU init. Last resort. |

Firmware ships in `linux-firmware` as of its 20260309 release. If your system
already has it, `install.sh` leaves those files alone rather than overwriting
them with the copies bundled here.

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

Prerequisites: `build-essential`, `linux-headers`, `dkms`, `zstd`. The script installs these automatically for Debian/Fedora/Arch/openSUSE.

```sh
git clone https://github.com/abdullaabdullazade/mt7902_driver
cd mt7902_driver
sudo ./install.sh            # installs both wifi + bluetooth
```

Reboot after installing.

You can also install components separately:

```sh
sudo ./install.sh --wifi     # wifi driver + firmware only
sudo ./install.sh --bt       # bluetooth driver + firmware only
sudo ./install.sh --all      # both (same as no flag)
sudo ./install.sh --no-dkms  # skip DKMS, compile manually
```

### Automatic driver selection

The installer picks the driver that suits your kernel, in this order:

1. **In-tree `mt7921e`**, if `modinfo mt7921e` shows the `14c3:7902` alias
   (kernel 7.1+). Nothing is built, nothing is blacklisted.
2. **[hmtheboy154/mt7902](https://github.com/hmtheboy154/mt7902)** — mainline
   mt76 with MediaTek's MT7902 patches — on kernel 6.6 and newer.
3. **Bundled `gen4-mt7902`**, only if the above did not work. After loading it
   the installer checks that `mt7902` is in `lsmod`, that `dmesg` is clean, and
   that a `wlan*` / `wlp*` / `wlo*` interface appeared; if not, it removes the
   driver again rather than leaving a half-installed system behind.

gen4-mt7902 is tried last on purpose: it is a vendor tree that frequently fails
MCU init on this card (`wlanAccessRegister: Event reports address incorrect`,
`Fail reason: 4`), which is what its `mcu_bypass` and `disable_rpm` options
exist to work around.

To override the order:

```sh
sudo ./install.sh --fallback      # go straight to hmtheboy154/mt7902
sudo ./install.sh --gen4          # try the bundled vendor driver first
sudo ./install.sh --force-custom  # build even if the kernel has in-tree support
```

Or install it manually:

```sh
git clone https://github.com/hmtheboy154/mt7902
cd mt7902
sudo make install -j$(nproc)
sudo make install_fw          # install firmware
```

See [hmtheboy154/mt7902](https://github.com/hmtheboy154/mt7902) for more details.

## Uninstall

```sh
sudo ./uninstall.sh          # remove everything
sudo ./uninstall.sh --wifi   # wifi only
sudo ./uninstall.sh --bt     # bluetooth only
sudo ./uninstall.sh --keep-fw  # keep firmware files
```

## How it works

**WiFi** — The `gen4-mt7902/` directory contains a kernel module based on MediaTek's `gen4-mt79xx` driver (originally from Xiaomi's BSP). It builds a `mt7902.ko` module and registers it via DKMS so it auto-rebuilds on kernel updates.

**Bluetooth** — The `mt7902_temp/` directory contains patched `btusb` and `btmtk` kernel modules for different kernel versions (6.14–6.19). The installer picks the version closest to your running kernel, compiles it, and replaces the stock modules (backing up the originals first).

**Firmware** — Both WiFi and BT firmware files are included in `mt7902_temp/mt7902_firmware/` and get copied to `/lib/firmware/mediatek/`.

## Repository layout

```
├── install.sh              # unified installer
├── uninstall.sh            # clean removal
├── gen4-mt7902/            # wifi driver source
│   ├── Makefile
│   ├── dkms.conf
│   ├── firmware/
│   ├── chips/, common/, include/, mgmt/, nic/, os/, ...
│   └── ...
├── mt7902_temp/            # bluetooth driver + firmware
│   ├── mt7902_firmware/    # all firmware (wifi + bt)
│   ├── linux-6.14/ … linux-6.19/
│   │   └── drivers/bluetooth/   # patched btusb + btmtk
│   └── ...
└── .github/workflows/
    └── sync-upstream.yml   # daily upstream sync
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

## Upstream sync

A GitHub Actions workflow runs daily and checks both upstream repos for new commits. If anything changed, it opens a pull request automatically. You can also trigger it manually from the Actions tab.

## Credits

This project wouldn't exist without the work of:

- **[hmtheboy154](https://github.com/hmtheboy154)** — WiFi driver ([gen4-mt7902](https://github.com/hmtheboy154/gen4-mt7902)). Extracted the `gen4-mt79xx` driver from Xiaomi's rodin BSP and adapted it for MT7902. Also contributes to [BlissOS](https://blissos.org/).

- **[OnlineLearningTutorials](https://github.com/OnlineLearningTutorials)** — Bluetooth driver and firmware ([mt7902_temp](https://github.com/OnlineLearningTutorials/mt7902_temp)). Patched `btusb`/`btmtk` for MT7902 support and provides all the firmware files.

- **[MediaTek / sean.wang](https://lore.kernel.org/linux-wireless/?q=mt7902)** — Official upstream MT7902 patch series for the `mt76` kernel driver (Feb 2026); key fixes forward-ported into this driver.

Community discussion happens on [Discord](https://discord.gg/JGhjAxEFhz).

## License

See the individual subdirectories for license details. `mt7902_temp/` is under GPL v2.0.
