# mt7902-linux

Out-of-tree WiFi and Bluetooth drivers for the **MediaTek MT7902** M.2 PCIe wireless card on Linux.

The MT7902 is not supported by the mainline `mt76` kernel driver yet. This repo bundles the two community-maintained driver projects into one place so you can get both WiFi and Bluetooth working with a single install command.

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
sudo modprobe mt7902 init_retry=5 init_delay_ms=5000
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

## Upstream sync

A GitHub Actions workflow runs daily and checks both upstream repos for new commits. If anything changed, it opens a pull request automatically. You can also trigger it manually from the Actions tab.

## Credits

This project wouldn't exist without the work of:

- **[hmtheboy154](https://github.com/hmtheboy154)** — WiFi driver ([gen4-mt7902](https://github.com/hmtheboy154/gen4-mt7902)). Extracted the `gen4-mt79xx` driver from Xiaomi's rodin BSP and adapted it for MT7902. Also contributes to [BlissOS](https://blissos.org/).

- **[OnlineLearningTutorials](https://github.com/OnlineLearningTutorials)** — Bluetooth driver and firmware ([mt7902_temp](https://github.com/OnlineLearningTutorials/mt7902_temp)). Patched `btusb`/`btmtk` for MT7902 support and provides all the firmware files.

- **[goracle](https://github.com/goracle)** — Experimental driver fork ([gen4-mt7902](https://github.com/goracle/gen4-mt7902)) with stability improvements, PCIe latchup recovery docs, and AIS FSM rewrites.

Community discussion happens on [Discord](https://discord.gg/JGhjAxEFhz).

## License

See the individual subdirectories for license details. `mt7902_temp/` is under GPL v2.0.
