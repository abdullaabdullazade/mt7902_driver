# MT7902 driver for Linux

[![Build](https://github.com/abdullaabdullazade/mt7902_driver/actions/workflows/build.yml/badge.svg)](https://github.com/abdullaabdullazade/mt7902_driver/actions/workflows/build.yml)

WiFi and Bluetooth for the **MediaTek MT7902** (`14c3:7902`, Filogic 310) on
Linux kernels that do not support it yet. One command, works offline, survives
kernel updates, and removes cleanly.

> **On kernel 7.1 or newer you do not need this.** The card is supported by the
> kernel itself. Check:
>
> ```sh
> modinfo mt7921e | grep -i 7902   # any output = your kernel already supports it
> ```
>
> Running `install.sh` there is harmless: it detects this and installs nothing.

## Install

```sh
git clone https://github.com/abdullaabdullazade/mt7902_driver
cd mt7902_driver
sudo ./install.sh
```

That is all. It installs the build tools and the headers for your running
kernel, builds WiFi and Bluetooth, checks the card actually works, and reboots.
No internet connection is needed during the install — everything it builds is
in this repository.

Works on Debian/Ubuntu and derivatives (Mint, Pop!_OS, Zorin, …), Fedora,
Arch and derivatives (Manjaro, EndeavourOS, CachyOS, …) and openSUSE.

### Options

| Option | What it does |
|---|---|
| `--wifi` / `--bt` | install only WiFi or only Bluetooth |
| `--mt76` | try the newer mt76 driver first (kernel 6.12+) |
| `--no-dkms` | build without DKMS (you rebuild after each kernel update) |
| `--no-reboot` | do not reboot at the end |
| `--clean-firmware` | remove stale firmware copies left by older versions of this installer |
| `--force-custom` | build a driver even on a kernel that supports the card |
| `--upgrade-kernel` | move to a kernel with built-in support instead (see below) |

## Uninstall

```sh
sudo ./uninstall.sh            # everything; --wifi / --bt / --keep-fw / --no-reboot
```

Removes every driver this repository installs (including ones from older
versions of it) and gives back the distribution's own modules. Files that
belong to a package are never touched.

## Which driver you get

| Your kernel | Driver |
|---|---|
| 7.1 and newer | the kernel's own — nothing is installed |
| 6.12 – 7.0 | `mt7902e`; if it does not work, `mt76` |
| 6.6 – 6.11 | `mt7902e` |
| older than 6.6 | `gen4-mt7902` (vendor driver, often unreliable — upgrading the kernel is better) |

Each driver is checked after loading — the card must be bound, an interface
must appear and the firmware must answer. If not, it is removed again and the
next one is tried, so only one driver is ever left on the system. Everything is
registered with DKMS and rebuilt automatically on kernel updates.

## Tested on

Real card (AzureWave `1a3b:5520`, in an ASUS Vivobook X1605VA) passed through
to a virtual machine of each distribution, with no network other than the card:

| Distribution | Kernel | Driver | WiFi | Bluetooth | Shutdown |
|---|---|---|---|---|---|
| Ubuntu 24.04 | 6.8 | `mt7902e` | ✅ | ✅ | ✅ |
| Ubuntu 24.04 HWE | 7.0 | `mt7902e` | ✅ | ✅ | ✅ |
| Ubuntu 24.04 HWE | 7.0 | `mt76` (`--mt76`) | ✅ | ✅ | ✅ |
| Fedora 43 | 6.17 | `mt7902e` | ✅ | ✅ | ✅ |
| Fedora 43 | 7.2 | built-in | ✅ | ✅ | ✅ |
| Arch Linux (`linux-lts`) | 6.18 | `mt7902e` | ✅ | ✅ | ✅ |
| Arch Linux | 7.2 | built-in | ✅ | ✅ | ✅ |

WiFi = scan on 2.4 and 5 GHz, connect on 5 GHz, ping. Bluetooth = controller up
with firmware 20250826. Every run also covered unloading and reloading the
driver and an uninstall that left the system as it was.

Earlier users also reported WMDM-257AX and AW-XB552NF cards working, and Arch
on 6.18.9.

Not tested yet: suspend/resume, Secure Boot enrollment, other laptops — reports
welcome.

<details>
<summary>Compared with the previous version of this installer</summary>

Same card, same machines, same kernels:

| | Previous version | This version |
|---|---|---|
| Shutdown on Ubuntu 6.8 | kernel crash, machine hangs | clean |
| Bluetooth on Fedora | did not work | works |
| Bluetooth firmware on Arch | a 2022 build | current (2025) |
| After uninstall | the distribution's firmware was deleted | untouched |
| Install without internet | fell back to a driver that hangs | works |

</details>

## Troubleshooting

**Secure Boot: "Key was rejected by service".** The driver is signed, but your
firmware does not know the key yet. The installer prints the exact
`mokutil --import …` command: run it, reboot, choose *Enroll MOK* in the blue
screen, and enter the password you just set.

**"Your kernel's own modules are missing".** Minimal installs can lack the
kernel's WiFi/Bluetooth base modules. Install the package the message names
(e.g. `kernel-modules` on Fedora, `linux-modules-extra` on Ubuntu) and run the
installer again.

**WiFi dead after a crash.** The card can lock up until it loses power. Shut
down, unplug the charger, hold the power button for 40 seconds, then boot.

**Old firmware.** If you used an older version of this installer, it may have
left firmware copies that hide your distribution's newer ones. `install.sh`
lists them; `sudo ./install.sh --clean-firmware` removes them.

**Reporting a problem.** Attach the installer output, `sudo dmesg`, and the
logs in `/var/lib/mt7902-driver/`.

<details>
<summary>Options of the gen4 vendor driver (kernels older than 6.6 only)</summary>

```sh
sudo modprobe mt7902 init_retry=5 init_delay_ms=5000   # more init retries
sudo modprobe mt7902 disable_rpm=1                     # no runtime power management
sudo modprobe mt7902 cmd_timeout_ms=8000               # longer firmware timeouts
sudo modprobe mt7902 mcu_bypass=1                      # force load an unresponsive card
```

</details>

## Moving to a kernel with built-in support

| Distribution | How to get 7.1 or newer |
|---|---|
| Arch, openSUSE Tumbleweed | `sudo pacman -Syu` / `sudo zypper dup` |
| Fedora | `sudo dnf upgrade --refresh` |
| Ubuntu / Debian | a newer release, or `sudo ./install.sh --upgrade-kernel` |

`--upgrade-kernel` installs an unsigned mainline kernel on Debian/Ubuntu: it
does not boot with Secure Boot (the installer checks and refuses), and you
update it yourself. On the new kernel, run `sudo ./uninstall.sh` once and
reboot; the built-in driver then takes over.

## What is inside

```
install.sh, uninstall.sh   the installer
firmware/                  MT7902 WiFi + Bluetooth firmware, identical to linux-firmware
mt7902/                    mt7902e — default WiFi driver, with the fixes below
mt76/                      mt76 — newer WiFi driver for 6.12+
gen4-mt7902/               vendor WiFi driver, last resort
bluetooth-dkms/            builds Bluetooth for each kernel through DKMS
mt7902_temp/               Bluetooth sources per kernel version
```

<details>
<summary>Fixes carried in <code>mt7902/</code></summary>

| Fix | Source |
|---|---|
| Associate on kernels before 6.15 (`error -22`) | community, hmtheboy154/mt7902 #16 / #22 |
| No crash at shutdown on kernels before 6.9 | community, Payton9000/mt7902 |
| Builds on kernel 6.11 | this repository |
| `disable_aspm` works again | Linux mainline `2dd788562234` |
| Fewer 4-way handshake timeouts | wireless tree `6f591a4bb5d9` |
| No deadlock on suspend/resume | wireless tree `0e6472108d51`, `3dcb98c5cb51` |
| PCIe reset error check | wireless tree `75673ab3c0e4` |
| ACPI SAR fixes (slow 5 GHz on some ASUS laptops) | mainline `45f53d98cbaa`, `af97bf5a7e72`, `7825de3f75d1` |
| Validate firmware country records | mainline `9417c5818a01`, `1a296bfd3e77` |

Bluetooth also gets every MT7902 USB ID the mainline kernel knows
(`0489:e156`, `0e8d:1ede`, `13d3:3579/3580/3594/3596`).

</details>

A weekly workflow keeps `mt76/` and the Bluetooth sources in sync with their
upstreams through a single pull request, and every change is built against
Ubuntu 6.8, 6.11, 6.14, 6.17 and 7.0 before it is merged.

## Credits

Built on the work of [hmtheboy154](https://github.com/hmtheboy154) (mt7902e and
gen4 drivers), [morrownr](https://github.com/morrownr/mt76) (mt76),
[OnlineLearningTutorials](https://github.com/OnlineLearningTutorials/mt7902_temp)
(Bluetooth), MediaTek's upstream MT7902 work, and the community fixes listed
above. Discussion: [Discord](https://discord.gg/JGhjAxEFhz).

## License

GPL-2.0 for the drivers (see each directory). Firmware: `firmware/LICENSE.mediatek`.
