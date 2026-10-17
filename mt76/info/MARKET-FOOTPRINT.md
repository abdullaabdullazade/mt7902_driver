# MediaTek Linux WiFi Market Footprint

A data-driven survey of which **MediaTek WiFi adapters and modules** are most commonly used by Linux users, across USB, PCIe/M.2, and SDIO form factors. Intended as input to the firmware-shipping decisions for [`morrownr/mt76`](https://github.com/morrownr/mt76).

Every claim cites a primary source. Every figure is time-stamped. Kernel anchoring to torvalds/linux HEAD `d730905bc3c0`; linux-firmware to gitlab HEAD `3fc7117bb925`; morrownr/mt76 to `131771025d08` (all 2026-04-17).

## The question

[`morrownr/mt76` issue #5](https://github.com/morrownr/mt76/issues/5) asks, in essence: *what are the most commonly used devices within the scope of this repo?*

## Scope

- **MediaTek-chipset adapters and modules** for **desktop, laptop, mini-PC, SBC, gaming handheld, and Chromebook** Linux users.
- Form factors covered: USB, PCIe / M.2, SDIO.
- **Consumer / prosumer devices.** Not router SoCs, not TVs, not phones (except where a SoC pairs with mt76 silicon for client WiFi on a consumer-accessible board like the BananaPi BPI-R4).
- **Linux usage signal.** What Linux users actually run, plus the cross-OS retail volume that reveals cheap-OEM populations invisible to Linux-specific discourse.

## Top-line answer

Tier 1 chip *families* that should ship firmware for `morrownr/mt76` (each covers PCIe + USB + SDIO variants where they exist; firmware sharing per kernel source):

| Chip family | Driver(s) | Form factors | Where it actually ships | Install-base signal |
|-------------|-----------|--------------|-------------------------|---------------------|
| **MT7921 / MT7921K (RZ608)** | mt7921e + mt7921u + mt7921s | PCIe M.2 + USB + SDIO | Lenovo ThinkPad E15 Gen 3 (dominant on linux-hardware.org top-host list), ThinkPad T14s, Dell Inspiron 14/16 5425/5625/5435/5635, HP Pavilion/Victus; AMD RZ608 laptops via Foxconn T99H245; Beelink SER5 / GMKtec K6 mini-PCs; USB: Netgear A8000/A7500, Alfa AWUS036AXML; ChromeOS Kompanio SoCs via SDIO | **6,351 PCIe probes** (4,714 @ 14c3:7961 + 1,637 @ 14c3:0608). Earliest probe Feb 2022. Generic `0e8d:7961` AliExpress USB listing: **10,000+ lifetime orders** |
| **MT7922 (RZ616)** | mt7921e (PCIe-only) | PCIe M.2 | Lenovo ThinkPad L/T AMD Gen 3-4, HP EliteBook 6xx/8xx G10-G11 + ProBook 445/455 G10, Framework Laptop 13/16, System76 Pangolin / Thelio R5-N1 (AW-XM514NF soldered), Tuxedo InfinityBook AMD Gen10; **gaming handhelds** ASUS ROG Ally (2023) + Ally X (2024) + Lenovo Legion Go (2023) + Legion Go S (2025); mini-PCs **GMKtec M6 Ultra** (829 Amazon reviews -- biggest single MediaTek PCIe consumer volume channel), Minisforum UM890 Pro | **5,538 PCIe probes** (4,758 @ 14c3:0616 + 780 @ 14c3:7922). Fenvi MT7922 PCIe card family on AliExpress: **~10,000+ lifetime orders across 3 listings** |
| **MT7925 (RZ717)** | mt7925e + mt7925u | PCIe M.2 + USB | HP OmniBook 7 14/16 (largest consumer driver), Lenovo ThinkPad T14 Gen 6 AMD / Yoga 7 / ThinkBook 16 G7+; Framework Laptop 13 Ryzen AI 300 + Framework Desktop default; System76 Thelio Mira r4-n4; **Slimbook Executive 2026** (Linux-first vendor, NEW finding); Ubuntu Certified HP ZBook 8 G1ah, Dell Pro Precision 9 Tower T2, Lenovo ThinkStation P8; USB: Netgear A9000 | **1,105 PCIe probes** (866 @ 14c3:7925 + 239 @ 14c3:0717). Earliest probe Apr 2024; ramping hard. Framework sells module separately at CAD $40 (~USD $29) |
| **MT7902** | mt7921e (PCIe-only) | PCIe M.2 + SDIO ID assigned | ASUS VivoBook X1605VA / K6602VV / K3605ZU family (all top-10 LHW hosts are ASUS VivoBook SKUs), HP Laptop 15-fd, Acer Aspire A315-24P / A314-23P / A315-59G | **1,510 PCIe probes**. Driver in torvalds master (Sean Wang 11-patch series, authored 2026-02-18/19, committed by Felix Fietkau nbd tree 2026-03-24). Wi-Fi 6E 1x1 (NOT Wi-Fi 7). Earliest probe Nov 2023 |
| **MT7920** | mt7921e (PCIe-only) | PCIe M.2 | Lenovo ThinkPad E14 Gen 7 AMD + E16 Gen 3 AMD (PSREF-explicit MediaTek Wi-Fi 6 MT7920); Lenovo IdeaPad Slim 3 14AHP10 83K9; THUNDEROBOT R15; Acer Aspire AG15-71P | 71 PCIe probes -- young chip, Apr 2025 earliest probe |
| **MT7612 / MT7662** | mt76x2e + mt76x2u | PCIe + USB | Alfa AWUS036ACM (USB; 393 Mb/s in `morrownr/USB-WiFi` Speed_Comparison_Test), Netgear A6210 (**5,100 Amazon reviews -- highest MediaTek USB on Amazon US**), AVM FRITZ!WLAN AC 860 (DACH staple, 158 linux-hardware.org probes), Microsoft Xbox One Wireless Adapter | Shared `mt7662.bin` serves PCIe + USB per kernel source: both `mt76x2/{pci,usb}.c` declare `MODULE_FIRMWARE(MT7662_FIRMWARE)` |
| **MT7610** | mt76x0e + mt76x0u | PCIe (~0) + USB | Alfa AWUS036ACHM (USB; "absolute goat" for range on Reddit), TP-Link TL-WDN5200, AVM FRITZ!WLAN USB Stick AC 430 | Highest Stack Exchange help-volume of any mt76 USB chip (19 questions, 289K total views). mt7610e.bin (PCIe) and mt7610u.bin (USB) are **distinct blobs**, not shared (kernel `mt76x0/mt76x0.h` defines separate `#define` macros) |
| **MT7663U / MT7663E** | mt7615 (USB stub + PCIe) | PCIe + USB | Legacy: Acer Aspire A315/A317 notebook family (54 LHW probes); minimal retail USB-stick presence; LG OEM module `043e:310c` | Firmware `mt7663_n9_v3.bin` + `mt7663pr2h.bin` already upstream |

### Gaming handheld coverage (English-speaking market 2023-2026)

| Device | Launch | Chip | Driver | Source |
|--------|--------|------|--------|--------|
| ASUS ROG Ally (Z1/Z1 Extreme) | 2023 | **MT7922 / RZ616** | mt7921e | iFixit teardown |
| ASUS ROG Ally X | 2024 | **MT7922** | mt7921e | iFixit teardown |
| ASUS ROG Xbox Ally / Ally X | 2025 | Likely **MT7925** (WiFi 7 per driver bundle) | mt7925e | ASUS driver package |
| Lenovo Legion Go | 2023 | **MT7922 / RZ616** | mt7921e | Amazon listing + Lenovo support |
| Lenovo Legion Go S | 2025 | **MediaTek** (Lenovo driver catalogue) | mt7921e | Lenovo WLAN driver page |
| AOKZOE A1 | 2023 | **RZ608 / MT7921** | mt7921e | Community + spec |
| MSI Claw A1M / Claw 8 AI+ | 2024/2025 | Intel Killer BE1750 (no MediaTek) | -- | MSI spec |
| AyaNeo Kun | 2024 | Intel AX210 (no MediaTek) | -- | Spec sheet |
| Valve Steam Deck LCD | 2022 | Realtek RTL8822CE (no MediaTek) | -- | iFixit |
| Valve Steam Deck OLED | 2023 | Qualcomm Quectel FC66E (no MediaTek) | -- | iFixit |
| GPD Win 4 / Win Max 2 / Pocket 4 | 2023-2025 | "Wi-Fi 6E" unspecified | -- | Spec lists no chip |
| OneXPlayer, most other AyaNeo, Anbernic, AOKZOE A1 Pro | -- | "Wi-Fi 6E" unspecified | -- | Specs silent on chip |

### AI PC / Copilot+ PC segment (2024-2026)

- **AMD Ryzen AI 300 / Strix Point / Strix Halo**: **MT7925 (RZ717) dominant**. Framework Laptop 13 + Desktop defaults, System76 Thelio Mira, Tuxedo, Slimbook Executive, most Chinese Strix Halo mini-PCs (GMKtec EVO-X2, FEVM FAEX1).
- **Snapdragon X Copilot+ PCs** (Surface Laptop 7, Surface Pro 11, Dell XPS 13 9345, HP OmniBook X, Lenovo Yoga Slim 7x, Samsung Galaxy Book 4 Edge, ASUS Vivobook S 15 Snapdragon): **100% Qualcomm FastConnect 7800, zero MediaTek.**
- **Intel Core Ultra 200V (Lunar Lake)**: Intel Killer BE1750 / BE200 dominant, **zero MediaTek** SKU located.
- **Apple M4**: Broadcom BCM4388 (moving to in-house silicon), **zero MediaTek**.

### ChromeOS (Chromebook Plus) segment -- MediaTek's strongest 2024-2026 laptop segment

MediaTek Kompanio SoCs (838 + Ultra 910) pair with MT7921S (SDIO) for integrated WiFi on:
- Lenovo Chromebook Duet Gen 9 (Kompanio 838)
- Acer Chromebook Plus Spin 514 (Kompanio Ultra 910)
- Lenovo Chromebook Plus 14
- ASUS Kompanio 520 Chromebooks

Few-million-unit EDU channel volume. linux-hardware.org materially under-counts this population because hw-probe is rarely run on ChromeOS.

### Mini-PC segment

Confirmed MediaTek shippers: **GMKtec M6 Ultra** (MT7922, 829 Amazon reviews -- alone exceeds combined review volume of every standalone MediaTek PCIe/M.2 card ASIN on Amazon US), GMKtec M5 Ultra / NucBox K6, Minisforum UM890 Pro, Beelink SER5 (MT7921K, 119 reviews), Geekom A7/GT13 Pro/XT12 Pro (MT7922 via AzureWave AW-XB591NF).

Confirmed non-MediaTek: Apple Mac mini M4 (Broadcom BCM4388), Minisforum UM790 Pro (Killer AX1675), Beelink SER8 (Intel AX200), Beelink Mini S12 Pro (Intel AX101), Mini S12 (Realtek), NiPoGi GK3 Plus (Realtek), Intel NUC 13, ASUS NUC 14/15 (Intel).

### Business desktop / workstation / AIO segment

MediaTek adoption in this segment is **AMD-gated**:

Confirmed MediaTek: Lenovo ThinkCentre M75q Gen 5 Tiny (MT7921 AND MT7925 BTO options per PSREF 2026-03-13), Acer Veriton X4240G (MT7921 per driver PCI ID), **HP Z2 Mini G1a (AMD Strix Halo workstation -- MediaTek MT7925 + BT 5.4, first HP Z-series workstation with MediaTek per HP QuickSpecs c09133726)**.

Confirmed non-MediaTek: Lenovo ThinkStation P3 Tower/Tiny/Ultra + P5 + P7 + P8 (Intel AX211 or AMD RZ616 which IS MT7922 but Lenovo brands as AMD not MediaTek), ThinkCentre M75s Gen 5 SFF (Realtek + RZ616), M90a Gen 6 AIO (Intel/Realtek), Dell OptiPlex 7020 Plus/Micro/SFF, Dell Precision 3680, HP EliteDesk 800 G9, HP Z2 G9 workstations, Apple Mac Studio / Mac Pro M4 (Broadcom).

### Distro LTS kernel landing matrix (2026-04-17)

| Chip | Mainline kernel | Ubuntu 24.04 LTS (6.8/6.14 HWE) | Debian 13 trixie (6.12) | Debian 12 (6.1) | Fedora 42 (6.14) | Fedora 43 (6.17) | openSUSE Leap 16 (6.12) |
|------|-----------------|-------------------------------|----------------------|-----------------|------------------|------------------|-------------------------|
| MT7921 | 5.12 | yes | yes | yes | yes | yes | yes |
| MT7922 | 5.16 | yes | yes | yes | yes | yes | yes |
| MT7925 | 6.7 | HWE only | yes | no | yes | yes | yes |
| MT7920 | 6.10 | HWE only | yes | no | yes | yes | yes |
| MT7902 | in mainline master via nbd tree 2026-03-24; v7.1 release track | not yet (6.14 HWE) | not yet | no | not yet | yes (6.17 reached) | not yet |
| MT7927 | not upstream | -- | -- | -- | -- | -- | -- |
| MT7612/7662, MT7610, MT7663 | 4.x | yes | yes | yes | yes | yes | yes |

Bottom line: MT7921/MT7922 are universally supported on current-LTS distros. MT7925/MT7920 require Debian 13+, Fedora 41+, Leap 16, or Ubuntu 24.04 HWE. MT7902 needs kernel 6.17+ (Fedora 43 today, else wait for distro bumps). MT7927 needs distro kernels that don't exist yet. RHEL is not included in the matrix: Red Hat's selective cherry-pick of driver patches across kernel versions makes "what's supported on RHEL N" unreliable to state in a general table -- a Red Hat user should confirm against their own installed kernel and rpm inventory.

### Security / CVE summary (19+ confirmed CVEs as of 2026-04-17)

Across MediaTek-CNA pool (silicon/firmware) and kernel-CNA pool (mt76 driver): **19+ CVEs touching MT79xx chips since 2024**. Highlights:

- **CVE-2025-20672** (Bluetooth heap overflow, CVSS 9.8 Critical) -- MediaTek-CNA, affects MT792x BT firmware
- **CVE-2024-26892**, **CVE-2024-27049**, **CVE-2024-46860**, **CVE-2024-57989**, **CVE-2025-39862** -- kernel-CNA mt76 driver UAFs / NULL derefs / list corruption (CVSS 5.5-7.8)
- **CVE-2026-20423**, **CVE-2026-20436** -- WLAN STA OOB writes, High, published March 2026

MT7925 lifetime CVE count across both CNAs: **11+ (not 7 as earlier count suggested)**. MT7921 family: 9+ kernel-side CVEs. MT7922, MT7902 have zero chip-specific CVEs (too new or architecturally distinct). Full table in `data/adapters.csv` and `references/distro-bugs.md`.

### OpenWrt Table of Hardware -- MediaTek-radio SBC / router (consumer-accessible)

Factory-MediaTek SBC in ToH: BananaPi BPI-R4, BPI-R3, BPI-R3 Mini, BPI-R64, BPI-R2; Seeed LinkStar H68K (Rockchip RK3568 + MT7921E M.2); OpenWrt One (MT7981BA reference); Olimex RT5350F.

Consumer routers with MediaTek radios: **GL.iNet** ships 10 MediaTek-SoC+radio OpenWrt-supported models (Flint 2, Beryl AX, Puli AX, Spitz AX, Brume 2, MT1300 Beryl, MT300N Mango, VIXMINI, plus discontinued). **Ubiquiti** has 5 MediaTek-SoC UniFi APs (UniFi 6 LR/Plus/Lite, nanoHD, FlexHD). Turris routers = zero MediaTek. Firewalla = zero ToH entries.

### SBC / ARM dev board segment

Factory-MediaTek: **BananaPi BPI-R4** (MT7988A Filogic 880 SoC + BE14 module: MT7995AV + MT7976CN + MT7977IAN Wi-Fi 7), BPI-R3 / BPI-R3 Mini (MT7986A + MT7975 + MT7976 Wi-Fi 6). BPI-R4 miniPCIe slots accept user-installed MT7916 (AsiaRF AW7916-NPD) + MT7922 / MT7925 client cards.

Zero factory MediaTek: **Radxa, Orange Pi, Khadas, FriendlyELEC, Raspberry Pi, Pine64, MNT Reform, BeagleBoard, StarFive, MilkV** (all Broadcom/Cypress AMPAK, Realtek, TI, or Intel via adapter). Nvidia Jetson Orin Nano MT7921 user-installs **FAIL** under JetPack 6.1 (Nvidia's forked kernel lags mainline mt76).

Factory-MediaTek SBC lifetime volume estimated at ~50K-150K units; user-installed MTK M.2 into non-MediaTek SBCs = single-digit thousands (enthusiast scale).

### Watch item, not yet shippable

- **MT7927** -- Wi-Fi 7 2x2 DBDC PCIe-only. Already **293 linux-hardware.org probes** on enthusiast desktops (Gigabyte Z790/X670E AORUS PRO X, System76 Thelio Mira). No mainline driver; **v4 patch series by Javier Tia posted 2026-03-26** to linux-wireless patchwork, state `New`. Patches will bind MT7927 to mt7925e.ko (NOT mt7921e.ko) and add firmware path `mediatek/mt7927/WIFI_RAM_CODE_MT6639_2_1.bin` (MT6639 is MediaTek's internal codename). Firmware-side gitlab MR !946 (Draft) covers only Bluetooth blob; MediaTek has not submitted Wi-Fi firmware. Shipping hardware: ASUS ROG X870E boards, Lenovo Legion Pro 7 16AFR10H (Legion Pro 7 Gen 10, machine type 83RU), MSI X870E Ace Max, TP-Link TBE550E PCIe, System76 Thelio Mira r4-n4 factory option, Framework Desktop Ryzen AI Max 300 factory option. `morrownr/mt76` cannot ship MT7927 firmware today; expected upstream layout is `mediatek/mt7927/` subdir paralleling MT7925.

### Explicit exclusions

- **MT7601U** -- standalone `mt7601u` driver, not the unified mt76 framework. Firmware ships separately upstream.
- **Router-class chips** (MT7603, MT7615, MT7915, MT7916, MT7986, MT7996, MT7988) -- router SoCs, excluded per the issue #5 framing. BPI-R4 / BPI-R3 board-level coverage noted above because those boards accept consumer mt76 client cards.

### Firmware-blob sharing (per kernel source, 2026-04-17)

| Driver family | Blob(s) | Shared between PCIe + USB? | Notes |
|---------------|---------|----------------------------|-------|
| mt76x0 | `mt7610e.bin` (PCIe), `mt7650e.bin` (PCIe only), `mt7610u.bin` (USB) | **No -- distinct files.** `mt76x0u.ko` declares `MT7610E_FIRMWARE` as preferred-then-fallback to `MT7610U_FIRMWARE` at runtime | Per `mt76x0/mt76x0.h` #define macros |
| mt76x2 | `mt7662.bin` + `mt7662_rom_patch.bin` | **Yes.** Both `pci.c` and `usb.c` declare `MODULE_FIRMWARE(MT7662_FIRMWARE)` | Single blob pair serves MT7612E/U, MT7662E/U, MT7602E |
| mt7921 | `WIFI_RAM_CODE_MT7961_1.bin` + patch | **Yes.** mt7921e + mt7921u + mt7921s all MODULE_FIRMWARE same blob | SDIO variant via ChromeOS Kompanio |
| mt7921e (MT7920-only) | `WIFI_RAM_CODE_MT7961_1a.bin` + 1a patch | -- | Distinct `_1a` blob variant |
| mt7921e (MT7922-only) | `WIFI_RAM_CODE_MT7922_1.bin` + patch | PCIe-only | Distinct from MT7921 |
| mt7921e (MT7902-only) | `WIFI_RAM_CODE_MT7902_1.bin` + patch | PCIe-only | Same blob for PCIe and SDIO (no separate SDIO firmware) |
| mt7925 | `mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin` + patch | **Yes.** Both mt7925e + mt7925u MODULE_FIRMWARE same subdir blob pair | Subdir layout |

**morrownr/mt76/firmware/ is byte-identical with upstream linux-firmware** for all PCIe-only blobs as of 2026-04-17:
- MT7902: `b595...4998` + `d73b...e30a`
- MT7922: `1226...1fda` + `6d04...5f5a`
- MT7925: `f156...451d` + `8b68...eeb3`

### Known regression / sentiment flags

- **MT7925 negative Linux sentiment is PCIe-internal-driven, not USB.** Framework-default 2026-01 kernel panic storm fixed downstream via `zbowling/mt7925` DKMS (12-patch series under review at linux-wireless; 0 upstream as of 2026-04-17). Open Fedora regression on `linux-firmware-20260110-1` (Red Hat BZ 2440298 ON_QA + 2459017 NEW). Seven MT7925-specific CVEs lifetime (3 in CVE-2025 IDs, 5 published in 2025 calendar year).
- **MT7921 family has 28+ CVEs since 2024** across the driver family.
- **MT7922 BT-on-resume panic** on kernel 6.11.3 fixed in 6.12.8 via btusb.c commits b967b37c / 9da1cfc4 / cc569d79 / f5c5661f (Sep 2024).
- **MT7902** now has a working mainline driver (since 2026-03-24 via Felix Fietkau's nbd tree); 1,510 orphan-until-mainline probes are an addressable install base once distro kernels roll to 7.0+.

Detailed CSV with VID:PIDs, FCC IDs, top-host data, kernel-commit anchors, and per-chip narratives: [`data/adapters.csv`](data/adapters.csv).

## Repo layout

```
data/          Master CSV with one row per identified MediaTek WiFi SKU or chip variant
references/    What each source is, why it's credible, what it can and cannot prove
methodology.md Research methodology, weighting, and provenance standards
```

Every claim cites a source URL + UTC timestamp.

## Data sources

| Source | Type | Credibility | Used for |
|--------|------|-------------|----------|
| [linux-hardware.org](https://linux-hardware.org) per-device pages | Community telemetry probes | High | Install base per VID:PID, top host machines, form-factor mix, earliest-probe date |
| Linux kernel source (`drivers/net/wireless/mediatek/mt76/`) | Authoritative | A+ | Driver / firmware / VID:PID ground truth |
| upstream linux-firmware (kernel.org + gitlab) | Kernel project | A+ | Firmware-blob reconciliation with morrownr/mt76 |
| linux-wireless patchwork | Upstream in-flight patch state | High | MT7927 driver progress (Javier Tia v4 series 2026-03-26) |
| [`morrownr/USB-WiFi`](https://github.com/morrownr/USB-WiFi) issues | Curator + community discussion | High | Linux community usage signal |
| [`morrownr/mt76`](https://github.com/morrownr/mt76) issues | Maintainer + early users | High | mt76-specific signal |
| [lore.kernel.org/linux-wireless](https://lore.kernel.org/linux-wireless/) | Kernel mailing list | High | Developer-confirmed adapters |
| [FCC ID database](https://fccid.io) | Government certification record | High | Authoritative chipset identification (RAS-MT79xx grantee) |
| Lenovo PSREF + Lenovo driver catalogue (ds-numbered pages) | OEM spec sheets | High | Laptop-level PCIe install base |
| HP QuickSpecs + HP driver catalogue | OEM spec sheets | High | Laptop PCIe install base |
| Dell support / technical specs | OEM spec sheets | High | Dell Inspiron MediaTek coverage; confirms Dell does NOT rebrand MediaTek |
| Framework Marketplace + Framework Community | Linux-first vendor spec | High | RZ717/RZ616 module retail + compat |
| System76, Tuxedo, Slimbook, Ubuntu Certified Hardware | Linux-first vendor spec | High | Linux-community PCIe signal |
| AzureWave / Foxconn / LiteOn module catalogues + WikiDevi | OEM modules | High | Module-level chip confirmation |
| iFixit teardowns | Hardware disassembly | High | Gaming handheld + Steam Deck + niche device chip confirmation |
| [Stack Exchange](https://askubuntu.com) | User Q&A | Medium-High | Help-seeking signal |
| Distro hardware compat databases | Wiki / certified-hardware lists | Medium | User-confirmed compatibility |
| Distro bug trackers (bugzilla.kernel.org / Red Hat / openSUSE / Ubuntu Launchpad / Debian BTS) | Bug reports | Medium | Pain-point signal, regression tracking |
| MITRE / NVD CVE databases | Security advisories | High | Per-chip CVE count + CVSS |
| OpenWrt forum + Table of Hardware | Router-community usage | Medium | SBC / router-class MediaTek coverage |
| Manufacturer product pages | First-party catalogues | Medium | Product enumeration |
| [Reddit](https://reddit.com) (multiple subs) | User recommendations | Low-Medium | Aspirational signal |
| YouTube reviews | Video reviews | Low-Medium | Aspirational signal |
| Amazon Best Sellers + targeted ASIN re-fetches | Retail volume proxy | Low-Medium | Consumer market signal + mini-PC channel volume |
| eBay sold-completed listings | Recent transaction volume | Medium | Retail throughput signal |
| AliExpress order counts | Lifetime order signal | Low-Medium | Cheap-OEM channel signal (Fenvi MT7922 family ~10K+) |

## Status

Published 2026-04-17. Dynamic retail numbers (Amazon review counts, eBay 90-day sold, AliExpress lifetime orders) are a snapshot in time and will drift; the underlying chip hierarchy is stable.

## License

CC0 / public domain for the data. Original analysis under MIT.
