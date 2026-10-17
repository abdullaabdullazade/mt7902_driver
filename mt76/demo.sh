#!/bin/sh
#
# Demo script -- simulates the full install/verify/uninstall experience
# without touching the system. Safe to run as regular user.
#

KVER="$(uname -r)"
KARCH="$(uname -m)"

# Colors
if [ -t 1 ]; then
	# Use command substitution so the variables hold real ESC bytes,
	# not the literal backslash-escape sequence. This keeps every
	# existing `printf '%s'` call site working: printf %s does not
	# interpret backslash escapes in its arguments, only %b does.
	GREEN=$(printf '\033[0;32m')
	RED=$(printf '\033[0;31m')
	YELLOW=$(printf '\033[1;33m')
	CYAN=$(printf '\033[0;36m')
	BOLD=$(printf '\033[1m')
	DIM=$(printf '\033[2m')
	NC=$(printf '\033[0m')
else
	GREEN='' RED='' YELLOW='' CYAN='' BOLD='' DIM='' NC=''
fi

TOTAL_STEPS=6
step() {
	printf '\n%s%s[%s/%s]%s %s%s%s\n' "${BOLD}" "${CYAN}" "$1" "${TOTAL_STEPS}" "${NC}" "${BOLD}" "$2" "${NC}"
}

pause() {
	sleep "${1:-1}"
}

# Distro
DISTRO="Unknown"
if [ -f /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
	DISTRO="${PRETTY_NAME:-${NAME} ${VERSION}}"
fi

# gcc
GCC_VER=$(gcc --version 2>/dev/null | head -1 || echo "gcc (GCC) 15.0.1")

# Memory
SMEM=$(LC_ALL=C free 2>/dev/null | awk '/Mem:/ { print $2 }')
SMEM="${SMEM:-16384000}"

clear

printf '\n%s%s  >>> DEMO MODE -- nothing is installed or modified <<<%s\n' "${BOLD}" "${YELLOW}" "${NC}"
pause 2

# ===========================================================================
# INSTALL
# ===========================================================================
printf '\n%s' "${BOLD}"
printf "  ================================================================\n"
printf "     mt76 WiFi Driver Installer\n"
printf '  ================================================================%s\n' "${NC}"
printf "  install-driver.sh v20260408\n"
printf '  Source:  %sa1b2c3d%s\n' "${CYAN}" "${NC}"
printf "  Distro:  %s\n" "${DISTRO}"
printf "  Kernel:  %s (%s)\n" "${KVER}" "${KARCH}"
printf "  CPUs:    %s/%s (in-use/total)\n" "$(($(nproc) - 1))" "$(nproc)"
printf "  Memory:  %s kB\n" "${SMEM}"
printf "  gcc:     %s\n" "${GCC_VER}"

if command -v dkms >/dev/null 2>&1; then
	printf "  dkms:    %s\n" "$(dkms --version 2>/dev/null)"
else
	printf '  dkms:    %snot installed%s\n' "${DIM}" "${NC}"
fi

if command -v mokutil >/dev/null 2>&1; then
	case $(mokutil --sb-state 2>&1) in
		*enabled*)  printf '  SecBoot: %senabled%s\n' "${YELLOW}" "${NC}" ;;
		*disabled*) printf "  SecBoot: disabled\n" ;;
		*)          printf "  SecBoot: not supported\n" ;;
	esac
else
	printf '  SecBoot: %sunknown%s\n' "${DIM}" "${NC}"
fi

# Real hardware detection
echo
printf '  %sDetected mt76 hardware:%s\n' "${BOLD}" "${NC}"
FOUND_HW=0
if command -v lsusb >/dev/null 2>&1; then
	USB_HW=$(lsusb 2>/dev/null | grep -iE "mediatek|mt76|0e8d:" | head -5)
	if [ -n "${USB_HW}" ]; then
		echo "${USB_HW}" | while IFS= read -r line; do
			printf "    %s\n" "${line}"
		done
		FOUND_HW=1
	fi
fi
if command -v lspci >/dev/null 2>&1; then
	PCI_HW=$(lspci 2>/dev/null | grep -iE "mediatek|mt76" | head -5)
	if [ -n "${PCI_HW}" ]; then
		echo "${PCI_HW}" | while IFS= read -r line; do
			printf "    %s\n" "${line}"
		done
		FOUND_HW=1
	fi
fi
if [ "${FOUND_HW}" -eq 0 ]; then
	printf '    %s(simulating: MediaTek MT7921AU WiFi 6E adapter)%s\n' "${DIM}" "${NC}"
fi
printf '  %s----------------------------------------------------------------%s\n' "${BOLD}" "${NC}"

pause 1

# Step 1
step 1 "Checking prerequisites"
pause 0.3
printf '%s  All prerequisites found.%s\n' "${GREEN}" "${NC}"
pause 0.2
printf '%s  Kernel headers present.%s\n' "${GREEN}" "${NC}"
pause 0.5

# Step 2
step 2 "Removing previous installation (if any)"
pause 0.4
printf '  %s(no previous installation found)%s\n' "${DIM}" "${NC}"
printf '%s  Clean.%s\n' "${GREEN}" "${NC}"
pause 0.5

# Step 3
step 3 "Configuring"
pause 0.3
printf "  Installing mt76_git.conf to /etc/modprobe.d\n"
pause 0.2
printf '%s  Done.%s\n' "${GREEN}" "${NC}"
pause 0.5

# Step 4 -- the big one, simulate build progress
step 4 "Building modules"
CORES=$(($(nproc) - 1))
[ "${CORES}" -lt 1 ] && CORES=1
printf '  %s(non-dkms build with %s cores)%s\n' "${DIM}" "${CORES}" "${NC}"
pause 0.5

# Simulate build output
FAMILIES="mt76_git mt76_usb_git mt76_sdio_git mt76x02_lib_git mt76x02_usb_git mt76_connac_lib_git mt792x_lib_git mt792x_usb_git"
SUBDIRS="mt7603e_git mt7615_common_git mt7615e_git mt7663_usb_sdio_common_git mt7663u_git mt7663s_git mt7915e_git mt7921_common_git mt7921e_git mt7921s_git mt7921u_git mt7925_common_git mt7925e_git mt7925u_git mt7996e_git mt76x0_common_git mt76x0u_git mt76x0e_git mt76x2_common_git mt76x2u_git mt76x2e_git"

COUNT=0
TOTAL=29
for mod in ${FAMILIES} ${SUBDIRS}; do
	COUNT=$((COUNT + 1))
	printf '\r  %s[%2d/%d]%s Building: %-35s' "${DIM}" "${COUNT}" "${TOTAL}" "${NC}" "${mod}"
	# Vary the sleep to simulate real compile times
	case "${mod}" in
		mt7996e*|mt7915e*|mt7615_common*) sleep 0.15 ;;
		mt76_git|mt76_connac*) sleep 0.12 ;;
		*) sleep 0.06 ;;
	esac
done
printf '\r  %s[%d/%d]%s %-50s\n' "${DIM}" "${TOTAL}" "${TOTAL}" "${NC}" "All modules built."

printf '%s  Build complete.%s\n' "${GREEN}" "${NC}"
pause 0.5

# Step 5
step 5 "Installing modules"
pause 0.3
printf '  %sStripping debug symbols...%s\n' "${DIM}" "${NC}"
pause 0.2
printf '  %sCompressing modules with zstd (matching distro scheme)...%s\n' "${DIM}" "${NC}"
pause 0.4
printf '%s  Installed %s module(s) for kernel %s.%s\n' "${GREEN}" "29" "${KVER}" "${NC}"
pause 0.5

# Step 6
step 6 "Verifying installation"
pause 0.3
printf '  %sModule count: 29%s\n' "${GREEN}" "${NC}"
pause 0.2
printf '  %smt76_git resolvable by depmod (version: 1.0)%s\n' "${GREEN}" "${NC}"
pause 0.2
printf '  %sBlacklist config installed%s\n' "${GREEN}" "${NC}"
pause 0.2
printf '  %sAll checks passed.%s\n' "${GREEN}" "${NC}"
pause 1

# Success banner
printf '\n%s' "${GREEN}"
printf "         .--.        \n"
printf "        /    \\       \n"
printf "       /  ..  \\      \n"
printf "      / .'  '. \\     \n"
printf "     / '      ' \\    \n"
printf "    /............\\   \n"
printf "          ||          \n"
printf "          ||          \n"
printf '%s\n' "${NC}"
printf '  %s%sInstallation complete!%s\n' "${BOLD}" "${GREEN}" "${NC}"
printf "\n"
printf '  %s================================================================%s\n' "${BOLD}" "${NC}"
printf "  Update this driver:\n"
printf '    %s$ git pull%s\n' "${CYAN}" "${NC}"
printf '    %s$ sudo sh install-driver.sh%s\n' "${CYAN}" "${NC}"
printf "\n"
printf "  Diagnose problems:\n"
printf '    %s$ ./check-driver.sh%s\n' "${CYAN}" "${NC}"
printf "\n"
printf '  %sTip: Update before distro or kernel upgrades.%s\n' "${DIM}" "${NC}"
printf '  %sTip: Updates can be run as often as you like (recommended: monthly).%s\n' "${DIM}" "${NC}"
printf '  %s================================================================%s\n' "${BOLD}" "${NC}"

pause 3

# ===========================================================================
# CHECK
# ===========================================================================
printf '\n\n%s%s  >>> Now simulating: check-driver.sh <<<%s\n' "${BOLD}" "${YELLOW}" "${NC}"
pause 2

ok()   { printf '%s[OK]%s    %s\n' "${GREEN}" "${NC}" "$*"; }
warn() { printf '%s[WARN]%s  %s\n' "${YELLOW}" "${NC}" "$*"; }
fail() { printf '%s[FAIL]%s  %s\n' "${RED}" "${NC}" "$*"; }
info() { printf '%s[INFO]%s  %s\n' "${CYAN}" "${NC}" "$*"; }

printf '\n%s' "${BOLD}"
printf "  ================================================================\n"
printf "     mt76 WiFi Driver Diagnostic Report\n"
printf '  ================================================================%s\n' "${NC}"
printf "  check-driver.sh v20260408\n"
printf "  Generated: %s\n" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
printf "  Kernel:    %s (%s)\n" "${KVER}" "${KARCH}"
printf "  Distro:    %s\n" "${DISTRO}"
printf '  %s----------------------------------------------------------------%s\n' "${BOLD}" "${NC}"

printf '\n%s--- Loaded mt76 Modules ---%s\n' "${BOLD}" "${NC}"
pause 0.3
ok "mt76_git  (1.0)  /lib/modules/${KVER}/extra/mt76/mt76_git.ko.zst"
pause 0.1
ok "mt76_usb_git  (1.0)  /lib/modules/${KVER}/extra/mt76/mt76_usb_git.ko.zst"
pause 0.1
ok "mt76_connac_lib_git  (1.0)  /lib/modules/${KVER}/extra/mt76/mt76_connac_lib_git.ko.zst"
pause 0.1
ok "mt792x_lib_git  (1.0)  /lib/modules/${KVER}/extra/mt76/mt792x_lib_git.ko.zst"
pause 0.1
ok "mt792x_usb_git  (1.0)  /lib/modules/${KVER}/extra/mt76/mt792x_usb_git.ko.zst"
pause 0.1
ok "mt7921_common_git  (1.0)  /lib/modules/${KVER}/extra/mt76/mt7921_common_git.ko.zst"
pause 0.1
ok "mt7921u_git  (1.0)  /lib/modules/${KVER}/extra/mt76/mt7921u_git.ko.zst"
echo
ok "7 out-of-tree _git module(s) loaded"
pause 0.5

printf '\n%s--- Blacklist Status ---%s\n' "${BOLD}" "${NC}"
pause 0.3
ok "mt76_git.conf is installed in /etc/modprobe.d/"
pause 0.5

printf '\n%s--- Detected Hardware ---%s\n' "${BOLD}" "${NC}"
pause 0.3
info "USB: Bus 001 Device 004: ID 0e8d:7961 MediaTek Inc. MT7921AU"
pause 0.5

printf '\n%s--- Wireless Interface Status ---%s\n' "${BOLD}" "${NC}"
pause 0.3

printf '\n  %swlan0%s (driver: mt7921u_git)\n' "${BOLD}" "${NC}"
pause 0.2
ok "  SSID: MyNetwork-5G"
info "  Freq: 5745 MHz"
info "  Signal: -42 dBm"
info "  TX rate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2"
info "  RX rate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2"
info "  Bands: 3 (phy0)"
pause 0.5

printf '\n%s--- Firmware Status ---%s\n' "${BOLD}" "${NC}"
pause 0.3
ok "12 firmware file(s) in /lib/firmware/mediatek"
ok "  mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin"
ok "  mediatek/WIFI_RAM_CODE_MT7961_1.bin"
pause 0.5

printf '\n%s--- Regulatory Domain ---%s\n' "${BOLD}" "${NC}"
pause 0.3

REG_REAL=""
if command -v iw >/dev/null 2>&1; then
	REG_REAL=$(iw reg get 2>/dev/null | grep -m1 country)
fi
info "${REG_REAL:-country US: DFS-FCC}"
pause 0.5

printf '\n%s--- Secure Boot ---%s\n' "${BOLD}" "${NC}"
pause 0.3
if command -v mokutil >/dev/null 2>&1; then
	case $(mokutil --sb-state 2>&1) in
		*enabled*)  warn "Secure Boot is ENABLED -- modules must be signed to load" ;;
		*disabled*) ok "Secure Boot is disabled" ;;
		*)          info "Secure Boot: not supported" ;;
	esac
else
	ok "Secure Boot is disabled"
fi
pause 0.5

printf '\n%s--- Recent Kernel Messages (mt76) ---%s\n' "${BOLD}" "${NC}"
pause 0.3
info "  [    2.341] mt7921u 1-3:1.0: HW/SW Version: 0x8a108a10, Build Time: 20230210142421a"
info "  [    2.584] mt7921u 1-3:1.0: WM Firmware Version: ____010000, Build Time: 20230210142421"
info "  [    3.012] mt7921u 1-3:1.0: CONNAC2x HW found, MAC: 7961"
pause 0.5

printf '\n%s--- Summary ---%s\n' "${BOLD}" "${NC}"
pause 0.3
ok "No issues detected"

printf '\n  %s================================================================%s\n' "${BOLD}" "${NC}"
info "To report a bug, copy ALL output above and paste it into your issue."
info "Save to file: ./check-driver.sh 2>&1 | tee mt76-diag.txt"
printf '  %s================================================================%s\n' "${BOLD}" "${NC}"

pause 3

# ===========================================================================
# UNINSTALL
# ===========================================================================
printf '\n\n%s%s  >>> Now simulating: uninstall-driver.sh <<<%s\n' "${BOLD}" "${YELLOW}" "${NC}"
pause 2

TOTAL_STEPS=4

printf '\n%s' "${BOLD}"
printf "  ================================================================\n"
printf "     mt76 WiFi Driver Uninstaller\n"
printf '  ================================================================%s\n' "${NC}"
printf "  uninstall-driver.sh v20260408\n"
printf "  Kernel:  %s (%s)\n" "${KVER}" "${KARCH}"
printf '  %s----------------------------------------------------------------%s\n' "${BOLD}" "${NC}"

step 1 "Unloading running mt76_git modules"
pause 0.3
printf "  Unloading: mt7921u_git\n"
pause 0.15
printf "  Unloading: mt7921_common_git\n"
pause 0.15
printf "  Unloading: mt792x_usb_git\n"
pause 0.15
printf "  Unloading: mt792x_lib_git\n"
pause 0.15
printf "  Unloading: mt76_connac_lib_git\n"
pause 0.15
printf "  Unloading: mt76_usb_git\n"
pause 0.15
printf "  Unloading: mt76_git\n"
pause 0.2
printf '%s  Unloaded 7 module(s).%s\n' "${GREEN}" "${NC}"
pause 0.5

step 2 "Removing installed modules"
pause 0.3
printf "  Removing non-dkms modules from /lib/modules/%s/extra/mt76\n" "${KVER}"
pause 0.3
printf '%s  Done.%s\n' "${GREEN}" "${NC}"
pause 0.5

step 3 "Cleaning up"
pause 0.3
printf "  Removing mt76_git.conf from /etc/modprobe.d\n"
pause 0.2
printf '%s  Clean.%s\n' "${GREEN}" "${NC}"
pause 0.5

step 4 "Rebuilding module database"
pause 0.4
printf '%s  Done.%s\n' "${GREEN}" "${NC}"

printf "\n"
printf '  %s%sUninstall complete.%s\n' "${BOLD}" "${GREEN}" "${NC}"
printf "  You may now delete the driver directory if desired.\n"
printf '  %s================================================================%s\n' "${BOLD}" "${NC}"
printf "\n"

pause 1
printf '%s%s  >>> DEMO COMPLETE -- no changes were made to your system <<<%s\n\n' "${BOLD}" "${YELLOW}" "${NC}"
