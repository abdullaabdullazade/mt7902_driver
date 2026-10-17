#!/bin/sh

# Purpose: Diagnostic check for MediaTek mt76 out-of-kernel WiFi drivers.
#
# Reports loaded modules, hardware detection, link status, firmware,
# blacklist health, and recent kernel messages. Does NOT require root.
# Output is designed to be copy-pasted directly into bug reports.
#
# To make this file executable:
#
# $ chmod +x check-driver.sh
#
# To execute this file:
#
# $ ./check-driver.sh
#
# To save output to a file for a bug report:
#
# $ ./check-driver.sh 2>&1 | tee mt76-diag.txt
#
# To check for errors:
#
# $ shellcheck check-driver.sh
#
# Copyright(c) 2025-2026 Nick Morrow, Devin (Lucid_Duck)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

SCRIPT_NAME="check-driver.sh"
SCRIPT_VERSION="20260408"

KVER="$(uname -r)"
KARCH="$(uname -m)"

OPTIONS_FILE="mt76_git.conf"

# ---------------------------------------------------------------------------
# Locate iw. Some distros (notably Debian) install iw in /usr/sbin and keep
# /usr/sbin out of the default non-root PATH, so `command -v iw` returns
# empty for a regular user even though iw is installed. Check the common
# sbin locations as a fallback and record the full path for later use.
# ---------------------------------------------------------------------------
if command -v iw >/dev/null 2>&1; then
	IW=iw
elif [ -x /usr/sbin/iw ]; then
	IW=/usr/sbin/iw
elif [ -x /sbin/iw ]; then
	IW=/sbin/iw
else
	IW=
fi

# ---------------------------------------------------------------------------
# Color support (auto-disabled when not writing to a terminal)
# ---------------------------------------------------------------------------
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
	NC=$(printf '\033[0m')
else
	GREEN='' RED='' YELLOW='' CYAN='' BOLD='' NC=''
fi

ok()   { printf '%s[OK]%s    %s\n' "${GREEN}" "${NC}" "$*"; }
warn() { printf '%s[WARN]%s  %s\n' "${YELLOW}" "${NC}" "$*"; }
fail() { printf '%s[FAIL]%s  %s\n' "${RED}" "${NC}" "$*"; }
info() { printf '%s[INFO]%s  %s\n' "${CYAN}" "${NC}" "$*"; }
hdr()  { printf '\n%s--- %s ---%s\n' "${BOLD}" "$*" "${NC}"; }

# ===========================================================================
# Banner
# ===========================================================================
printf '\n%s' "${BOLD}"
printf "  ================================================================\n"
printf "     mt76 WiFi Driver Diagnostic Report\n"
printf '  ================================================================%s\n' "${NC}"
printf '  %s v%s\n' "${SCRIPT_NAME}" "${SCRIPT_VERSION}"
printf "  Generated: %s\n" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
printf "  Kernel:    %s (%s)\n" "${KVER}" "${KARCH}"

# distro
if [ -f /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
	printf "  Distro:    %s\n" "${PRETTY_NAME:-${NAME} ${VERSION}}"
fi
printf '  %s----------------------------------------------------------------%s\n' "${BOLD}" "${NC}"

# git commit of installed driver (if modinfo works)
SRCVER=$(modinfo -F srcversion mt76_git 2>/dev/null || true)
if [ -n "${SRCVER}" ]; then
	printf "  Srcver:    %s\n" "${SRCVER}"
fi

# ===========================================================================
hdr "Loaded mt76 Modules"
# ===========================================================================

MT76_MODS=$(lsmod 2>/dev/null | awk '$1 ~ /mt76|mt79|mt7603|mt7615|mt7663|mt7915|mt7921|mt7925|mt7996/{print $1}' | sort)
GIT_COUNT=0
INKERNEL_COUNT=0

if [ -z "${MT76_MODS}" ]; then
	warn "No mt76 modules are currently loaded"
else
	for mod in ${MT76_MODS}; do
		src=$(modinfo -F filename "${mod}" 2>/dev/null)
		ver=$(modinfo -F version "${mod}" 2>/dev/null)
		case "${mod}" in
			*_git)
				ok "${mod}  (${ver:-no version})  ${src}"
				GIT_COUNT=$((GIT_COUNT + 1))
				;;
			*)
				fail "${mod}  <-- IN-KERNEL module loaded (should be blacklisted!)"
				INKERNEL_COUNT=$((INKERNEL_COUNT + 1))
				;;
		esac
	done

	echo
	if [ "${INKERNEL_COUNT}" -gt 0 ]; then
		fail "${INKERNEL_COUNT} in-kernel module(s) loaded -- blacklist is not working!"
		info "Check /etc/modprobe.d/${OPTIONS_FILE} and reboot"
	fi
	if [ "${GIT_COUNT}" -gt 0 ]; then
		ok "${GIT_COUNT} out-of-tree _git module(s) loaded"
	fi
fi

# ===========================================================================
hdr "Blacklist Status"
# ===========================================================================

if [ -f /etc/modprobe.d/${OPTIONS_FILE} ]; then
	ok "${OPTIONS_FILE} is installed in /etc/modprobe.d/"

	# check for common leaks -- modules that are blacklisted but still loadable
	# from the in-kernel path
	for mod in mt76 mt76_usb mt76_sdio mt7603e mt7915e mt7996e; do
		KMOD_PATH=$(modinfo -F filename "${mod}" 2>/dev/null || true)
		case "${KMOD_PATH}" in
			*kernel/drivers/net/wireless*)
				info "${mod}: in-kernel module exists at ${KMOD_PATH} (blacklisted)"
				;;
		esac
	done
else
	fail "${OPTIONS_FILE} is NOT installed -- in-kernel modules will load instead!"
	info "Run: sudo cp ${OPTIONS_FILE} /etc/modprobe.d/ && sudo depmod -a"
fi

# ===========================================================================
hdr "Detected Hardware"
# ===========================================================================

FOUND_HW=0

# USB devices
if command -v lsusb >/dev/null 2>&1; then
	USB_HW=$(lsusb 2>/dev/null | grep -iE "mediatek|mt76|0e8d:" | head -10)
	if [ -n "${USB_HW}" ]; then
		echo "${USB_HW}" | while IFS= read -r line; do
			info "USB: ${line}"
		done
		FOUND_HW=1
	fi
fi

# PCI devices
if command -v lspci >/dev/null 2>&1; then
	PCI_HW=$(lspci 2>/dev/null | grep -iE "mediatek|mt76" | head -10)
	if [ -n "${PCI_HW}" ]; then
		echo "${PCI_HW}" | while IFS= read -r line; do
			info "PCI: ${line}"
		done
		FOUND_HW=1
	fi
fi

# sysfs fallback: scan for USB devices bound to any mt76-family driver.
# Catches rebadged adapters (e.g. NetGear A9000, 0846:9072) where lsusb
# shows the rebadger's vendor ID instead of MediaTek's 0e8d, and the
# vendor-string regex above never sees "mediatek" or "mt76".
if [ "${FOUND_HW}" -eq 0 ]; then
	for drv_path in /sys/bus/usb/drivers/mt7*; do
		[ -d "${drv_path}" ] || continue
		drv_name=$(basename "${drv_path}")
		for dev_link in "${drv_path}"/*; do
			[ -L "${dev_link}" ] || continue
			dev_base=$(basename "${dev_link}")
			[ "${dev_base}" = "module" ] && continue
			# idVendor/idProduct/manufacturer/product live on the USB
			# device one level up from the interface binding, so read
			# from "${dev_link}/../" not "${dev_link}/"
			dev_vid=$(cat "${dev_link}/../idVendor" 2>/dev/null)
			dev_pid=$(cat "${dev_link}/../idProduct" 2>/dev/null)
			dev_mfg=$(cat "${dev_link}/../manufacturer" 2>/dev/null)
			dev_prd=$(cat "${dev_link}/../product" 2>/dev/null)
			if [ -n "${dev_vid}" ] && [ -n "${dev_pid}" ]; then
				info "USB: ID ${dev_vid}:${dev_pid} ${dev_mfg} ${dev_prd} (driver: ${drv_name})"
			else
				info "USB: ${dev_base} (driver: ${drv_name})"
			fi
			FOUND_HW=1
		done
	done
fi

if [ "${FOUND_HW}" -eq 0 ]; then
	warn "No MediaTek wireless hardware detected"
	info "If your device is connected, it may not be powered on or recognized"
fi

# ===========================================================================
hdr "Wireless Interface Status"
# ===========================================================================

if [ -n "${IW}" ]; then
	WLAN_DEVS=$(${IW} dev 2>/dev/null | awk '/Interface/{print $2}')
	if [ -z "${WLAN_DEVS}" ]; then
		warn "No wireless interfaces found"
	else
		for iface in ${WLAN_DEVS}; do
			# figure out which driver owns this interface
			DRV=$(readlink "/sys/class/net/${iface}/device/driver" 2>/dev/null | awk -F/ '{print $NF}')
			case "${DRV}" in
				*mt7*)
					printf '\n  %s%s%s (driver: %s)\n' "${BOLD}" "${iface}" "${NC}" "${DRV}"
					;;
				*)
					info "${iface} is not an mt76 device (driver: ${DRV:-unknown})"
					continue
					;;
			esac

			# link info
			LINK=$(${IW} dev "${iface}" link 2>/dev/null)
			case "${LINK}" in
				*"Not connected"*)
					warn "  ${iface}: Not connected to any network"
					;;
				*"Connected"*|*"SSID"*)
					SSID=$(echo "${LINK}" | awk -F: '/SSID/{gsub(/^[ \t]+/,"",$2); print $2}')
					FREQ=$(echo "${LINK}" | awk '/freq:/{print $2}')
					SIGNAL=$(echo "${LINK}" | awk '/signal:/{print $2, $3}')
					TX_RATE=$(echo "${LINK}" | awk '/tx bitrate:/{$1=$2=""; gsub(/^[ \t]+/,""); print}')
					RX_RATE=$(echo "${LINK}" | awk '/rx bitrate:/{$1=$2=""; gsub(/^[ \t]+/,""); print}')

					[ -n "${SSID}" ]    && ok "  SSID: ${SSID}"
					[ -n "${FREQ}" ]    && info "  Freq: ${FREQ} MHz"
					[ -n "${SIGNAL}" ]  && info "  Signal: ${SIGNAL}"
					[ -n "${TX_RATE}" ] && info "  TX rate: ${TX_RATE}"
					[ -n "${RX_RATE}" ] && info "  RX rate: ${RX_RATE}"
					;;
				*)
					info "  ${iface}: status unknown"
					;;
			esac

			# phy capabilities (band info)
			PHY=$(${IW} dev "${iface}" info 2>/dev/null | awk '/wiphy/{print $2}')
			if [ -n "${PHY}" ]; then
				BANDS=$(${IW} phy "phy${PHY}" info 2>/dev/null | grep -c "Band [0-9]")
				info "  Bands: ${BANDS} (phy${PHY})"
			fi
		done
	fi
else
	warn "iw not found -- cannot check wireless interfaces"
fi

# ===========================================================================
hdr "Firmware Status"
# ===========================================================================

FW_DIR="/lib/firmware/mediatek"
if [ -d "${FW_DIR}" ]; then
	FW_COUNT=$(find "${FW_DIR}" -type f \( -name "*.bin" -o -name "*.bin.xz" -o -name "*.bin.zst" -o -name "*.bin.gz" \) 2>/dev/null | wc -l)
	ok "${FW_COUNT} firmware file(s) in ${FW_DIR}"

	# show firmware files relevant to loaded modules
	for mod in ${MT76_MODS}; do
		FW_LIST=$(modinfo -F firmware "${mod}" 2>/dev/null | head -5)
		if [ -n "${FW_LIST}" ]; then
			echo "${FW_LIST}" | while IFS= read -r fw; do
				if [ -f "/lib/firmware/${fw}" ] || \
				   [ -f "/lib/firmware/${fw}.xz" ] || \
				   [ -f "/lib/firmware/${fw}.zst" ] || \
				   [ -f "/lib/firmware/${fw}.gz" ]; then
					ok "  ${fw}"
				else
					fail "  ${fw} -- MISSING!"
				fi
			done
		fi
	done
else
	warn "${FW_DIR} does not exist"
	info "Run: sudo make install_fw"
fi

# ===========================================================================
hdr "Regulatory Domain"
# ===========================================================================

if [ -n "${IW}" ]; then
	REG=$(${IW} reg get 2>/dev/null | grep -m1 "country")
	if [ -n "${REG}" ]; then
		info "${REG}"
	else
		warn "Could not determine regulatory domain"
	fi
fi

# ===========================================================================
hdr "Secure Boot"
# ===========================================================================

if command -v mokutil >/dev/null 2>&1; then
	SB_STATE=$(mokutil --sb-state 2>&1)
	case "${SB_STATE}" in
		*enabled*)
			warn "Secure Boot is ENABLED -- modules must be signed to load"
			SIGNER=$(modinfo -F signer mt76_git 2>/dev/null)
			if [ -n "${SIGNER}" ]; then
				ok "mt76_git is signed by: ${SIGNER}"
			elif modinfo mt76_git >/dev/null 2>&1; then
				warn "mt76_git is installed but not signed"
			fi
			;;
		*disabled*)
			ok "Secure Boot is disabled"
			;;
		*)
			info "Secure Boot: ${SB_STATE}"
			;;
	esac
else
	info "mokutil not installed -- Secure Boot status unknown"
fi

# ===========================================================================
hdr "Recent Kernel Messages (mt76)"
# ===========================================================================

# dmesg may be restricted to root on some kernels (Debian, Ubuntu, and any
# system with kernel.dmesg_restrict=1). Detect that up front so we can emit a
# clean, honest message instead of a false "no messages found" result.
DMESG_RESTRICT=0
if [ -r /proc/sys/kernel/dmesg_restrict ]; then
	DMESG_RESTRICT=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo 0)
fi

if [ "$(id -u)" -ne 0 ] && [ "${DMESG_RESTRICT}" = "1" ]; then
	info "dmesg is restricted on this kernel (kernel.dmesg_restrict=1)"
	info "for kernel messages, re-run as root: sudo ./check-driver.sh"
else
	DMESG_OUT=$(dmesg 2>/dev/null | grep -iE "mt76|mt79|mt7603|mt7615|mt7915|mt7921|mt7922|mt7925|mt7996|mediatek" | tail -25)
	if [ -n "${DMESG_OUT}" ]; then
		# highlight errors and warnings
		echo "${DMESG_OUT}" | while IFS= read -r line; do
			case "${line}" in
				*error*|*ERROR*|*fail*|*FAIL*|*firmware*not*found*)
					fail "  ${line}"
					;;
				*warn*|*WARN*)
					warn "  ${line}"
					;;
				*)
					info "  ${line}"
					;;
			esac
		done
	else
		info "No mt76-related kernel messages found"
	fi
fi

# ===========================================================================
hdr "Summary"
# ===========================================================================

ISSUES=0

if [ "${GIT_COUNT}" -eq 0 ] && [ -n "${MT76_MODS}" ]; then
	fail "No _git modules loaded -- out-of-tree driver may not be installed"
	ISSUES=$((ISSUES + 1))
elif [ "${GIT_COUNT}" -eq 0 ] && [ -z "${MT76_MODS}" ]; then
	warn "No mt76 modules loaded at all"
	ISSUES=$((ISSUES + 1))
fi

if [ "${INKERNEL_COUNT}" -gt 0 ]; then
	fail "In-kernel modules are loaded -- blacklist problem"
	ISSUES=$((ISSUES + 1))
fi

if [ ! -f /etc/modprobe.d/${OPTIONS_FILE} ]; then
	fail "Blacklist config missing"
	ISSUES=$((ISSUES + 1))
fi

if [ "${ISSUES}" -eq 0 ]; then
	ok "No issues detected"
else
	echo
	warn "${ISSUES} issue(s) found -- see details above"
fi

printf '\n  %s================================================================%s\n' "${BOLD}" "${NC}"
info "To report a bug, copy ALL output above and paste it into your issue."
info "Save to file: ./check-driver.sh 2>&1 | tee mt76-diag.txt"
printf '  %s================================================================%s\n\n' "${BOLD}" "${NC}"
