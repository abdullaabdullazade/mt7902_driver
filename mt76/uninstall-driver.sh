#!/bin/sh

# Purpose: Uninstall MediaTek mt76 out-of-kernel WiFi drivers.
#
# Supports dkms and non-dkms removals.
#
# To make this file executable:
#
# $ chmod +x uninstall-driver.sh
#
# To execute this file:
#
# $ sudo ./uninstall-driver.sh
#
# or
#
# $ sudo sh uninstall-driver.sh
#
# To check for errors:
#
# $ shellcheck uninstall-driver.sh
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

SCRIPT_NAME="uninstall-driver.sh"
SCRIPT_VERSION="20260408"

DRV_NAME="mt76"
DRV_VERSION="1.0"

OPTIONS_FILE="mt76_git.conf"

KARCH="$(uname -m)"
KVER="$(uname -r)"

MODDESTDIR="/lib/modules/${KVER}/extra/mt76"

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
	CYAN=$(printf '\033[0;36m')
	BOLD=$(printf '\033[1m')
	DIM=$(printf '\033[2m')
	NC=$(printf '\033[0m')
else
	GREEN='' RED='' CYAN='' BOLD='' DIM='' NC=''
fi

# helper: step counter
TOTAL_STEPS=5
step() {
	printf '\n%s%s[%s/%s]%s %s%s%s\n' "${BOLD}" "${CYAN}" "$1" "${TOTAL_STEPS}" "${NC}" "${BOLD}" "$2" "${NC}"
}

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
	printf '%sYou must run this script with superuser (root) privileges.%s\n' "${RED}" "${NC}"
	echo "Try: \"sudo ./${SCRIPT_NAME}\""
	exit 1
fi

# support for the NoPrompt option allows non-interactive use of this script
NO_PROMPT=0
while [ $# -gt 0 ]
do
	case $1 in
		NoPrompt)
			NO_PROMPT=1 ;;
		*h|*help|*)
			echo "Syntax $0 <NoPrompt>"
			echo "       NoPrompt - noninteractive mode"
			echo "       -h|--help - Show help"
			exit 1
			;;
	esac
	shift
done

# If stdin is not a terminal, treat this run as implicitly non-interactive
# even without the NoPrompt flag. Otherwise a blind `read -r` at the
# trailing reboot prompt blocks on an inherited-but-empty parent stdin
# (seen when the script is run via cron, cloud-init, qemu-guest-agent, or
# similar) and the uninstall appears to hang at the reboot prompt instead
# of finishing cleanly.
if [ ! -t 0 ]; then
	NO_PROMPT=1
fi

# ===========================================================================
# Banner
# ===========================================================================
printf '\n%s' "${BOLD}"
printf "  ================================================================\n"
printf "     mt76 WiFi Driver Uninstaller\n"
printf '  ================================================================%s\n' "${NC}"
printf '  %s v%s\n' "${SCRIPT_NAME}" "${SCRIPT_VERSION}"
printf "  Kernel:  %s (%s)\n" "${KVER}" "${KARCH}"
printf '  %s----------------------------------------------------------------%s\n' "${BOLD}" "${NC}"


# ===== STEP 1: Unload modules =============================================
step 1 "Unloading running mt76_git modules"

UNLOADED=0
for mod in $(lsmod 2>/dev/null | awk '/_(git)/{print $1}' | grep -E "mt76|mt79|mt760|mt762|mt7603|mt7615|mt7663|mt7915|mt7921|mt7925|mt7996"); do
	printf "  Unloading: %s\n" "${mod}"
	rmmod "${mod}" 2>/dev/null
	UNLOADED=$((UNLOADED + 1))
done

if [ "${UNLOADED}" -eq 0 ]; then
	printf '  %sNo mt76_git modules were loaded.%s\n' "${DIM}" "${NC}"
else
	printf '%s  Unloaded %s module(s).%s\n' "${GREEN}" "${UNLOADED}" "${NC}"
fi


# ===== STEP 2: Remove installed modules ===================================
step 2 "Removing installed modules"

# non-dkms
if [ -d "${MODDESTDIR}" ]; then
	printf "  Removing non-dkms modules from %s\n" "${MODDESTDIR}"
	rm -rf "${MODDESTDIR}"
	rmdir --ignore-fail-on-non-empty /lib/modules/"${KVER}"/extra 2>/dev/null
	/sbin/depmod -a "${KVER}"
fi

# dkms
if command -v dkms >/dev/null 2>&1; then
	dkms status 2>/dev/null | while IFS="/,: " read -r drvname drvver kerver _dummy; do
		case "$drvname" in *mt76*)
			if [ "${kerver}" = "added" ]; then
				printf "  Removing from dkms: %s/%s\n" "${drvname}" "${drvver}"
				dkms remove -m "${drvname}" -v "${drvver}" --all 2>/dev/null
			else
				printf "  Uninstalling from dkms: %s/%s (kernel %s)\n" "${drvname}" "${drvver}" "${kerver}"
				dkms remove -m "${drvname}" -v "${drvver}" -k "${kerver}" \
					-c "/usr/src/${drvname}-${drvver}/dkms.conf" 2>/dev/null
			fi
		esac
	done
fi

printf '%s  Done.%s\n' "${GREEN}" "${NC}"


# ===== STEP 3: Clean up config and source =================================
step 3 "Cleaning up"

if [ -f /etc/modprobe.d/${OPTIONS_FILE} ]; then
	printf "  Removing %s from /etc/modprobe.d\n" "${OPTIONS_FILE}"
	rm -f /etc/modprobe.d/${OPTIONS_FILE}
fi

if [ -d /usr/src/${DRV_NAME}-${DRV_VERSION} ]; then
	printf "  Removing source from /usr/src/%s-%s\n" "${DRV_NAME}" "${DRV_VERSION}"
	rm -rf /usr/src/${DRV_NAME}-${DRV_VERSION}
fi

make clean >/dev/null 2>&1

printf '%s  Clean.%s\n' "${GREEN}" "${NC}"


# ===== STEP 4: Final depmod ===============================================
step 4 "Rebuilding module database"

/sbin/depmod -a "${KVER}"

printf '%s  Done.%s\n' "${GREEN}" "${NC}"



# ===== STEP 5: Rebuild initramfs ===========================================
step 5 "Rebuilding initramfs"

# Mirror what install-driver.sh does so the initramfs reflects current
# module state after the OOT modules are removed.
if command -v dracut >/dev/null 2>&1; then
	dracut -f >/dev/null 2>&1 \
		&& printf '%s  Rebuilt via dracut.%s\n' "${GREEN}" "${NC}" \
		|| printf '%s  dracut -f failed; rebuild manually.%s\n' "${YELLOW}" "${NC}"
elif command -v update-initramfs >/dev/null 2>&1; then
	update-initramfs -u >/dev/null 2>&1 \
		&& printf '%s  Rebuilt via update-initramfs.%s\n' "${GREEN}" "${NC}" \
		|| printf '%s  update-initramfs failed; rebuild manually.%s\n' "${YELLOW}" "${NC}"
elif command -v mkinitcpio >/dev/null 2>&1; then
	mkinitcpio -P >/dev/null 2>&1 \
		&& printf '%s  Rebuilt via mkinitcpio.%s\n' "${GREEN}" "${NC}" \
		|| printf '%s  mkinitcpio -P failed; rebuild manually.%s\n' "${YELLOW}" "${NC}"
else
	printf '  %sNo known initramfs tool found (dracut / update-initramfs / mkinitcpio).%s\n' "${YELLOW}" "${NC}"
fi


# ===========================================================================
# Footer
# ===========================================================================
printf "\n"
printf '  %s%sUninstall complete.%s\n' "${BOLD}" "${GREEN}" "${NC}"
printf "  You may now delete the driver directory if desired.\n"
printf '  %s================================================================%s\n' "${BOLD}" "${NC}"
printf "\n"

# if NoPrompt is not used, ask user some questions
if [ $NO_PROMPT -ne 1 ]; then
	printf "Do you want to reboot now? (recommended) [Y/n] "
	read -r yn
	case "$yn" in
		[nN]) ;;
		*) reboot ;;
	esac
fi
