#!/bin/sh

# Purpose: Install MediaTek mt76 out-of-kernel WiFi drivers.
#
# Supports dkms and non-dkms installations.
#
# To make this file executable:
#
# $ chmod +x install-driver.sh
#
# To execute this file:
#
# $ sudo ./install-driver.sh
#
# or
#
# $ sudo sh install-driver.sh
#
# To check for errors:
#
# $ shellcheck install-driver.sh
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

SCRIPT_NAME="install-driver.sh"
SCRIPT_VERSION="20260408"

DRV_NAME="mt76"
DRV_VERSION="1.0"
DRV_DIR="$(pwd)"

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
	YELLOW=$(printf '\033[1;33m')
	CYAN=$(printf '\033[0;36m')
	BOLD=$(printf '\033[1m')
	DIM=$(printf '\033[2m')
	NC=$(printf '\033[0m')
else
	GREEN='' RED='' YELLOW='' CYAN='' BOLD='' DIM='' NC=''
fi

# helper: step counter
TOTAL_STEPS=8
step() {
	printf '\n%s%s[%s/%s]%s %s%s%s\n' "${BOLD}" "${CYAN}" "$1" "${TOTAL_STEPS}" "${NC}" "${BOLD}" "$2" "${NC}"
}

# helper: print an error block
die_error() {
	printf '%sAn error occurred: %s%s\n' "${RED}" "$1" "${NC}"
	echo "Please report this error."
	echo "Please copy and post the following items into the problem report."
	echo "    -all screen output from ${SCRIPT_NAME}"
	echo "You should run the following before reattempting installation."
	echo "$ sudo ./uninstall-driver.sh"
	exit "$1"
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
# NoFirmware skips copying the bundled firmware blobs into /lib/firmware/mediatek
NO_PROMPT=0
SKIP_FIRMWARE=0
SIGNED=0
while [ $# -gt 0 ]
do
	case $1 in
		NoPrompt)
			NO_PROMPT=1 ;;
		NoFirmware)
			SKIP_FIRMWARE=1 ;;
		*h|*help|*)
			echo "Syntax $0 <NoPrompt> <NoFirmware>"
			echo "       NoPrompt   - noninteractive mode"
			echo "       NoFirmware - skip firmware installation"
			echo "       -h|--help  - Show help"
			exit 1
			;;
	esac
	shift
done

# If stdin is not a terminal, treat this run as implicitly non-interactive
# even without the NoPrompt flag. Otherwise blind `read -r` calls silently
# consume EOF and fall through to default-yes branches -- which for the
# post-install prompts means we would reboot the host behind the user's
# back when invoked from a pipe, cron job, cloud-init hook, or CI runner.
if [ ! -t 0 ]; then
	NO_PROMPT=1
fi

# ===========================================================================
# Banner
# ===========================================================================
printf '\n%s' "${BOLD}"
printf "  ================================================================\n"
printf "     mt76 WiFi Driver Installer\n"
printf '  ================================================================%s\n' "${NC}"
printf '  %s v%s\n' "${SCRIPT_NAME}" "${SCRIPT_VERSION}"

# git commit
if command -v git >/dev/null 2>&1 && [ -d "${DRV_DIR}/.git" ]; then
	GIT_HASH=$(git -C "${DRV_DIR}" rev-parse --short HEAD 2>/dev/null)
	GIT_DIRTY=""
	if ! git -C "${DRV_DIR}" diff --quiet HEAD 2>/dev/null; then
		GIT_DIRTY="-dirty"
	fi
	printf '  Source:  %s%s%s\n' "${CYAN}" "${GIT_HASH}${GIT_DIRTY}" "${NC}"
fi

# distro
if command -v lsb_release >/dev/null 2>&1; then
	DISTRO=$(lsb_release -sd 2>/dev/null)
	printf "  Distro:  %s\n" "${DISTRO}"
elif [ -f /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
	printf "  Distro:  %s\n" "${PRETTY_NAME:-${NAME} ${VERSION}}"
fi

printf "  Kernel:  %s (%s)\n" "${KVER}" "${KARCH}"

# the compiler the kernel was built with decides which compiler can build
# modules for it (see the clang note in the prerequisite check below)
KCONFIG="/lib/modules/${KVER}/build/.config"
KERNEL_CC=""
if [ -f "${KCONFIG}" ]; then
	KERNEL_CC=$(sed -n 's/^CONFIG_CC_VERSION_TEXT="\(.*\)"$/\1/p' "${KCONFIG}")
	[ -n "${KERNEL_CC}" ] && printf "  Built:   %s\n" "${KERNEL_CC}"
fi

# kernel parameters
if [ -f /proc/cmdline ]; then
	KPARAMS=$(sed 's/root=[^ ]*//;s/[ ]\+/, /g;s/^BOOT_IMAGE=[^ ]*//' /proc/cmdline | sed 's/^, //')
	if [ -n "${KPARAMS}" ]; then
		printf "  Params:  %s\n" "${KPARAMS}"
	fi
fi

# memory and CPU
SMEM=$(LC_ALL=C free | awk '/Mem:/ { print $2 }')
sproc=$(nproc)
# avoid Out of Memory condition in low-RAM systems by limiting core usage
if [ "$sproc" -gt 1 ]; then
	if [ "$SMEM" -lt 1400000 ]; then
		sproc=2
	fi
	if [ "$SMEM" -lt 700000 ]; then
		sproc=1
	fi
fi

printf "  CPUs:    %s/%s (in-use/total)\n" "${sproc}" "$(nproc)"
printf "  Memory:  %s kB\n" "${SMEM}"

# gcc
gcc_ver=$(gcc --version 2>/dev/null | head -1)
printf "  gcc:     %s\n" "${gcc_ver}"

# dkms
if command -v dkms >/dev/null 2>&1; then
	dkms_ver=$(dkms --version 2>/dev/null)
	printf "  dkms:    %s\n" "${dkms_ver}"
fi

# Secure Boot
if command -v mokutil >/dev/null 2>&1; then
	case $(mokutil --sb-state 2>&1) in
		*enabled*)  printf '  SecBoot: %senabled%s\n' "${YELLOW}" "${NC}" ;;
		*disabled*) printf "  SecBoot: disabled\n" ;;
		*)          printf "  SecBoot: not supported\n" ;;
	esac
else
	printf '  SecBoot: %sunknown (mokutil not installed)%s\n' "${DIM}" "${NC}"
fi

# VM detection
VM_INFO=$(dmesg 2>/dev/null | grep -i hypervisor | head -1)
if [ -n "${VM_INFO}" ]; then
	printf "  VM:      %s\n" "${VM_INFO}"
fi

# regulatory
if command -v iw >/dev/null 2>&1; then
	REG_COUNTRY=$(iw reg get 2>/dev/null | grep -m1 country)
	if [ -n "${REG_COUNTRY}" ]; then
		printf "  Reg:     %s\n" "${REG_COUNTRY}"
	fi
fi

# hardware detection
echo
printf '  %sDetected mt76 hardware:%s\n' "${BOLD}" "${NC}"
FOUND_HW=0
if command -v lsusb >/dev/null 2>&1; then
	lsusb_mt76=$(lsusb 2>/dev/null | grep -iE "mediatek|mt76|0e8d:" | head -10)
	if [ -n "${lsusb_mt76}" ]; then
		echo "${lsusb_mt76}" | while IFS= read -r line; do
			printf "    %s\n" "${line}"
		done
		FOUND_HW=1
	fi
fi
if command -v lspci >/dev/null 2>&1; then
	lspci_mt76=$(lspci 2>/dev/null | grep -iE "mediatek|mt76" | head -10)
	if [ -n "${lspci_mt76}" ]; then
		echo "${lspci_mt76}" | while IFS= read -r line; do
			printf "    %s\n" "${line}"
		done
		FOUND_HW=1
	fi
fi
# sysfs fallback: scan for USB devices bound to any mt76-family driver.
# Catches rebadged adapters (e.g. NetGear A8500, 0846:9072) where lsusb
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
				printf "    %s: ID %s:%s %s %s\n" "${drv_name}" "${dev_vid}" "${dev_pid}" "${dev_mfg}" "${dev_prd}"
			else
				printf "    %s: %s\n" "${drv_name}" "${dev_base}"
			fi
			FOUND_HW=1
		done
	done
fi
if [ "${FOUND_HW}" -eq 0 ]; then
	printf '    %s(none detected -- modules will still be installed)%s\n' "${DIM}" "${NC}"
fi
printf '  %s----------------------------------------------------------------%s\n' "${BOLD}" "${NC}"


# ===== STEP 1: Prerequisites =============================================
step 1 "Checking prerequisites"

MISSING=""
if ! command -v gcc >/dev/null 2>&1; then
	MISSING="${MISSING} gcc"
fi
# ensure /usr/sbin is in the PATH so iw can be found
if ! echo "$PATH" | grep -qw sbin; then
	export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
fi
if ! command -v iw >/dev/null 2>&1; then
	MISSING="${MISSING} iw"
fi
if ! command -v make >/dev/null 2>&1; then
	MISSING="${MISSING} make"
fi
# Without dkms, Secure Boot means the modules get signed here, which needs
# a key, and openssl creates it.
if ! command -v dkms >/dev/null 2>&1 && command -v mokutil >/dev/null 2>&1 \
	&& mokutil --sb-state 2>/dev/null | grep -qi enabled \
	&& ! command -v openssl >/dev/null 2>&1; then
	MISSING="${MISSING} openssl"
fi

# A kernel built with clang (CachyOS, Chimera) makes
# kbuild pass clang-only flags to whatever compiler builds a module, so gcc
# fails on it with "unrecognized command-line option -mstack-alignment=8".
# The Makefile switches the build to clang on its own; it just needs the
# tools installed. Package names are the same on Arch, Debian and Fedora.
if [ -f "${KCONFIG}" ] && grep -q '^CONFIG_CC_IS_CLANG=y' "${KCONFIG}"; then
	for tool in clang ld.lld llvm-ar; do
		if ! command -v "${tool}" >/dev/null 2>&1; then
			case "${tool}" in
				clang)   MISSING="${MISSING} clang" ;;
				ld.lld)  MISSING="${MISSING} lld" ;;
				llvm-ar) MISSING="${MISSING} llvm" ;;
			esac
		fi
	done
	if [ -n "${MISSING}" ]; then
		printf '  This kernel was built with clang, so its modules must be too.\n'
	fi
fi

if [ -n "${MISSING}" ]; then
	printf '%sMissing required packages:%s%s\n' "${RED}" "${NC}" "${MISSING}"
	echo "Please install them and run \"sudo ./${SCRIPT_NAME}\" again."
	exit 1
fi
printf '%s  All prerequisites found.%s\n' "${GREEN}" "${NC}"

# check for kernel header files
if [ ! -d "/lib/modules/${KVER}/build" ]; then
	printf '%s  Kernel headers not found for %s%s\n' "${RED}" "${KVER}" "${NC}"
	echo "  Please install them and try again."
	exit 1
fi
printf '%s  Kernel headers present.%s\n' "${GREEN}" "${NC}"


# ===== STEP 2: Clean previous installation ===============================
step 2 "Removing previous installation (if any)"

# ensure directory is clean
make clean >/dev/null 2>&1

# check for and uninstall non-dkms installations
if [ -d "${MODDESTDIR}" ]; then
	printf "  Removing non-dkms modules from %s\n" "${MODDESTDIR}"
	rm -rf "${MODDESTDIR}"
	/sbin/depmod -a "${KVER}"
fi

# check for and uninstall dkms installations
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
	if [ -f /etc/modprobe.d/${OPTIONS_FILE} ]; then
		printf "  Removing old %s\n" "${OPTIONS_FILE}"
		rm -f /etc/modprobe.d/${OPTIONS_FILE}
	fi
	if [ -d /usr/src/${DRV_NAME}-${DRV_VERSION} ]; then
		printf "  Removing old source from /usr/src/%s-%s\n" "${DRV_NAME}" "${DRV_VERSION}"
		rm -rf /usr/src/${DRV_NAME}-${DRV_VERSION}
	fi
fi

printf '%s  Clean.%s\n' "${GREEN}" "${NC}"


# ===== STEP 3: Configure ==================================================
step 3 "Configuring"

printf "  Installing %s to /etc/modprobe.d\n" "${OPTIONS_FILE}"
cp -f ${OPTIONS_FILE} /etc/modprobe.d

printf '%s  Done.%s\n' "${GREEN}" "${NC}"


# ===== STEP 4: Install firmware ===========================================
step 4 "Installing firmware"

FW_SRC="${DRV_DIR}/firmware"
FW_DEST="/lib/firmware/mediatek"

if [ "${SKIP_FIRMWARE}" -eq 1 ]; then
	printf '  %sSkipped (NoFirmware flag set).%s\n' "${YELLOW}" "${NC}"
	printf '  %sTesters should confirm linux-firmware is current before reporting bugs.%s\n' "${DIM}" "${NC}"
elif [ ! -d "${FW_SRC}" ]; then
	printf '  %sFirmware source directory not found at %s -- skipping.%s\n' "${YELLOW}" "${FW_SRC}" "${NC}"
else
	mkdir -p "${FW_DEST}"
	FW_COUNT=0

	# top-level .bin files (mt7610, mt7662, mt7902, mt7922, mt7961)
	for f in "${FW_SRC}"/*.bin; do
		[ -f "$f" ] || continue
		base=$(basename "$f")
		cp -f "$f" "${FW_DEST}/"
		printf '    %s -> %s/%s\n' "$base" "${FW_DEST}" "$base"
		FW_COUNT=$((FW_COUNT + 1))
	done

	# Any chip-specific subdirectory under firmware/ (mt7925, mt7927, future).
	for subdir in "${FW_SRC}"/*/; do
		[ -d "$subdir" ] || continue
		sub=$(basename "$subdir")
		mkdir -p "${FW_DEST}/${sub}"
		for f in "${subdir}"*.bin; do
			[ -f "$f" ] || continue
			base=$(basename "$f")
			cp -f "$f" "${FW_DEST}/${sub}/"
			printf '    %s/%s -> %s/%s/%s\n' "$sub" "$base" "${FW_DEST}" "$sub" "$base"
			FW_COUNT=$((FW_COUNT + 1))
		done
	done

	if [ "${FW_COUNT}" -gt 0 ]; then
		printf '%s  Installed %s firmware file(s) to %s%s\n' "${GREEN}" "${FW_COUNT}" "${FW_DEST}" "${NC}"
	else
		printf '  %sNo firmware files found in %s%s\n' "${YELLOW}" "${FW_SRC}" "${NC}"
	fi
fi


# ===== STEP 5: Build =====================================================
step 5 "Building modules"

if ! command -v dkms >/dev/null 2>&1; then
	printf '  %s(non-dkms build with %s cores)%s\n' "${DIM}" "${sproc}" "${NC}"

	make -j"${sproc}"
	RESULT=$?
	[ "$RESULT" != "0" ] && die_error "$RESULT"

	printf '%s  Build complete.%s\n' "${GREEN}" "${NC}"
else
	printf '  %s(dkms build)%s\n' "${DIM}" "${NC}"

	# copy source for dkms
	printf "  Copying source to /usr/src/%s-%s\n" "${DRV_NAME}" "${DRV_VERSION}"
	cp -r "${DRV_DIR}" /usr/src/${DRV_NAME}-${DRV_VERSION}

	# dkms add
	dkms add -m ${DRV_NAME} -v ${DRV_VERSION} -k "${KVER}" \
		-c "/usr/src/${DRV_NAME}-${DRV_VERSION}/dkms.conf"
	RESULT=$?

	if [ "$RESULT" != "0" ]; then
		if [ "$RESULT" = "3" ]; then
			printf '%s  Already in dkms tree. Run uninstall-driver.sh first.%s\n' "${YELLOW}" "${NC}"
			exit $RESULT
		fi
		die_error "$RESULT"
	fi
	printf '%s  Added to dkms.%s\n' "${GREEN}" "${NC}"

	# dkms build
	if command -v /usr/bin/time >/dev/null 2>&1; then
		/usr/bin/time -f "  Compile time: %U seconds" \
			dkms build -m ${DRV_NAME} -v ${DRV_VERSION} -k "${KVER}" \
			-c "/usr/src/${DRV_NAME}-${DRV_VERSION}/dkms.conf" --force
	else
		dkms build -m ${DRV_NAME} -v ${DRV_VERSION} -k "${KVER}" \
			-c "/usr/src/${DRV_NAME}-${DRV_VERSION}/dkms.conf" --force
	fi
	RESULT=$?
	[ "$RESULT" != "0" ] && die_error "$RESULT"

	printf '%s  Build complete.%s\n' "${GREEN}" "${NC}"
fi


# ===== STEP 6: Install ===================================================
step 6 "Installing modules"

if ! command -v dkms >/dev/null 2>&1; then
	# non-dkms: check for secure boot
	if command -v mokutil >/dev/null 2>&1; then
		if mokutil --sb-state 2>/dev/null | grep -qi enabled; then
			printf '  %sSecure Boot enabled -- signing the modules%s\n' "${YELLOW}" "${NC}"
			make sign-install
			RESULT=$?
			SIGNED=1
		else
			make install
			RESULT=$?
		fi
	else
		make install
		RESULT=$?
	fi
	[ "$RESULT" != "0" ] && die_error "$RESULT"
else
	# dkms install
	dkms install -m ${DRV_NAME} -v ${DRV_VERSION} -k "${KVER}" \
		-c "/usr/src/${DRV_NAME}-${DRV_VERSION}/dkms.conf" --force
	RESULT=$?
	[ "$RESULT" != "0" ] && die_error "$RESULT"
fi

# Count installed modules. We previously hard-coded MODDESTDIR
# (/extra/mt76) and a DKMS-specific /updates fallback, but the real
# install location varies by distro and by build mode:
#   - Alpine non-dkms:        /lib/modules/KVER/extra/mt76/*_git.ko.gz
#   - Arch dkms:              /lib/modules/KVER/updates/dkms/*_git.ko.zst
#   - Fedora dkms:            /lib/modules/KVER/extra/*_git.ko.xz   (flat)
#   - Debian dkms:            /lib/modules/KVER/updates/dkms/*_git.ko.xz
# The safest answer is to search the whole kernel modules tree for any
# *_git.ko* files, which catches every layout every distro uses.
MOD_COUNT=$(find "/lib/modules/${KVER}" -name "*_git.ko*" 2>/dev/null | wc -l)
printf '%s  Installed %s module(s) for kernel %s.%s\n' "${GREEN}" "${MOD_COUNT}" "${KVER}" "${NC}"


# ===== STEP 7: Verify ====================================================
step 7 "Verifying installation"

VERIFY_OK=1

if [ "${MOD_COUNT}" -eq 0 ]; then
	printf '  %sNo _git modules found after install!%s\n' "${RED}" "${NC}"
	VERIFY_OK=0
else
	printf '  %sModule count: %s%s\n' "${GREEN}" "${MOD_COUNT}" "${NC}"
fi

if modinfo mt76_git >/dev/null 2>&1; then
	GIT_VER=$(modinfo -F version mt76_git 2>/dev/null)
	printf '  %smt76_git resolvable by depmod (version: %s)%s\n' "${GREEN}" "${GIT_VER:-unknown}" "${NC}"
else
	printf '  %smodinfo cannot find mt76_git (normal before reboot)%s\n' "${YELLOW}" "${NC}"
fi

if [ -f /etc/modprobe.d/${OPTIONS_FILE} ]; then
	printf '  %sBlacklist config installed%s\n' "${GREEN}" "${NC}"
else
	printf '  %sBlacklist config MISSING!%s\n' "${RED}" "${NC}"
	VERIFY_OK=0
fi

if [ "${VERIFY_OK}" -eq 1 ]; then
	printf '  %sAll checks passed.%s\n' "${GREEN}" "${NC}"
else
	printf '  %sSome checks need attention -- see above.%s\n' "${YELLOW}" "${NC}"
fi

# unblock wifi
if command -v rfkill >/dev/null 2>&1; then
	rfkill unblock wlan
fi



# ===== STEP 8: Rebuild initramfs ===========================================
step 8 "Rebuilding initramfs"

# After installing the _git modules and the modprobe.d blacklist that
# silences the in-tree mt76 family, the initramfs may still cache the
# in-tree modules. Regenerate so the boot path picks up the new state
# rather than reloading the in-tree modules from a stale initramfs.
if command -v dracut >/dev/null 2>&1; then
	dracut -f >/dev/null 2>&1 \
		&& printf '%s  Rebuilt via dracut.%s\n' "${GREEN}" "${NC}" \
		|| printf '%s  dracut -f failed; rebuild manually before reboot.%s\n' "${YELLOW}" "${NC}"
elif command -v update-initramfs >/dev/null 2>&1; then
	update-initramfs -u >/dev/null 2>&1 \
		&& printf '%s  Rebuilt via update-initramfs.%s\n' "${GREEN}" "${NC}" \
		|| printf '%s  update-initramfs failed; rebuild manually before reboot.%s\n' "${YELLOW}" "${NC}"
elif command -v mkinitcpio >/dev/null 2>&1; then
	mkinitcpio -P >/dev/null 2>&1 \
		&& printf '%s  Rebuilt via mkinitcpio.%s\n' "${GREEN}" "${NC}" \
		|| printf '%s  mkinitcpio -P failed; rebuild manually before reboot.%s\n' "${YELLOW}" "${NC}"
else
	printf '  %sNo known initramfs tool found (dracut / update-initramfs / mkinitcpio).%s\n' "${YELLOW}" "${NC}"
	printf '  %sRegenerate manually if your distro uses a different system.%s\n' "${DIM}" "${NC}"
fi


# ===========================================================================
# Success banner
# ===========================================================================
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
printf "  Edit module parameters (optional):\n"
printf '    %s$ sudo ./edit-parameters.sh%s\n' "${CYAN}" "${NC}"
printf "\n"
printf '  %sTip: Update before distro or kernel upgrades.%s\n' "${DIM}" "${NC}"
printf '  %sTip: Updates can be run as often as you like (recommended: monthly).%s\n' "${DIM}" "${NC}"
printf '  %s================================================================%s\n' "${BOLD}" "${NC}"
printf "\n"

if [ $SIGNED -eq 1 ]; then
	printf '  %sSecure Boot:%s the modules are signed with a Machine Owner Key. If a\n' "${BOLD}" "${NC}"
	printf '  password was asked for above, the MOK manager appears on the next boot:\n'
	printf '  pick Enroll MOK, Continue, Yes, and enter that password. The driver\n'
	printf '  loads after that.\n\n'
fi

# if NoPrompt is not used, ask user about rebooting
if [ $NO_PROMPT -ne 1 ]; then
	printf '  Module parameters take effect when the driver is loaded. The\n'
	printf '  simplest way to apply the new settings is a reboot. (Skipping\n'
	printf '  this and rebooting later is fine.)\n\n'
	printf "Do you want to reboot now? (recommended) [Y/n] "
	read -r yn
	case "$yn" in
		[nN]) ;;
		*) reboot ;;
	esac
fi
