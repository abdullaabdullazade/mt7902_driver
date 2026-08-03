#!/bin/bash
#
# MT7902 Driver Installer
# Builds and installs WiFi + Bluetooth drivers and firmware for the
# MediaTek MT7902 PCIe wireless card.
#
# Usage: sudo ./install.sh [--all|--wifi|--bt] [--no-dkms]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KVER=$(uname -r)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)

DO_WIFI=false
DO_BT=false
USE_DKMS=true
USE_FALLBACK=false
FORCE_CUSTOM=false
PREFER_GEN4=false
DO_KERNEL_UPGRADE=false
SKIP_CARD_CHECK=false
FALLBACK_REPO="https://github.com/hmtheboy154/mt7902"
FALLBACK_DIR="/tmp/mt7902-fallback"
WIFI_DRIVER_USED=""

# ── colors ────────────────────────────────────────────────────
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'

# ── banner (vertical RGB gradient: cyan → purple → pink) ─────
show_banner() {
    echo ""
    echo -e "\033[1;38;2;0;210;255m  ███╗   ███╗████████╗███████╗ █████╗  ██████╗ ██████╗         ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ \033[0m"
    echo -e "\033[1;38;2;50;180;255m  ████╗ ████║╚══██╔══╝╚════██║██╔══██╗██╔═████╗╚════██╗        ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗\033[0m"
    echo -e "\033[1;38;2;120;140;250m  ██╔████╔██║   ██║       ██╔╝╚██████║██║██╔██║ █████╔╝        ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝\033[0m"
    echo -e "\033[1;38;2;170;100;240m  ██║╚██╔╝██║   ██║      ██╔╝  ╚═══██║████╔╝██║██╔═══╝         ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗\033[0m"
    echo -e "\033[1;38;2;210;75;210m  ██║ ╚═╝ ██║   ██║      ██║   █████╔╝╚██████╔╝███████╗███████╗██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║\033[0m"
    echo -e "\033[1;38;2;236;72;153m  ╚═╝     ╚═╝   ╚═╝      ╚═╝   ╚════╝  ╚═════╝ ╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝\033[0m"
    echo ""
}

show_info_box() {
    echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
    printf "  ${WHITE}Kernel${NC}  %-20s ${WHITE}Arch${NC}  %s\n" "$KVER" "$(uname -m)"
    printf "  ${WHITE}Distro${NC}  %-20s ${WHITE}Date${NC}  %s\n" "$DISTRO" "$(date '+%Y-%m-%d %H:%M')"
    echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
    echo ""
}

# ── step logging ──────────────────────────────────────────────
step_count=0
step() {
    step_count=$((step_count + 1))
    echo -e "  ${CYAN}[${step_count}]${NC} ${BOLD}$1${NC}"
}
ok()   { echo -e "      ${GREEN}✓${NC} $1"; }
warn() { echo -e "      ${YELLOW}!${NC} $1"; }
fail() { echo -e "      ${RED}✗${NC} $1"; }

# ── crash safety ──────────────────────────────────────────────
# Set to true once anything persistent (DKMS module, blacklist,
# initramfs) has been written. If the script then dies, is Ctrl-C'd,
# or the kernel hangs during modprobe, the user must be told how to
# get back to a bootable system.
GEN4_STAGED=false

print_recovery_notice() {
    echo ""
    echo -e "  ${YELLOW}━━━ RECOVERY ━━━${NC}"
    echo -e "  If this machine does not boot after a reboot, at the GRUB menu"
    echo -e "  press ${BOLD}e${NC} on the Ubuntu/Linux entry, append this to the ${BOLD}linux${NC} line,"
    echo -e "  then press ${BOLD}Ctrl+X${NC}:"
    echo ""
    echo -e "      ${CYAN}modprobe.blacklist=mt7902,mt7902e${NC}"
    echo ""
    echo -e "  Once booted, run: ${CYAN}sudo ${SCRIPT_DIR}/uninstall.sh${NC}"
    echo ""
}

on_error() {
    local rc=$?
    [ "$rc" -eq 0 ] && return 0
    echo ""
    fail "Installer aborted (exit ${rc})."
    if [ "$GEN4_STAGED" = true ]; then
        print_recovery_notice
    fi
}
trap on_error EXIT

# ── usage ─────────────────────────────────────────────────────
usage() {
    show_banner
    cat <<EOF
  Usage: sudo $0 [OPTION]

  Options:
    --all         Install both WiFi and Bluetooth drivers (default)
    --wifi        Install WiFi driver only
    --bt          Install Bluetooth driver only
    --no-dkms     Build WiFi driver manually instead of using DKMS
    --fallback    Skip gen4 driver, use hmtheboy154/mt7902 directly
    --force-custom Build a custom driver even if the kernel already
                  supports 14c3:7902 in the in-tree mt7921e driver
    --gen4        Try the bundled gen4-mt7902 vendor driver before the
                  mt76-based one (default order is the other way round)
    --upgrade-kernel
                  Offer to install a mainline 7.1 kernel, which supports this
                  card in-tree. Asks for confirmation; never reboots for you.
                  Debian/Ubuntu only, and refused under Secure Boot.
    --no-card-check
                  Install even when no MT7902 is present on the PCI bus
    -h, --help    Show this message

  Examples:
    sudo $0               # install everything (auto-selects best driver)
    sudo $0 --wifi        # wifi driver + firmware only
    sudo $0 --bt          # bluetooth driver + firmware only
    sudo $0 --fallback    # use hmtheboy154/mt7902 driver directly
EOF
    exit 0
}

# parse args — default is --all
if [ $# -eq 0 ]; then
    DO_WIFI=true; DO_BT=true
fi

for arg in "$@"; do
    case $arg in
        --all)      DO_WIFI=true; DO_BT=true ;;
        --wifi)     DO_WIFI=true ;;
        --bt)       DO_BT=true ;;
        --no-dkms)  USE_DKMS=false ;;
        --fallback) USE_FALLBACK=true ;;
        --force-custom) FORCE_CUSTOM=true ;;
        --gen4)     PREFER_GEN4=true ;;
        --upgrade-kernel) DO_KERNEL_UPGRADE=true ;;
        --no-card-check) SKIP_CARD_CHECK=true ;;
        -h|--help)  usage ;;
        *)          echo "Unknown option: $arg"; usage ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ Run this script with sudo${NC}"
    exit 1
fi

# ── distro detection ──────────────────────────────────────────
DISTRO="unknown"
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|linuxmint|pop|elementary|zorin) DISTRO="debian" ;;
            fedora|rhel|centos|rocky|alma)                DISTRO="fedora" ;;
            arch|manjaro|endeavouros|garuda)               DISTRO="arch" ;;
            opensuse*|sles)                                DISTRO="suse" ;;
        esac
    fi
}

install_deps() {
    step "Installing build dependencies"
    local rc=0
    case "$DISTRO" in
        debian) apt-get update -qq >/dev/null 2>&1
                apt-get install -y build-essential linux-headers-$(uname -r) dkms zstd git > /dev/null 2>&1 || rc=$? ;;
        fedora) dnf install -y make gcc kernel-devel kernel-headers dkms zstd git > /dev/null 2>&1 || rc=$? ;;
        arch)   pacman -S --needed --noconfirm base-devel linux-headers dkms zstd git > /dev/null 2>&1 || rc=$? ;;
        suse)   zypper install -y make gcc kernel-devel dkms zstd git > /dev/null 2>&1 || rc=$? ;;
        *)      warn "Unknown distro — install manually: build-essential, linux-headers, dkms, zstd, git"; return 0 ;;
    esac

    if [ "$rc" -ne 0 ]; then
        # Mainline or vendor kernels often have no matching headers package in
        # the distribution's repositories. That is not fatal on its own — the
        # headers may already be installed, or the in-tree driver may make the
        # whole build unnecessary — so carry on and let the build be the judge.
        warn "Could not install every build dependency (package manager exit ${rc})"
        if [ -d "/lib/modules/${KVER}/build" ]; then
            ok "Kernel headers for ${KVER} are present, continuing"
        else
            warn "No kernel headers found at /lib/modules/${KVER}/build"
            warn "If a build fails below, install the headers for your kernel first"
        fi
        return 0
    fi
    ok "Dependencies ready (${DISTRO})"
}

# ── optional kernel upgrade ───────────────────────────────────
# Only ever runs behind --upgrade-kernel, and only after the user types "yes".
# Replacing someone's kernel is not something a WiFi driver installer should
# decide on its own: it can strand out-of-tree DKMS modules, and an unsigned
# mainline build will not boot at all with Secure Boot on.
secure_boot_enabled() {
    if command -v mokutil >/dev/null 2>&1; then
        mokutil --sb-state 2>/dev/null | grep -qi "SecureBoot enabled" && return 0
    fi
    local f
    for f in /sys/firmware/efi/efivars/SecureBoot-*; do
        [ -e "$f" ] || continue
        # 5th byte is the flag
        [ "$(od -An -t u1 -j 4 -N 1 "$f" 2>/dev/null | tr -d ' ')" = "1" ] && return 0
    done
    return 1
}

# Shown before anything is built, so nobody sits through a driver install
# without knowing that a kernel upgrade solves the problem outright.
announce_kernel_situation() {
    intree_supports_mt7902 && return 0

    echo -e "  ${YELLOW}━━━ HEADS UP ━━━${NC}"
    echo -e "  Your kernel is ${BOLD}${KMAJOR}.${KMINOR}${NC}, which has no MT7902 support of its own."
    echo -e "  ${BOLD}Kernel 7.1 and newer support this card out of the box${NC} — no"
    echo -e "  out-of-tree driver, no DKMS, nothing to rebuild on every update."
    echo ""
    echo -e "  ${WHITE}Getting to 7.1 depends on your distribution:${NC}"
    case "$DISTRO" in
        debian) echo -e "    ${DIM}Ubuntu/Debian stable do not move to a new kernel series within${NC}"
                echo -e "    ${DIM}a release. Either move to a newer release, or install a${NC}"
                echo -e "    ${DIM}mainline build: ${NC}${CYAN}sudo ./install.sh --upgrade-kernel${NC}" ;;
        fedora) echo -e "    ${DIM}Fedora does ship new kernel series to existing releases, so${NC}"
                echo -e "    ${DIM}${NC}${CYAN}sudo dnf upgrade --refresh${NC}${DIM} will get you there once 7.1 lands.${NC}"
                echo -e "    ${DIM}Until then a full upgrade is gigabytes and changes nothing here.${NC}" ;;
        arch)   echo -e "    ${CYAN}sudo pacman -Syu${NC}${DIM} — rolling, so this should already have it${NC}" ;;
        suse)   echo -e "    ${CYAN}sudo zypper dup${NC}${DIM} — on Tumbleweed this should already have it${NC}" ;;
        *)      echo -e "    ${CYAN}Update through your distribution's usual channel${NC}" ;;
    esac
    echo ""
    echo -e "  ${DIM}This is not urgent: the driver installed below works on 6.6 - 7.0.${NC}"
    echo -e "  ${DIM}Upgrading just means nothing to rebuild on future kernel updates.${NC}"
    # Offer it as a choice when there is someone there to answer. Default is No:
    # a driver installer should not upgrade a kernel unless asked to.
    # /dev/tty can exist as a device node yet not be openable (containers, cron,
    # piped runs), so test by actually opening it.
    if ( exec 3< /dev/tty ) 2>/dev/null; then
        local reply=""
        printf "  Upgrade the kernel now instead of installing a driver? [y/%bN%b] " "${BOLD}" "${NC}"
        read -r reply < /dev/tty || reply=""
        case "$reply" in
            y|Y|yes|YES)
                if [ "$DISTRO" = "debian" ]; then
                    upgrade_kernel && exit 0
                else
                    run_distro_upgrade && exit 0
                fi
                warn "Kernel upgrade did not complete — continuing with the driver install"
                ;;
        esac
        echo ""
        return 0
    fi

    echo ""
    echo -e "  ${DIM}Carrying on for now and installing the best driver available${NC}"
    echo -e "  ${DIM}for ${KMAJOR}.${KMINOR}. Press Ctrl+C within 5s to stop and upgrade instead.${NC}"
    echo ""
    sleep 5
}

# Distributions other than Debian/Ubuntu get their own supported upgrade path
# rather than an unsigned mainline build. Whether it actually reaches 7.1
# depends on what the distribution is shipping today, so say so.
# What kernel version can this distribution actually give us right now? A full
# system upgrade is gigabytes; it is not worth downloading to end up on the same
# kernel series. Only asked when the user has already said they want to upgrade.
available_kernel_version() {
    case "$DISTRO" in
        fedora) dnf -q --refresh list --available kernel 2>/dev/null |
                    awk '/^kernel/ {print $2}' | sort -V | tail -1 ;;
        arch)   pacman -Sy >/dev/null 2>&1
                pacman -Si linux 2>/dev/null | awk -F': ' '/^Version/ {print $2}' | head -1 ;;
        suse)   zypper --non-interactive info kernel-default 2>/dev/null |
                    awk -F': ' '/^Version/ {print $2}' | head -1 ;;
    esac
}

run_distro_upgrade() {
    local cmd=""
    case "$DISTRO" in
        fedora) cmd="dnf upgrade --refresh -y" ;;
        arch)   cmd="pacman -Syu --noconfirm" ;;
        suse)   cmd="zypper --non-interactive dup" ;;
        *)      warn "No automatic upgrade path known for this distribution"
                suggest_kernel_upgrade
                return 1 ;;
    esac

    step "Checking what kernel your distribution offers"
    local avail maj min
    avail=$(available_kernel_version)
    if [ -n "$avail" ]; then
        maj=${avail%%.*}
        min=${avail#*.}; min=${min%%.*}
        min=${min//[!0-9]/}
        if [ -n "$maj" ] && [ -n "$min" ] &&
           { [ "$maj" -lt 7 ] || { [ "$maj" -eq 7 ] && [ "$min" -lt 1 ]; }; }; then
            warn "Newest kernel your distribution offers is ${avail} — below 7.1"
            echo ""
            echo -e "  ${DIM}So this will not give you in-tree support for the card yet.${NC}"
            echo -e "  ${DIM}It still updates the system and the kernel within its series,${NC}"
            echo -e "  ${DIM}which is worth doing on its own — it is just a large download.${NC}"
            echo ""
            printf "  Run a full system update anyway? [y/%bN%b] " "${BOLD}" "${NC}"
            local go=""
            read -r go < /dev/tty || go=""
            case "$go" in
                y|Y|yes|YES) ;;
                *) warn "Skipped — continuing with the driver install"; return 1 ;;
            esac
        else
            ok "Kernel ${avail} is available — this will give you in-tree support"
        fi
    else
        warn "Could not determine which kernel your distribution offers"
    fi

    echo ""
    echo -e "  ${YELLOW}This runs a full system upgrade:${NC}  ${CYAN}${cmd}${NC}"
    echo -e "  ${DIM}Nothing is rebooted for you.${NC}"
    echo ""
    printf "  Type %byes%b to run it: " "${BOLD}" "${NC}"
    local answer=""
    read -r answer < /dev/tty || true
    [ "$answer" = "yes" ] || { warn "Cancelled"; return 1; }

    step "Running system upgrade — this downloads a lot and takes a while"
    echo -e "  ${DIM}Leave it alone until it finishes; output below is the package manager's.${NC}"
    echo ""
    if ! $cmd; then
        fail "System upgrade failed"
        return 1
    fi
    ok "System upgrade finished"
    echo ""
    echo -e "  ${WHITE}Reboot, then run this script again.${NC}"
    echo -e "  ${DIM}If the new kernel is 7.1+ it will install nothing at all.${NC}"
    echo ""
    return 0
}

upgrade_kernel() {
    step "Kernel upgrade requested (--upgrade-kernel)"

    if intree_supports_mt7902; then
        ok "This kernel already supports the card — no upgrade needed"
        return 0
    fi

    if [ "$DISTRO" != "debian" ]; then
        warn "Automatic upgrade is only wired up for Debian/Ubuntu here."
        suggest_kernel_upgrade
        return 1
    fi

    if secure_boot_enabled; then
        fail "Secure Boot is enabled."
        fail "Mainline kernel builds are unsigned and will not boot with it on."
        fail "Use your distribution's own signed kernel instead:"
        echo -e "    ${DIM}sudo apt update && sudo apt full-upgrade${NC}"
        return 1
    fi

    local base="https://kernel.ubuntu.com/mainline"
    step "Finding the newest 7.1.x build"
    local ver
    ver=$(curl -fsSL --max-time 60 "${base}/" 2>/dev/null |
          grep -oE 'v7\.1(\.[0-9]+)?/' | tr -d '/' | sort -uV | tail -1)
    [ -n "$ver" ] || { fail "Could not reach ${base}"; return 1; }
    ok "Newest build: ${ver}"

    local dir="${base}/${ver}/amd64"
    local sums
    sums=$(curl -fsSL --max-time 60 "${dir}/CHECKSUMS" 2>/dev/null) ||
        { fail "Could not fetch CHECKSUMS for ${ver}"; return 1; }

    local img mod
    img=$(echo "$sums" | grep -oE 'linux-image-unsigned-[^ ]*_amd64\.deb' | head -1)
    mod=$(echo "$sums" | grep -oE 'linux-modules-[^ ]*_amd64\.deb' | head -1)
    [ -n "$img" ] && [ -n "$mod" ] || { fail "Unexpected file listing for ${ver}"; return 1; }

    echo ""
    echo -e "  ${YELLOW}This will install an unsigned mainline kernel:${NC}"
    echo -e "    ${DIM}${img}${NC}"
    echo -e "    ${DIM}${mod}${NC}"
    echo -e "  ${DIM}Source: ${dir}${NC}"
    echo ""
    echo -e "  ${YELLOW}It is not supported by your distribution.${NC} Your current kernel stays"
    echo -e "  installed and selectable from the GRUB menu. Out-of-tree modules"
    echo -e "  (NVIDIA, VirtualBox, ...) will need rebuilding for the new kernel."
    echo ""
    printf "  Type %byes%b to continue: " "${BOLD}" "${NC}"
    local answer=""
    read -r answer < /dev/tty || true
    if [ "$answer" != "yes" ]; then
        warn "Kernel upgrade cancelled"
        return 1
    fi

    local tmp
    tmp=$(mktemp -d /tmp/mt7902-kernel-XXXXXX)
    step "Downloading ${ver}"
    local f
    for f in "$mod" "$img"; do
        curl -fsSL --max-time 900 -o "${tmp}/${f}" "${dir}/${f}" ||
            { fail "Download failed: ${f}"; rm -rf "$tmp"; return 1; }
    done

    step "Verifying checksums"
    for f in "$mod" "$img"; do
        local want got
        want=$(echo "$sums" | grep -E "^[0-9a-f]{64}  ${f}$" | awk '{print $1}' | head -1)
        got=$(sha256sum "${tmp}/${f}" | awk '{print $1}')
        if [ -z "$want" ] || [ "$want" != "$got" ]; then
            fail "Checksum mismatch for ${f} — refusing to install"
            rm -rf "$tmp"
            return 1
        fi
    done
    ok "Checksums verified"

    step "Installing ${ver}"
    # Minimal images (cloud, server, containers) are missing pieces the kernel
    # postinst expects; without them its triggers fail with
    # "run-parts: missing operand" even though the kernel itself unpacked fine.
    apt-get install -y linux-base initramfs-tools grub2-common > /dev/null 2>&1 || true

    # apt resolves dependencies where a bare dpkg -i cannot.
    if ! apt-get install -y "${tmp}/${mod}" "${tmp}/${img}" > "${tmp}/apt.log" 2>&1; then
        dpkg -i "${tmp}/${mod}" "${tmp}/${img}" > "${tmp}/dpkg.log" 2>&1 || true
    fi
    dpkg --configure -a > /dev/null 2>&1 || true
    apt-get install -f -y > /dev/null 2>&1 || true

    # Judge by what ended up on disk, not by the exit status of a trigger.
    local kver_new="${ver#v}"
    local img_file
    img_file=$(ls /boot/vmlinuz-*"${kver_new}"* 2>/dev/null | head -1)
    if [ -z "$img_file" ]; then
        fail "Kernel ${ver} did not install — logs in ${tmp}"
        return 1
    fi

    command -v update-grub >/dev/null 2>&1 && update-grub > /dev/null 2>&1 || true
    ok "Kernel ${ver} installed ($(basename "$img_file"))"
    rm -rf "$tmp"

    echo ""
    echo -e "  ${WHITE}Reboot into the new kernel, then run this script again.${NC}"
    echo -e "  ${DIM}It will find the in-tree driver and install nothing.${NC}"
    echo ""
    return 0
}

# ── card presence ─────────────────────────────────────────────
# Without this, a machine that has no MT7902 builds every driver in turn and
# finishes with "both drivers failed", which reads like the drivers are broken
# rather than like the card is absent. Read sysfs rather than shelling out to
# lspci, which is not installed everywhere.
mt7902_present() {
    local d vendor device
    for d in /sys/bus/pci/devices/*; do
        [ -r "$d/vendor" ] && [ -r "$d/device" ] || continue
        read -r vendor < "$d/vendor"
        read -r device < "$d/device"
        [ "$vendor" = "0x14c3" ] && [ "$device" = "0x7902" ] && return 0
    done
    return 1
}

# ── wireless interface detection ──────────────────────────────
# Do not match on interface names. systemd's predictable naming produces wls*
# on some machines — a real MT7902 on kernel 7.1 comes up as "wls4" — and a
# wlan*/wlp*/wlo* pattern misses it, so a working driver gets reported as
# broken and torn out again. Ask the kernel instead: every wireless netdev has
# a "wireless" directory in sysfs.
wireless_iface_present() {
    local d
    for d in /sys/class/net/*/wireless; do
        [ -d "$d" ] && return 0
    done
    return 1
}

# ── firmware installation ─────────────────────────────────────
# A truncated firmware file is worse than a missing one: request_firmware()
# finds it, hands the driver zero bytes and fails with -EINVAL (-22), and
# EVERY driver for this card then dies with "hardware init failed" — the
# custom ones and the in-tree mt7921e alike. Copy to a temporary name, check
# the size, and only then move it into place, so a failed copy can never
# leave a stub behind that shadows a good file from linux-firmware.
install_firmware() {
    local src="$1" dstdir="$2"
    local base tmp srcsz dstsz
    base="$(basename "$src")"
    srcsz=$(stat -c %s "$src" 2>/dev/null || echo 0)

    if [ "$srcsz" -eq 0 ]; then
        fail "Refusing to install empty firmware file: ${base}"
        return 1
    fi

    mkdir -p "$dstdir"

    # linux-firmware has shipped MT7902 firmware since its 20260309 release.
    # If the distribution already provides a non-empty copy, that one is
    # authoritative — do not overwrite it with the bundle in this repo.
    if [ -s "${dstdir}/${base}" ]; then
        return 0
    fi

    tmp="${dstdir}/.${base}.new"
    if ! cp "$src" "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        fail "Could not copy firmware ${base}"
        return 1
    fi

    dstsz=$(stat -c %s "$tmp" 2>/dev/null || echo 0)
    if [ "$dstsz" -ne "$srcsz" ]; then
        rm -f "$tmp"
        fail "Firmware ${base} copied short (${dstsz}/${srcsz} bytes) — not installing"
        return 1
    fi

    mv -f "$tmp" "${dstdir}/${base}"
}

# Catch stubs left behind by earlier runs (or by anything else) before a
# driver trips over them.
verify_firmware() {
    local dir="$1" empty
    empty=$(find "$dir" -maxdepth 2 -name 'mt7902*' -o -maxdepth 2 -name 'WIFI_*MT7902*' 2>/dev/null | while read -r f; do
        [ -f "$f" ] && [ ! -s "$f" ] && echo "$f"
    done)
    if [ -n "$empty" ]; then
        fail "Zero-byte firmware files present — the card will fail with -EINVAL:"
        echo "$empty" | while read -r f; do echo -e "        ${DIM}${f}${NC}"; done
        fail "Remove them and reinstall linux-firmware, then re-run this script."
        return 1
    fi
    return 0
}

# ── in-tree support probe ─────────────────────────────────────
# Linux 7.1 merged MT7902 (14c3:7902) support into the in-tree mt7921e driver,
# with the firmware shipped in linux-firmware. On those kernels the stock driver
# is the right answer and blacklisting it — as this installer used to do
# unconditionally — replaces a working driver with a fragile one. Kernels up to
# 6.19 list only 7920/0616/0608/7922/7961 and leave the device unclaimed; those
# still need the driver in this repo. Probe the alias rather than the version
# number, so distro kernels that backport the support are detected too.
intree_supports_mt7902() {
    modinfo mt7921e 2>/dev/null | grep -qi 'd00007902'
}

# hmtheboy154/mt7902 is mainline mt76 plus MediaTek's MT7902 series, backported
# to older kernels. Its README claims 6.6~6.19, but the tree also builds clean
# against 7.0 (verified against the 7.0.0-070000-generic headers), which matters
# because 7.0 is otherwise stranded: in-tree support only starts at 7.1.
# Below 6.6 the backport does not apply and only the vendor tree is left.
backport_supports_kernel() {
    { [ "$KMAJOR" -eq 6 ] && [ "$KMINOR" -ge 6 ]; } || [ "$KMAJOR" -ge 7 ]
}

# Everything this repo installs is a workaround for running a kernel older than
# 7.1. Say so once, with the command for the distro at hand, and let the user
# decide — an installer for a WiFi driver has no business replacing someone's
# kernel behind their back, which can break DKMS modules, Secure Boot signing
# and the boot itself.
suggest_kernel_upgrade() {
    echo ""
    echo -e "  ${DIM}Kernel 7.1+ supports this card out of the box, with no${NC}"
    echo -e "  ${DIM}out-of-tree driver at all. If you want to get there:${NC}"
    case "$DISTRO" in
        debian) echo -e "    ${DIM}sudo apt update && sudo apt full-upgrade${NC}"
                echo -e "    ${DIM}(Ubuntu: a newer HWE stack, e.g. linux-generic-hwe-<release>)${NC}" ;;
        fedora) echo -e "    ${DIM}sudo dnf upgrade --refresh${NC}" ;;
        arch)   echo -e "    ${DIM}sudo pacman -Syu${NC}" ;;
        suse)   echo -e "    ${DIM}sudo zypper dup${NC}" ;;
        *)      echo -e "    ${DIM}Update through your distribution's usual channel${NC}" ;;
    esac
    echo -e "  ${DIM}Then re-run this script — it will detect the in-tree driver${NC}"
    echo -e "  ${DIM}and remove the need for anything installed here.${NC}"
    echo ""
}

warn_unsupported_kernel() {
    echo ""
    echo -e "  ${YELLOW}━━━ KERNEL ${KMAJOR}.${KMINOR} IS TOO OLD ━━━${NC}"
    echo -e "  The mt76 driver for this card needs ${BOLD}kernel 6.6 or newer${NC};"
    echo -e "  ${BOLD}7.1+${NC} has it in-tree. Only the old vendor driver is left here,"
    echo -e "  and it frequently fails MCU init on this card."
    echo ""
    echo -e "  ${WHITE}Best fix:${NC} move to kernel 7.1 or newer and use the stock driver."
    echo ""
}

use_intree_driver() {
    step "Using in-tree mt7921e (kernel ${KVER} supports 14c3:7902)"
    # check_wifi_health() looks for the custom mt7902 module by name, so the
    # in-tree driver needs its own check: module loaded and an interface up.
    if try_modprobe mt7921e && sleep 2 && lsmod | grep -q '^mt7921e ' && \
       wireless_iface_present; then
        WIFI_DRIVER_USED="mt7921e (in-tree)"
        ok "WiFi is up on the in-tree driver — nothing to build"
        echo ""
        echo -e "  ${DIM}Your kernel already supports this card. The custom driver${NC}"
        echo -e "  ${DIM}is not needed and is not installed. To force it anyway:${NC}"
        echo -e "    ${DIM}sudo ./install.sh --force-custom${NC}"
        return 0
    fi
    warn "In-tree mt7921e did not bring the interface up; falling back to the custom driver"
    rmmod mt7921e 2>/dev/null || true
    return 1
}

# ── initramfs ─────────────────────────────────────────────────
rebuild_initramfs() {
    if command -v update-initramfs &>/dev/null; then
        update-initramfs -u 2>/dev/null && ok "initramfs updated (Debian/Ubuntu)"
    elif command -v mkinitcpio &>/dev/null; then
        mkinitcpio -P 2>/dev/null && ok "initramfs updated (Arch)"
    elif command -v dracut &>/dev/null; then
        dracut --force 2>/dev/null && ok "initramfs updated (Fedora/RHEL)"
    fi
    return 0
}

# ── blacklist stock drivers ───────────────────────────────────
# Only called AFTER the custom driver has proven it works. Doing this
# earlier leaves a machine with no working WiFi driver at all when the
# custom one fails.
blacklist_stock_drivers() {
    step "Blacklisting conflicting stock drivers"
    mkdir -p /etc/modprobe.d
    cat > /etc/modprobe.d/blacklist-mt7921.conf <<'EOF'
# Blacklist stock MediaTek WiFi drivers — using custom mt7902.ko instead
blacklist mt7921e
blacklist mt7902e
blacklist mt7921_common
blacklist mt76_connac_lib
blacklist mt7921s
blacklist mt7921u
EOF
    ok "Stock drivers blacklisted (/etc/modprobe.d/blacklist-mt7921.conf)"
    rebuild_initramfs
}

# ── guarded module load ───────────────────────────────────────
# A bad mt7902 build can wedge the kernel thread in probe and never
# return. Bounded so the installer keeps control and can fall back.
try_modprobe() {
    timeout 60 modprobe "$@" 2>/dev/null
    local rc=$?
    if [ "$rc" -eq 124 ]; then
        warn "modprobe $* timed out after 60s (driver hung in probe)"
        return 1
    fi
    return $rc
}

# ── wifi health check ─────────────────────────────────────────
# Returns 0 if the driver loaded OK, 1 if it failed or has errors.
check_wifi_health() {
    local healthy=true

    # 1. Check if module is loaded
    if ! lsmod | grep -q "^mt7902 "; then
        warn "Module mt7902 not found in lsmod"
        healthy=false
    fi

    # 2. Check dmesg for panic / error indicators from mt7902
    local errors
    errors=$(dmesg --since "30 seconds ago" 2>/dev/null | grep -iE 'mt7902.*(panic|oops|bug|error|fail|timeout|firmware.*fail|mcu.*fail|BAR0)' || true)
    if [ -n "$errors" ]; then
        warn "Kernel errors detected after loading mt7902:"
        echo "$errors" | head -5 | while read -r line; do
            echo -e "        ${DIM}${line}${NC}"
        done
        healthy=false
    fi

    # 3. Check if a WiFi interface appeared (wlan*, wlp*, etc.)
    sleep 2  # give the interface a moment to register
    if ! wireless_iface_present; then
        warn "No WiFi interface appeared"
        healthy=false
    fi

    [ "$healthy" = true ]
}

# ── full cleanup of failed gen4-mt7902 ────────────────────────
# Removes everything so the fallback driver has a clean slate.
cleanup_gen4() {
    step "Removing failed gen4-mt7902 driver"

    # 1. Unload module
    rmmod mt7902 2>/dev/null || true
    ok "Module unloaded"

    # 2. Remove from DKMS
    if dkms status gen4-mt7902 2>/dev/null | grep -q "gen4-mt7902"; then
        dkms remove gen4-mt7902/0.1 --all 2>/dev/null || true
        ok "DKMS entry removed"
    fi

    # 3. Remove DKMS source copy
    rm -rf /usr/src/gen4-mt7902-0.1
    ok "DKMS source removed (/usr/src/gen4-mt7902-0.1)"

    # 4. Remove installed .ko files
    local mod_dir="/lib/modules/$(uname -r)"
    find "$mod_dir" -name "mt7902.ko*" -delete 2>/dev/null || true
    ok "Kernel module files cleaned"

    # 5. Remove modprobe config (mcu_bypass etc.)
    rm -f /etc/modprobe.d/mt7902.conf
    rm -f /etc/modprobe.d/mt7902-noautoload.conf

    # 6. Remove blacklist (so hmtheboy154's mt7902e is not blocked)
    rm -f /etc/modprobe.d/blacklist-mt7921.conf
    ok "Blacklist removed (mt7902e will be allowed to load)"

    # 7. Remove late-load service
    if command -v systemctl &>/dev/null; then
        systemctl disable mt7902-late.service 2>/dev/null || true
        rm -f /etc/systemd/system/mt7902-late.service
        systemctl daemon-reload 2>/dev/null || true
    fi

    # 8. Rebuild initramfs without the blacklist
    if command -v update-initramfs &>/dev/null; then
        update-initramfs -u 2>/dev/null && ok "initramfs rebuilt (clean)"
    elif command -v mkinitcpio &>/dev/null; then
        mkinitcpio -P 2>/dev/null && ok "initramfs rebuilt (clean)"
    elif command -v dracut &>/dev/null; then
        dracut --force 2>/dev/null && ok "initramfs rebuilt (clean)"
    fi

    depmod -a
    ok "gen4-mt7902 fully removed"
}

# ── fallback wifi driver (hmtheboy154/mt7902) ─────────────────
install_wifi_fallback() {
    echo ""
    echo -e "  ${YELLOW}━━━ Switching to alternative driver (hmtheboy154/mt7902) ━━━${NC}"
    echo ""

    # Only clean up gen4 if it is actually on the system. This path now also
    # runs as the *first* choice, where there is nothing to remove and the
    # cleanup output would be misleading.
    if [ "$GEN4_STAGED" = true ] || dkms status gen4-mt7902 2>/dev/null | grep -q gen4-mt7902 ||
       [ -e "/lib/modules/${KVER}/updates/dkms/mt7902.ko" ] ||
       [ -e "/lib/modules/${KVER}/updates/dkms/mt7902.ko.zst" ]; then
        cleanup_gen4
    fi

    step "Cloning hmtheboy154/mt7902"
    # git refuses to run if the current directory has been removed underneath us
    cd "$SCRIPT_DIR" 2>/dev/null || cd /tmp
    rm -rf "$FALLBACK_DIR"
    if ! git clone --depth 1 "$FALLBACK_REPO" "$FALLBACK_DIR" 2>&1; then
        fail "Could not clone ${FALLBACK_REPO}"
        fail "Check your internet connection and try again."
        return 1
    fi
    ok "Repository cloned to ${FALLBACK_DIR}"

    step "Building alternative WiFi driver"
    cd "$FALLBACK_DIR"
    make -j$(nproc)
    sudo make install -j$(nproc)
    ok "Alternative driver built and installed"

    step "Installing firmware (hmtheboy154/mt7902)"
    make install_fw 2>/dev/null || warn "Firmware install step skipped (may already be present)"
    ok "Firmware installed"

    cd "$SCRIPT_DIR"

    step "Loading alternative WiFi module"
    depmod -a
    rmmod mt7902e 2>/dev/null || true
    rmmod mt7921e 2>/dev/null || true
    rmmod mt7921_common 2>/dev/null || true
    rmmod mt76_connac_lib 2>/dev/null || true
    if ! try_modprobe mt7902e; then
        fail "Could not load alternative driver either."
        WIFI_DRIVER_USED="none (both drivers failed)"
        return 1
    fi
    ok "Alternative driver loaded (mt7902e by hmtheboy154)"

    WIFI_DRIVER_USED="hmtheboy154/mt7902"
}

# ── wifi ──────────────────────────────────────────────────────
install_wifi() {
    local src="${SCRIPT_DIR}/gen4-mt7902"

    # detect firmware path (Arch uses /usr/lib/firmware, others use /lib/firmware)
    local FW_DIR="/lib/firmware"
    [ -d "/usr/lib/firmware" ] && ! [ -L "/lib" ] && FW_DIR="/usr/lib/firmware"

    # ── prefer the in-tree driver when the kernel has 7902 support ──
    if [ "$FORCE_CUSTOM" = false ] && [ "$USE_FALLBACK" = false ] && intree_supports_mt7902; then
        use_intree_driver && return 0
    fi

    # ── if --fallback flag used, skip gen4 entirely ────────────
    if [ "$USE_FALLBACK" = true ]; then
        step "Skipping gen4 driver (--fallback flag set)"
        install_wifi_fallback || return 1
        return 0
    fi

    # ── on kernels without in-tree support, try the mt76-based driver first ──
    # gen4-mt7902 is a vendor tree that repeatedly fails MCU init on this
    # hardware ("wlanAccessRegister: Event reports address incorrect",
    # "Fail reason: 4"), which is what the mcu_bypass/disable_rpm options in
    # this repo exist to work around. hmtheboy154/mt7902 is built on mt76 —
    # the same lineage upstream ended up merging — so it is the better first
    # choice. gen4 is still attempted if it fails. Use --gen4 to invert this.
    if [ "$PREFER_GEN4" = false ]; then
        if backport_supports_kernel; then
            step "Trying the mt76-based driver first (gen4 is the fallback)"
            if install_wifi_fallback; then
                return 0
            fi
            warn "mt76-based driver did not work; trying gen4-mt7902"
        else
            warn_unsupported_kernel
            warn "Skipping the mt76 backport (needs kernel 6.6 or newer)"
        fi
    fi

    [ -d "$src" ] || { fail "WiFi source not found: $src"; return 1; }

    step "Building WiFi driver (gen4-mt7902)"

    if [ "$USE_DKMS" = true ]; then
        dkms status gen4-mt7902 2>/dev/null | grep -q "gen4-mt7902" && \
            dkms remove gen4-mt7902/0.1 --all 2>/dev/null || true

        mkdir -p /usr/src/gen4-mt7902-0.1
        cp -r "$src"/* /usr/src/gen4-mt7902-0.1/
        dkms add -m gen4-mt7902 -v 0.1 > /dev/null 2>&1
        dkms build -m gen4-mt7902 -v 0.1
        dkms install -m gen4-mt7902 -v 0.1
        ok "DKMS module registered (auto-rebuild on kernel updates)"
    else
        # `make -j$(nproc)` under `set -e` still lets the script continue when
        # make itself is missing, so this used to report a successful build on
        # a machine with no toolchain at all.
        if ! command -v make >/dev/null 2>&1; then
            fail "make is not installed — cannot build the driver"
            fail "Install your distribution's kernel build tools and try again."
            return 1
        fi
        if [ ! -d "/lib/modules/${KVER}/build" ]; then
            fail "No kernel headers at /lib/modules/${KVER}/build — cannot build"
            return 1
        fi
        cd "$src"
        if ! make -j"$(nproc)"; then
            cd "$SCRIPT_DIR"
            fail "Driver build failed"
            return 1
        fi
        if ! make install -j"$(nproc)"; then
            cd "$SCRIPT_DIR"
            fail "Driver install failed"
            return 1
        fi
        cd "$SCRIPT_DIR"
        ok "Module built and installed manually"
    fi

    step "Installing WiFi firmware"
    mkdir -p "${FW_DIR}/mediatek/mt7902"
    local fw_failed=0
    if [ -d "$src/firmware" ]; then
        for f in "$src/firmware/"*; do
            [ -f "$f" ] || continue
            install_firmware "$f" "${FW_DIR}/mediatek/" || fw_failed=1
        done
    fi

    local fw="${SCRIPT_DIR}/mt7902_temp/mt7902_firmware"
    if [ -d "$fw" ]; then
        for f in "$fw"/WIFI_*.bin.zst "$fw"/WIFI_*.bin; do
            [ -f "$f" ] || continue
            install_firmware "$f" "${FW_DIR}/mediatek/" || fw_failed=1
        done
        for f in "$fw"/mt7902_*.bin.zst "$fw"/mt7902_*.bin; do
            [ -f "$f" ] || continue
            install_firmware "$f" "${FW_DIR}/mediatek/mt7902/" || fw_failed=1
        done
    fi
    verify_firmware "${FW_DIR}/mediatek" || return 1
    if [ "$fw_failed" -ne 0 ]; then
        fail "Some firmware files could not be installed — the driver would fail"
        fail "to initialise the card. Re-clone this repository and try again."
        return 1
    fi
    ok "Firmware installed to ${FW_DIR}/mediatek/"

    # Prevent udev from auto-loading mt7902 at boot. The module is loaded
    # explicitly by mt7902-late.service *after* userspace is up, so a driver
    # that hangs in probe can never hang the boot itself. Written before the
    # first modprobe on purpose: if the machine freezes during that modprobe,
    # the next boot is still clean.
    step "Disabling boot-time auto-load of mt7902 (boot safety)"
    mkdir -p /etc/modprobe.d
    cat > /etc/modprobe.d/mt7902-noautoload.conf <<'EOF'
# mt7902 is loaded late by mt7902-late.service, never automatically at boot.
# This keeps a hanging driver from freezing the boot. Do not remove unless
# you also remove the module.
blacklist mt7902
EOF
    GEN4_STAGED=true
    rebuild_initramfs
    ok "Auto-load disabled (/etc/modprobe.d/mt7902-noautoload.conf)"

    print_recovery_notice

    step "Loading WiFi module"
    depmod -a
    # unload any conflicting stock drivers first
    rmmod mt7921e 2>/dev/null || true
    rmmod mt7902e 2>/dev/null || true
    rmmod mt7921_common 2>/dev/null || true
    rmmod mt76_connac_lib 2>/dev/null || true
    rmmod mt7902 2>/dev/null || true

    # ── try loading gen4 driver + health check ────────────────
    local gen4_ok=false
    if try_modprobe mt7902; then
        step "Verifying gen4 driver health"
        if check_wifi_health; then
            ok "gen4-mt7902 loaded and WiFi interface is up"
            gen4_ok=true
            WIFI_DRIVER_USED="gen4-mt7902 (abdullaabdullazade)"
        else
            warn "gen4-mt7902 loaded but health check failed"
        fi
    else
        warn "gen4-mt7902 failed to load"
    fi

    # ── try MCU bypass if standard load had issues ────────────
    if [ "$gen4_ok" = false ]; then
        warn "Attempting MCU Bypass (Force Load)..."
        rmmod mt7902 2>/dev/null || true
        if try_modprobe mt7902 mcu_bypass=1; then
            sleep 2
            if check_wifi_health; then
                warn "Module loaded with MCU Bypass — works but may be unstable."
                echo "options mt7902 mcu_bypass=1" > /etc/modprobe.d/mt7902.conf
                ok "Persisted MCU bypass options to /etc/modprobe.d/mt7902.conf"
                gen4_ok=true
                WIFI_DRIVER_USED="gen4-mt7902 (abdullaabdullazade) [mcu_bypass]"
            else
                warn "MCU bypass also failed health check"
            fi
        else
            warn "MCU bypass load failed"
        fi
    fi

    # ── fallback to hmtheboy154/mt7902 ────────────────────────
    if [ "$gen4_ok" = false ]; then
        echo ""
        warn "gen4-mt7902 driver is not working on this system."
        echo -e "      ${YELLOW}Automatically falling back to hmtheboy154/mt7902...${NC}"
        install_wifi_fallback || return 1
        return 0
    fi

    # driver is proven working — only now is it safe to take the stock
    # drivers out of the picture
    blacklist_stock_drivers

    # install late-load systemd service (fixes boot race condition)
    if [ -f "${SCRIPT_DIR}/mt7902-late.service" ] && command -v systemctl &>/dev/null; then
        step "Installing late-load systemd service"
        cp "${SCRIPT_DIR}/mt7902-late.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable mt7902-late.service 2>/dev/null
        ok "mt7902-late.service enabled (auto-loads WiFi after boot)"
    fi
}

# ── bluetooth ─────────────────────────────────────────────────
install_bt() {
    local base="${SCRIPT_DIR}/mt7902_temp"
    local tag="linux-${KMAJOR}.${KMINOR}"
    local bt_dir=""

    # detect firmware path
    local FW_DIR="/lib/firmware"
    [ -d "/usr/lib/firmware" ] && ! [ -L "/lib" ] && FW_DIR="/usr/lib/firmware"

    step "Locating Bluetooth source for kernel ${KVER}"

    if [ -d "${base}/${tag}/drivers/bluetooth" ]; then
        bt_dir="${base}/${tag}/drivers/bluetooth"
        ok "Exact match: ${tag}"
    else
        warn "No exact match for ${tag}, selecting closest..."
        local best=""
        for d in "${base}"/linux-*/drivers/bluetooth; do
            [ -d "$d" ] || continue
            local v=$(echo "$d" | grep -oP 'linux-\K[0-9]+\.[0-9]+')
            local maj=$(echo "$v" | cut -d. -f1)
            local min=$(echo "$v" | cut -d. -f2)
            if [ "$maj" -lt "$KMAJOR" ] || { [ "$maj" -eq "$KMAJOR" ] && [ "$min" -le "$KMINOR" ]; }; then
                best="$d"
            fi
        done
        if [ -z "$best" ]; then
            # every bundled source is newer than the running kernel — build the
            # oldest one and rely on the compat shims below
            best=$(ls -d "${base}"/linux-*/drivers/bluetooth 2>/dev/null | sort -V | head -1)
            [ -n "$best" ] && warn "Kernel ${KMAJOR}.${KMINOR} is older than every bundled source; using oldest with compat shims"
        fi
        [ -z "$best" ] && { fail "No bluetooth source found"; return 1; }
        bt_dir="$best"
        ok "Using $(basename $(dirname $(dirname $bt_dir)))"
    fi

    # ── compat shims for kernels older than the bundled source ────
    # <linux/unaligned.h> is the 6.12+ name; before that the same helpers
    # live in <asm/unaligned.h>. Provide a shim header on the include path
    # so the newer bluetooth source still compiles on older kernels.
    local compat_inc=""
    if [ "$KMAJOR" -lt 6 ] || { [ "$KMAJOR" -eq 6 ] && [ "$KMINOR" -lt 12 ]; }; then
        compat_inc="$(mktemp -d /tmp/mt7902-compat-XXXXXX)"
        mkdir -p "${compat_inc}/linux"
        cat > "${compat_inc}/linux/unaligned.h" <<'EOF'
/* Compat shim: <linux/unaligned.h> only exists on 6.12+ */
#ifndef _MT7902_COMPAT_LINUX_UNALIGNED_H
#define _MT7902_COMPAT_LINUX_UNALIGNED_H
#include <asm/unaligned.h>
#endif
EOF
        ok "Compat shim enabled (linux/unaligned.h for kernel < 6.12)"
    fi

    step "Building btusb + btmtk modules"
    cd "$bt_dir"
    make -C /lib/modules/$(uname -r)/build/ M=$(pwd) \
        ${compat_inc:+EXTRA_CFLAGS="-I${compat_inc}"} modules

    # Install firmware before loading the modules — btmtk needs it present
    # at modprobe time, not after. Doing this after modprobe (as before)
    # meant a fresh install always failed firmware setup on first load.
    step "Installing Bluetooth firmware"
    local fw="${SCRIPT_DIR}/mt7902_temp/mt7902_firmware"
    if [ -d "$fw" ]; then
        mkdir -p "${FW_DIR}/mediatek"
        for f in "$fw"/BT_*.bin.zst "$fw"/BT_*.bin; do
            [ -f "$f" ] && cp "$f" "${FW_DIR}/mediatek/"
        done
    fi
    ok "BT firmware copied"

    # Sign modules if Secure Boot is enabled, using whatever MOK key is
    # already enrolled (e.g. the one DKMS generates for other out-of-tree
    # drivers). Without this, modprobe fails with "Key was rejected by
    # service" and gives no hint about why.
    if command -v mokutil &>/dev/null && mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
        step "Signing modules for Secure Boot"
        local sign_file=""
        for candidate in \
            "/usr/src/linux-headers-$(uname -r)/scripts/sign-file" \
            "/lib/modules/$(uname -r)/build/scripts/sign-file"; do
            [ -x "$candidate" ] && { sign_file="$candidate"; break; }
        done

        local mok_key="" mok_cert=""
        if [ -f "/var/lib/shim-signed/mok/MOK.priv" ] && [ -f "/var/lib/shim-signed/mok/MOK.der" ]; then
            mok_key="/var/lib/shim-signed/mok/MOK.priv"
            mok_cert="/var/lib/shim-signed/mok/MOK.der"
        elif [ -f "/var/lib/dkms/mok.key" ] && [ -f "/var/lib/dkms/mok.pub" ]; then
            mok_key="/var/lib/dkms/mok.key"
            mok_cert="/var/lib/dkms/mok.pub"
        fi

        if [ -n "$sign_file" ] && [ -n "$mok_key" ]; then
            "$sign_file" sha256 "$mok_key" "$mok_cert" btusb.ko
            "$sign_file" sha256 "$mok_key" "$mok_cert" btmtk.ko
            ok "Modules signed with enrolled MOK key (${mok_key})"
        else
            warn "Secure Boot is enabled but no enrolled MOK key was found."
            warn "modprobe will likely fail with 'Key was rejected by service'."
            warn "Either disable Secure Boot, or enroll a MOK key (installing any"
            warn "DKMS driver will generate+enroll one) and re-run with --bt."
        fi
    fi

    if command -v zstd &>/dev/null; then
        zstd -f btusb.ko -o btusb.ko.zst 2>/dev/null
        zstd -f btmtk.ko -o btmtk.ko.zst 2>/dev/null
    fi

    local mod="/lib/modules/$(uname -r)/kernel/drivers/bluetooth"

    # backup originals
    [ -f "${mod}/btusb.ko.zst" ] && cp "${mod}/btusb.ko.zst" "${mod}/btusb.ko.zst.bak" 2>/dev/null || true
    [ -f "${mod}/btmtk.ko.zst" ] && cp "${mod}/btmtk.ko.zst" "${mod}/btmtk.ko.zst.bak" 2>/dev/null || true

    step "Installing Bluetooth modules"
    if [ -f btusb.ko.zst ] && [ -f btmtk.ko.zst ]; then
        install -m 644 btusb.ko.zst btmtk.ko.zst "$mod/"
    else
        install -m 644 btusb.ko btmtk.ko "$mod/"
    fi

    rmmod btusb 2>/dev/null || true
    rmmod btmtk 2>/dev/null || true
    depmod -a
    if ! modprobe btmtk; then
        fail "Failed to load btmtk (see Secure Boot warning above if shown)"
        exit 1
    fi
    if ! modprobe btusb; then
        fail "Failed to load btusb (see Secure Boot warning above if shown)"
        exit 1
    fi
    ok "Modules loaded"

    cd "$SCRIPT_DIR"
}

# ── main ──────────────────────────────────────────────────────
detect_distro
show_banner
show_info_box

if [ "$DO_KERNEL_UPGRADE" = true ]; then
    upgrade_kernel || true
    exit 0
fi

if [ "$DO_WIFI" = true ] && [ "$SKIP_CARD_CHECK" = false ] && ! mt7902_present; then
    echo -e "  ${YELLOW}No MT7902 (14c3:7902) found on the PCI bus.${NC}"
    echo ""
    echo -e "  ${DIM}Nothing here applies to this machine. If the card is fitted but${NC}"
    echo -e "  ${DIM}not showing up, check that it is seated and enabled in firmware:${NC}"
    echo -e "    ${DIM}lspci -nn | grep -i 14c3${NC}"
    echo ""
    echo -e "  ${DIM}To install anyway (building for another machine, testing):${NC}"
    echo -e "    ${DIM}sudo ./install.sh --wifi --no-card-check${NC}"
    echo ""
    exit 0
fi

# On a kernel that already supports the card there is nothing to compile, so
# do not drag the user through a package install first — on mainline or vendor
# kernels the headers package often does not exist and that used to abort the
# whole run at step 1.
if [ "$DO_WIFI" = true ] && [ "$DO_BT" = false ] && \
   [ "$FORCE_CUSTOM" = false ] && [ "$USE_FALLBACK" = false ] && \
   intree_supports_mt7902; then
    echo ""
    echo -e "  ${WHITE}── WiFi ──────────────────────────────────${NC}"
    if use_intree_driver; then
        echo ""
        echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
        echo -e "  ${GREEN}${BOLD}Nothing to install.${NC}"
        echo -e "  ${WHITE}WiFi driver:${NC} ${CYAN}${WIFI_DRIVER_USED}${NC}"
        echo ""
        exit 0
    fi
fi

if [ "$DO_WIFI" = true ]; then
    announce_kernel_situation
fi

install_deps

WIFI_FAILED=false
if [ "$DO_WIFI" = true ]; then
    echo ""
    echo -e "  ${WHITE}── WiFi ──────────────────────────────────${NC}"
    # A WiFi failure must not skip the Bluetooth install the user also asked for
    install_wifi || WIFI_FAILED=true
fi

if [ "$DO_BT" = true ]; then
    echo ""
    echo -e "  ${WHITE}── Bluetooth ─────────────────────────────${NC}"
    install_bt
fi

echo ""
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""
if [ "$WIFI_FAILED" = true ]; then
    echo -e "  ${YELLOW}${BOLD}Installation finished with errors.${NC}"
    echo -e "  ${YELLOW}WiFi could not be installed — no driver loaded.${NC}"
    echo -e "  ${DIM}Stock drivers were left untouched, so your system is unchanged.${NC}"
else
    echo -e "  ${GREEN}${BOLD}Installation complete.${NC}"
fi
echo ""
if [ "$DO_WIFI" = true ] && [ "$DO_BT" = true ]; then
    echo -e "  ${DIM}Installed: WiFi + Bluetooth${NC}"
elif [ "$DO_WIFI" = true ]; then
    echo -e "  ${DIM}Installed: WiFi${NC}"
else
    echo -e "  ${DIM}Installed: Bluetooth${NC}"
fi
if [ -n "$WIFI_DRIVER_USED" ]; then
    echo -e "  ${WHITE}WiFi driver:${NC} ${CYAN}${WIFI_DRIVER_USED}${NC}"
fi
echo -e "  ${DIM}Reboot for changes to take effect.${NC}"
if [[ "$WIFI_DRIVER_USED" == *"gen4"* ]]; then
    echo -e "  ${DIM}WiFi flaky? → sudo rmmod mt7902 && sudo modprobe mt7902${NC}"
    echo -e "  ${DIM}Stability issues? Try these options:${NC}"
    echo -e "    ${DIM}1. Disable Runtime PM: sudo modprobe mt7902 disable_rpm=1${NC}"
    echo -e "    ${DIM}2. Increase Timeout:   sudo modprobe mt7902 cmd_timeout_ms=8000${NC}"
    echo -e "    ${DIM}3. Force Load (Dead Card): sudo modprobe mt7902 mcu_bypass=1${NC}"
    echo ""
    echo -e "  ${YELLOW}Still having problems?${NC} ${DIM}Re-run with the fallback driver:${NC}"
    echo -e "    ${DIM}sudo ./install.sh --fallback${NC}"
elif [[ "$WIFI_DRIVER_USED" == *"hmtheboy154"* ]]; then
    echo -e "  ${DIM}Using alternative driver by hmtheboy154.${NC}"
    echo -e "  ${DIM}Source: https://github.com/hmtheboy154/mt7902${NC}"
fi

# Anything other than the in-tree driver means the kernel is older than 7.1;
# the full explanation was printed before the install started.
if [ "$DO_WIFI" = true ] && [ -n "$WIFI_DRIVER_USED" ] && \
   [[ "$WIFI_DRIVER_USED" != *"in-tree"* ]]; then
    echo -e "  ${DIM}Reminder: kernel 7.1+ supports this card without any of this.${NC}"
fi
echo ""
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""
if [ "$WIFI_FAILED" = true ]; then
    echo -e "  ${DIM}Not rebooting automatically — read the errors above first.${NC}"
    exit 1
fi

echo -e "  ${YELLOW}Rebooting in 10 seconds... (Ctrl+C to cancel)${NC}"
for i in 10 9 8 7 6 5 4 3 2 1; do
    echo -ne "\r  ${BOLD}${i}...${NC}  "
    sleep 1
done
echo ""
reboot
