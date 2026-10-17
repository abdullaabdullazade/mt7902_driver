#!/bin/bash
#
# MT7902 Driver Installer
# Builds and installs WiFi + Bluetooth drivers and firmware for the
# MediaTek MT7902 PCIe wireless card.
#
# Usage: sudo ./install.sh [--all|--wifi|--bt] [--no-dkms] [--help]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"
KVER=$(uname -r)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)

DO_WIFI=false
DO_BT=false
USE_DKMS=true
FORCE_CUSTOM=false
# Which WiFi driver to try first: mt7902e (default), mt76 or gen4
PREFER_DRIVER="mt7902e"
DO_KERNEL_UPGRADE=false
SKIP_CARD_CHECK=false
NO_REBOOT=false
CLEAN_FIRMWARE=false
REPO_URL="https://github.com/abdullaabdullazade/mt7902_driver"
WIFI_DRIVER_USED=""
LAST_MODPROBE_ERR=""

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
    --no-dkms     Build the drivers manually instead of using DKMS
                  (they then stop working after the next kernel update)
    --mt7902e     Use the mt7902e driver first. This is the default.
    --fallback    Same as --mt7902e (kept for older instructions)
    --mt76        Try the mt76 driver first: mainline mt76 at kernel 7.3 level,
                  with every MT7902 fix merged since 7.1 (kernel 6.12 - 7.0).
                  Replaces all in-kernel mt76 drivers with its own copies.
    --gen4        Try the bundled gen4-mt7902 vendor driver first
    --force-custom Build a custom driver even if the kernel already
                  supports 14c3:7902 in the in-tree mt7921e driver
    --clean-firmware
                  Remove stale MT7902 firmware copies left by older versions
                  of this installer that hide the newer firmware your
                  distribution ships (only files no package owns)
    --no-reboot   Do not reboot at the end
    --upgrade-kernel
                  Offer to move to a kernel that supports this card in-tree
                  (7.1+). Fedora installs its own signed kernel alongside the
                  current one; Debian/Ubuntu get a mainline build, which is
                  refused under Secure Boot. Asks first, never reboots.
    --no-card-check
                  Install even when no MT7902 is present on the PCI bus
    -h, --help    Show this message

  Examples:
    sudo $0               # install everything (auto-selects best driver)
    sudo $0 --wifi        # wifi driver + firmware only
    sudo $0 --bt          # bluetooth driver + firmware only
    sudo $0 --mt76        # prefer the newer mt76 driver
EOF
    exit 0
}

# parse args — default is --all

for arg in "$@"; do
    case $arg in
        --all)      DO_WIFI=true; DO_BT=true ;;
        --wifi)     DO_WIFI=true ;;
        --bt)       DO_BT=true ;;
        --no-dkms)  USE_DKMS=false ;;
        --fallback|--mt7902e) PREFER_DRIVER="mt7902e" ;;
        --mt76)     PREFER_DRIVER="mt76" ;;
        --gen4)     PREFER_DRIVER="gen4" ;;
        --force-custom) FORCE_CUSTOM=true ;;
        --clean-firmware) CLEAN_FIRMWARE=true ;;
        --no-reboot) NO_REBOOT=true ;;
        --upgrade-kernel) DO_KERNEL_UPGRADE=true ;;
        --no-card-check) SKIP_CARD_CHECK=true ;;
        -h|--help)  usage ;;
        *)          echo "Unknown option: $arg"; usage ;;
    esac
done
# Options that only change *how* (--mt76, --no-dkms, --no-reboot, ...) must
# not change *what*: with neither --wifi nor --bt, install both. This used to
# key off "no arguments at all", so e.g. `install.sh --fallback` installed
# nothing and still printed "Installation complete".
if [ "$DO_WIFI" = false ] && [ "$DO_BT" = false ]; then
    DO_WIFI=true; DO_BT=true
fi

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ Run this script with sudo${NC}"
    exit 1
fi

# ── distro detection ──────────────────────────────────────────
# Derivatives (CachyOS, Nobara, Kali, KDE neon, ...) are matched through
# ID_LIKE, so they get their parent's package commands instead of "unknown".
DISTRO="unknown"
detect_distro() {
    [ -f /etc/os-release ] || return 0
    local ID="" ID_LIKE="" id
    . /etc/os-release
    for id in $ID $ID_LIKE; do
        case "$id" in
            ubuntu|debian|linuxmint|pop|elementary|zorin|kali|neon|raspbian)
                DISTRO="debian"; return 0 ;;
            fedora|rhel|centos|rocky|almalinux|alma|nobara|ultramarine)
                DISTRO="fedora"; return 0 ;;
            arch|manjaro|endeavouros|garuda|cachyos|artix)
                DISTRO="arch"; return 0 ;;
            opensuse*|suse|sles)
                DISTRO="suse"; return 0 ;;
        esac
    done
}

kernel_built_with_clang() {
    grep -qs '^CONFIG_CC_IS_CLANG=y' "/lib/modules/${KVER}/build/.config"
}

# The headers have to match the running kernel exactly. A bare "kernel-devel"
# or "linux-headers" installs the headers for the newest kernel in the
# repositories, which is not the one running until the next reboot, and the
# build then fails with "no kernel headers".
headers_package() {
    case "$DISTRO" in
        debian) echo "linux-headers-${KVER}" ;;
        fedora) echo "kernel-devel-${KVER}" ;;
        arch)   # linux, linux-lts, linux-zen, linux-cachyos, ... each have their own
                local base=""
                [ -r "/usr/lib/modules/${KVER}/pkgbase" ] && read -r base < "/usr/lib/modules/${KVER}/pkgbase"
                echo "${base:-linux}-headers" ;;
        suse)   local flavor="${KVER##*-}"
                echo "kernel-${flavor:-default}-devel" ;;
    esac
}

install_deps() {
    step "Installing build dependencies"
    local rc=0 hdr extra=""
    hdr=$(headers_package)
    # Clang-built kernels need their modules built with clang as well
    kernel_built_with_clang && extra="clang lld llvm"
    case "$DISTRO" in
        debian) apt-get update -qq >/dev/null 2>&1
                apt-get install -y build-essential "$hdr" dkms zstd git iw $extra > /dev/null 2>&1 || rc=$? ;;
        fedora) dnf install -y make gcc "$hdr" dkms zstd git iw $extra > /dev/null 2>&1 || rc=$? ;;
        arch)   pacman -S --needed --noconfirm base-devel "$hdr" dkms zstd git iw $extra > /dev/null 2>&1 || rc=$? ;;
        suse)   zypper --non-interactive install make gcc "$hdr" dkms zstd git iw $extra > /dev/null 2>&1 || rc=$? ;;
        *)      warn "Unknown distro — install manually: compiler, make, kernel headers for ${KVER}, dkms, zstd, git, iw"
                [ -d "/lib/modules/${KVER}/build" ] || warn "No kernel headers found at /lib/modules/${KVER}/build"
                return 0 ;;
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
            warn "Install ${hdr} (or your kernel's headers) and run this again"
        fi
        return 0
    fi
    ok "Dependencies ready (${DISTRO}, headers: ${hdr})"
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
            # Fedora installs kernels side by side, so pulling in just the one
            # is a few hundred megabytes instead of a full system upgrade, and
            # leaves the running kernel in place to fall back to. Note that
            # `dnf install kernel` is a no-op when any kernel is installed —
            # the version has to be explicit.
            if [ "$DISTRO" = "fedora" ]; then
                cmd="dnf install -y kernel-${avail} kernel-core-${avail} kernel-modules-${avail} kernel-modules-core-${avail}"
            fi
            # Arch and openSUSE Tumbleweed do not support partial upgrades, so
            # they keep the full-system command.
        fi
    else
        warn "Could not determine which kernel your distribution offers"
    fi

    echo ""
    if [ "$DISTRO" = "fedora" ] && [ "${cmd#dnf install}" != "$cmd" ]; then
        echo -e "  ${YELLOW}This installs the new kernel alongside your current one:${NC}"
    else
        echo -e "  ${YELLOW}This runs a full system upgrade:${NC}"
    fi
    echo -e "  ${CYAN}${cmd}${NC}"
    echo -e "  ${DIM}Nothing is rebooted for you; the running kernel stays in GRUB.${NC}"
    echo ""
    printf "  Type %byes%b to run it: " "${BOLD}" "${NC}"
    local answer=""
    read -r answer < /dev/tty || true
    [ "$answer" = "yes" ] || { warn "Cancelled"; return 1; }

    step "Installing the kernel — this downloads a lot and takes a while"
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

    # Everything except Debian/Ubuntu has a supported kernel in its own
    # repositories, which beats an unsigned mainline build every time.
    if [ "$DISTRO" != "debian" ]; then
        run_distro_upgrade
        return $?
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

# Kernel 7.1 carries MT7902 Bluetooth upstream alongside the WiFi support, so
# its btusb/btmtk already cover this chip and must not be replaced with the
# older sources bundled here. Below 7.1 the backport is still needed — 7.0 in
# particular has neither in-tree support nor a reason to skip the build.
bt_intree_supported() {
    [ "$KMAJOR" -gt 7 ] || { [ "$KMAJOR" -eq 7 ] && [ "$KMINOR" -ge 1 ]; }
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

    # linux-firmware has shipped MT7902 firmware since its 20260309 release,
    # usually compressed (.zst on Ubuntu/Arch, .xz on Fedora). Any variant
    # already present satisfies the driver, and that copy is authoritative:
    # an uncompressed copy from here would be loaded first and hide it.
    if fw_any_variant "${dstdir}/${base}"; then
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
    record_installed "${dstdir}/${base}"
}

# WiFi + BT firmware for the mt76-based drivers, identical to linux-firmware's.
install_mt7902_firmware() {
    local kind="$1" f failed=0
    for f in "${SCRIPT_DIR}/firmware/"${kind}_*MT7902*.bin; do
        [ -f "$f" ] || continue
        install_firmware "$f" "${FW_DIR}/mediatek" || failed=1
    done
    verify_firmware "${FW_DIR}/mediatek" || return 1
    [ "$failed" -eq 0 ]
}

# Catch stubs left behind by earlier runs (or by anything else) before a
# driver trips over them.
verify_firmware() {
    local dir="$1" empty
    empty=$(find "$dir" -maxdepth 2 \( -name 'mt7902*' -o -name '*MT7902*' \) 2>/dev/null | while read -r f; do
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

# Older versions of this installer copied uncompressed firmware even when the
# distribution already shipped it. The kernel loads the uncompressed file
# first, so those copies hide every later linux-firmware update — on one test
# machine Bluetooth was running a 2022 build while the package had a 2025 one.
# Point them out every run; remove them only when asked, because the machine
# may be working fine as it is.
check_shadowing_firmware() {
    local stale f
    stale=$(find_shadowing_firmware)
    [ -n "$stale" ] || return 0
    step "Checking for stale firmware copies"
    if [ "$CLEAN_FIRMWARE" = true ]; then
        echo "$stale" | while read -r f; do
            rm -f "$f" && ok "Removed ${f}"
        done
        ok "Your distribution's firmware is used from now on (takes effect after reboot)"
        return 0
    fi
    warn "These files are not from any package and hide newer firmware your"
    warn "distribution ships for the same chip:"
    echo "$stale" | while read -r f; do echo -e "        ${DIM}${f}${NC}"; done
    warn "To use the distribution's firmware instead, run:"
    echo -e "        ${CYAN}sudo ./install.sh --clean-firmware${NC} ${DIM}(add the options you normally use)${NC}"
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
# The error text is kept for explain_load_failure.
try_modprobe() {
    local rc
    LAST_MODPROBE_ERR=$(timeout 60 modprobe "$@" 2>&1 >/dev/null)
    rc=$?
    if [ "$rc" -eq 124 ]; then
        warn "modprobe $* timed out after 60s (driver hung in probe)"
        return 1
    fi
    return $rc
}

# The usual reason a freshly built module will not load is Secure Boot:
# DKMS signs it, but with a key the firmware does not trust yet.
explain_load_failure() {
    [ -n "$LAST_MODPROBE_ERR" ] && echo -e "        ${DIM}${LAST_MODPROBE_ERR}${NC}"
    if echo "$LAST_MODPROBE_ERR" | grep -qiE 'key was rejected|required key not available'; then
        local cert=""
        for cert in /var/lib/shim-signed/mok/MOK.der /var/lib/dkms/mok.pub; do
            [ -f "$cert" ] && break
            cert=""
        done
        warn "Secure Boot is on: the module is signed with a key your firmware"
        warn "does not trust yet. Enroll it once, then reboot and choose"
        warn "\"Enroll MOK\" in the blue screen that appears:"
        echo -e "        ${CYAN}sudo mokutil --import ${cert:-/var/lib/dkms/mok.pub}${NC}"
    fi
}

# After a driver is loaded: is the card bound to it and is there a wireless
# interface? Firmware download takes a few seconds, so poll rather than sleep.
wifi_up() {
    local want="$1" i
    for i in $(seq 1 20); do
        if [ "$(mt7902_bound_driver)" = "$want" ] && wireless_iface_present; then
            return 0
        fi
        sleep 1
    done
    # When the card is absent (--no-card-check) there is nothing to bind to
    mt7902_pci_dev >/dev/null || lsmod | grep -q "^${want} "
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

# ── DKMS helpers ──────────────────────────────────────────────
show_build_log() {
    local name="$1" ver="$2" log="$3" f
    for f in "/var/lib/dkms/${name}/${ver}/build/make.log" \
             "/var/lib/dkms/${name}/${ver}/${KVER}/$(uname -m)/log/make.log" "$log"; do
        if [ -s "$f" ]; then
            echo -e "        ${DIM}── last lines of ${f} ──${NC}"
            grep -E 'error|Error|undefined' "$f" | tail -8 | while IFS= read -r l; do echo -e "        ${DIM}${l}${NC}"; done
            break
        fi
    done
    [ -s "$log" ] && cp -f "$log" "${STATE_DIR}/" 2>/dev/null
    echo -e "        ${DIM}Full log: ${STATE_DIR}/$(basename "$log")${NC}"
}

# Copy a source tree to /usr/src/<name>-<ver> and add, build and install it
# for the running kernel. Under `set -e` a failing command inside a function
# called from `if`/`||` does NOT stop the function, so every step is checked
# explicitly — earlier versions reported "registered" after a failed build.
dkms_install_pkg() {
    local name="$1" ver="$2" src="$3"
    local log="${STATE_DIR}/${name}-build.log"
    mkdir -p "$STATE_DIR"
    dkms remove -m "$name" -v "$ver" --all >/dev/null 2>&1 || true
    rm -rf "/usr/src/${name}-${ver}"
    mkdir -p "/usr/src/${name}-${ver}"
    cp -r "$src"/. "/usr/src/${name}-${ver}/"
    : > "$log"
    if ! dkms add -m "$name" -v "$ver" >>"$log" 2>&1 ||
       ! dkms build -m "$name" -v "$ver" -k "$KVER" >>"$log" 2>&1 ||
       ! dkms install -m "$name" -v "$ver" -k "$KVER" --force >>"$log" 2>&1; then
        fail "Building ${name} for ${KVER} failed"
        show_build_log "$name" "$ver" "$log"
        dkms remove -m "$name" -v "$ver" --all >/dev/null 2>&1 || true
        rm -rf "/usr/src/${name}-${ver}"
        return 1
    fi
    ok "${name} built and registered with DKMS (rebuilt automatically on kernel updates)"
}

# Without DKMS: build in place and drop the modules under updates/, which
# depmod prefers over the kernel's own tree. Nothing of the kernel's is touched.
manual_install_pkg() {
    local name="$1" src="$2"; shift 2
    local log="${STATE_DIR}/${name}-build.log" llvm="" m dst="/lib/modules/${KVER}/updates/${name}"
    mkdir -p "$STATE_DIR"
    command -v make >/dev/null 2>&1 || { fail "make is not installed — cannot build ${name}"; return 1; }
    [ -d "/lib/modules/${KVER}/build" ] || { fail "No kernel headers at /lib/modules/${KVER}/build"; return 1; }
    kernel_built_with_clang && llvm="LLVM=1"
    if ! make -C "$src" KVER="$KVER" $llvm > "$log" 2>&1; then
        fail "Building ${name} failed"
        show_build_log "$name" none "$log"
        return 1
    fi
    mkdir -p "$dst"
    for m in "$@"; do
        install -m 644 "${src}/${m}.ko" "${dst}/${m}.ko" || return 1
        record_installed "${dst}/${m}.ko"
    done
    depmod -a "$KVER"
    ok "${name} built and installed to ${dst} (rebuild it after a kernel update)"
    warn "Without DKMS this driver stops working after the next kernel update"
}

# Kernel log lines printed since a mark, to judge a driver by what it said
# rather than only by whether modprobe returned 0 (issue #2: mt7902e loads,
# then every MCU message times out and scanning never works).
dmesg_mark() { dmesg 2>/dev/null | wc -l; }
dmesg_since() { dmesg 2>/dev/null | tail -n +"$(( $1 + 1 ))"; }

wifi_errors_since() {
    dmesg_since "$1" | grep -iE "$2" |
        grep -iE 'timeout|timed out|hardware init failed|failed to|error -|probe .*failed' || true
}

# Two drivers bound to one card race each other at every boot; take every
# other driver from this repository away before installing one.
remove_other_wifi_drivers() {
    local keep="$1"
    [ "$keep" != "gen4" ] && { [ "$GEN4_STAGED" = true ] || dkms_has gen4-mt7902 ||
        ls /lib/modules/"${KVER}"/updates/dkms/mt7902.ko* >/dev/null 2>&1; } && cleanup_gen4
    [ "$keep" != "mt7902e" ] && remove_mt7902e
    [ "$keep" != "mt76" ] && remove_mt76 "${SCRIPT_DIR}/mt76"
    return 0
}

unload_stock_mt76() {
    local m
    for m in mt7921e mt7921_common mt792x_lib mt76_connac_lib mt76; do
        rmmod "$m" 2>/dev/null || true
    done
}

# ── WiFi driver: hmtheboy154/mt7902 (mt7902e) ─────────────────
# Mainline mt76 plus MediaTek's MT7902 series (Feb 2026), for 6.6 - 7.0. The
# upstream repository is archived; the copy in mt7902/ is its final state, so
# no network is needed — usually there is none, since WiFi is what is missing.
write_mt7902e_dkms_conf() {
    cat > "$1/dkms.conf" <<EOF
PACKAGE_NAME="mt7902e"
PACKAGE_VERSION="${MT7902E_DKMS_VER}"
BUILD_EXCLUSIVE_KERNEL="^(6\\.([6-9]|1[0-9])|7\\.)"
MAKE[0]="make KVER=\${kernelver} \$(grep -qs '^CONFIG_CC_IS_CLANG=y' /lib/modules/\${kernelver}/build/.config && echo LLVM=1)"
BUILT_MODULE_NAME[0]="mt7902e"
DEST_MODULE_LOCATION[0]="/updates/dkms"
AUTOINSTALL="yes"
EOF
}

install_wifi_mt7902e() {
    local src="${SCRIPT_DIR}/mt7902" stage="${STATE_DIR}/mt7902e-src" mark errs

    echo ""
    echo -e "  ${WHITE}Driver: mt7902e${NC}"

    if [ ! -f "${src}/Makefile" ]; then
        fail "mt7902/ is missing from this checkout — clone ${REPO_URL} again"
        return 1
    fi

    remove_other_wifi_drivers mt7902e

    step "Installing WiFi firmware"
    install_mt7902_firmware WIFI || return 1
    ok "Firmware in place"

    step "Building mt7902e"
    mkdir -p "$STATE_DIR"
    rm -rf "$stage"
    cp -r "$src" "$stage"
    write_mt7902e_dkms_conf "$stage"
    if [ "$USE_DKMS" = true ] && command -v dkms >/dev/null 2>&1; then
        dkms_install_pkg mt7902e "$MT7902E_DKMS_VER" "$stage" || return 1
    else
        manual_install_pkg mt7902e "$stage" mt7902e || return 1
    fi

    # Only with --force-custom on 7.1+: the in-tree driver would win otherwise
    if intree_supports_mt7902; then
        echo "blacklist mt7921e" > /etc/modprobe.d/mt7902-blacklist-intree.conf
    fi

    step "Loading mt7902e"
    unload_stock_mt76
    rmmod mt7902e 2>/dev/null || true
    mark=$(dmesg_mark)
    if ! try_modprobe mt7902e; then
        fail "mt7902e did not load"
        explain_load_failure
        if echo "$LAST_MODPROBE_ERR" | grep -qiE 'key was rejected|required key not available'; then
            # Not broken: it loads once the signing key is enrolled. Keep it.
            WIFI_DRIVER_USED="mt7902e (waiting for Secure Boot key enrollment)"
            return 0
        fi
        remove_mt7902e
        return 1
    fi
    if ! wifi_up mt7902e; then
        fail "mt7902e loaded but the card did not come up"
        dmesg_since "$mark" | grep -i mt79 | tail -5 | while IFS= read -r l; do echo -e "        ${DIM}${l}${NC}"; done
        remove_mt7902e
        return 1
    fi
    sleep 5
    errs=$(wifi_errors_since "$mark" 'mt79')
    if [ -n "$errs" ]; then
        fail "mt7902e is up but the firmware is not answering:"
        echo "$errs" | head -4 | while IFS= read -r l; do echo -e "        ${DIM}${l}${NC}"; done
        remove_mt7902e
        return 1
    fi
    if mt7902_pci_dev >/dev/null; then
        ok "mt7902e loaded, card bound, wireless interface present"
    else
        ok "mt7902e loaded (no card on this machine to bind — --no-card-check)"
    fi
    WIFI_DRIVER_USED="mt7902e"
}

# ── WiFi driver: morrownr/mt76 ────────────────────────────────
# The whole mainline mt76 family at kernel 7.3 level, built as *_git modules
# next to the in-kernel ones (which its modprobe.d file blacklists). It carries
# every MT7902 fix merged since 7.1. Supported on 6.12 and newer only.
mt76_supports_kernel() {
    [ "$KMAJOR" -ge 7 ] || { [ "$KMAJOR" -eq 6 ] && [ "$KMINOR" -ge 12 ]; }
}

install_wifi_mt76() {
    local src="${SCRIPT_DIR}/mt76" log="${STATE_DIR}/mt76-install.log" mark errs

    echo ""
    echo -e "  ${WHITE}Driver: mt76 (mt7921e_git)${NC}"
    [ -f "${src}/install-driver.sh" ] || { fail "mt76/ is missing from this checkout"; return 1; }

    remove_other_wifi_drivers mt76

    step "Installing WiFi firmware"
    install_mt7902_firmware WIFI || return 1
    ok "Firmware in place"

    step "Building mt76 — takes a few minutes"
    mkdir -p "$STATE_DIR"
    unload_stock_mt76
    if ! ( cd "$src" && sh install-driver.sh NoPrompt NoFirmware ) > "$log" 2>&1 </dev/null; then
        fail "mt76 install failed"
        grep -vE '^\s*$' "$log" | tail -8 | while IFS= read -r l; do echo -e "        ${DIM}${l}${NC}"; done
        echo -e "        ${DIM}Full log: ${log}${NC}"
        remove_mt76 "$src"
        return 1
    fi
    ok "Built and installed (log: ${log})"

    step "Loading mt7921e_git"
    mark=$(dmesg_mark)
    if ! try_modprobe mt7921e_git; then
        fail "mt7921e_git did not load"
        explain_load_failure
        if echo "$LAST_MODPROBE_ERR" | grep -qiE 'key was rejected|required key not available'; then
            WIFI_DRIVER_USED="mt76 (waiting for Secure Boot key enrollment)"
            return 0
        fi
        remove_mt76 "$src"
        return 1
    fi
    if ! wifi_up mt7921e_git; then
        fail "mt7921e_git loaded but the card did not come up"
        dmesg_since "$mark" | grep -i mt79 | tail -5 | while IFS= read -r l; do echo -e "        ${DIM}${l}${NC}"; done
        remove_mt76 "$src"
        return 1
    fi
    sleep 5
    errs=$(wifi_errors_since "$mark" 'mt79')
    if [ -n "$errs" ]; then
        fail "mt7921e_git is up but the firmware is not answering:"
        echo "$errs" | head -4 | while IFS= read -r l; do echo -e "        ${DIM}${l}${NC}"; done
        remove_mt76 "$src"
        return 1
    fi
    if mt7902_pci_dev >/dev/null; then
        ok "mt7921e_git loaded, card bound, wireless interface present"
    else
        ok "mt7921e_git loaded (no card on this machine to bind — --no-card-check)"
    fi
    WIFI_DRIVER_USED="mt76 (mt7921e_git)"
}

# ── WiFi driver: bundled gen4-mt7902 (vendor) ─────────────────
# Last resort: it frequently fails MCU init on this card ("wlanAccessRegister:
# Event reports address incorrect", "Fail reason: 4") and can hang in probe,
# hence the boot-safety measures below.
install_wifi_gen4() {
    local src="${SCRIPT_DIR}/gen4-mt7902"

    echo ""
    echo -e "  ${WHITE}Driver: gen4-mt7902 (vendor, last resort)${NC}"
    [ -d "$src" ] || { fail "WiFi source not found: $src"; return 1; }

    remove_other_wifi_drivers gen4

    step "Building WiFi driver (gen4-mt7902)"
    if [ "$USE_DKMS" = true ] && command -v dkms >/dev/null 2>&1; then
        rm -rf /usr/src/gen4-mt7902-0.1
        dkms_install_pkg gen4-mt7902 0.1 "$src" || return 1
    else
        manual_install_pkg gen4-mt7902 "$src" mt7902 || return 1
    fi

    step "Installing WiFi firmware"
    local fw_failed=0 f
    for f in "$src/firmware/"*; do
        [ -f "$f" ] || continue
        install_firmware "$f" "${FW_DIR}/mediatek" || fw_failed=1
    done
    # vendor-only files under mediatek/mt7902/ (uncompressed copies only:
    # the kernel would pick the .bin anyway and the .zst is a duplicate)
    for f in "${SCRIPT_DIR}/mt7902_temp/mt7902_firmware"/mt7902_*.bin; do
        [ -f "$f" ] || continue
        install_firmware "$f" "${FW_DIR}/mediatek/mt7902" || fw_failed=1
    done
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
    unload_stock_mt76
    rmmod mt7902e 2>/dev/null || true
    rmmod mt7902 2>/dev/null || true

    local gen4_ok=false
    if try_modprobe mt7902; then
        step "Verifying gen4 driver health"
        if check_wifi_health; then
            ok "gen4-mt7902 loaded and WiFi interface is up"
            gen4_ok=true
            WIFI_DRIVER_USED="gen4-mt7902"
        else
            warn "gen4-mt7902 loaded but health check failed"
        fi
    else
        warn "gen4-mt7902 failed to load"
        explain_load_failure
    fi

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
                WIFI_DRIVER_USED="gen4-mt7902 [mcu_bypass]"
            else
                warn "MCU bypass also failed health check"
            fi
        else
            warn "MCU bypass load failed"
        fi
    fi

    if [ "$gen4_ok" = false ]; then
        cleanup_gen4
        GEN4_STAGED=false
        return 1
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

# ── wifi ──────────────────────────────────────────────────────
# Order on a kernel without in-tree support:
#   mt7902e (default) -> morrownr/mt76 -> gen4
# mt7902e stays first because it is what this installer has always used and
# what works for most people; mt76 is newer and carries the post-7.1 fixes,
# so it is the next thing tried when mt7902e misbehaves (--mt76 tries it first).
install_wifi() {
    if [ "$FORCE_CUSTOM" = false ] && intree_supports_mt7902; then
        use_intree_driver && return 0
    fi

    local order d
    case "$PREFER_DRIVER" in
        mt76) order="mt76 mt7902e gen4" ;;
        gen4) order="gen4 mt7902e mt76" ;;
        *)    order="mt7902e mt76 gen4" ;;
    esac
    backport_supports_kernel || warn_unsupported_kernel

    for d in $order; do
        case "$d" in
            mt7902e)
                backport_supports_kernel || { warn "Skipping mt7902e (needs kernel 6.6 or newer)"; continue; }
                install_wifi_mt7902e && return 0 ;;
            mt76)
                mt76_supports_kernel || { warn "Skipping mt76 (needs kernel 6.12 or newer)"; continue; }
                install_wifi_mt76 && return 0 ;;
            gen4)
                install_wifi_gen4 && return 0 ;;
        esac
        warn "${d} did not work on this machine — trying the next driver"
    done
    WIFI_DRIVER_USED="none (every driver failed)"
    return 1
}

# ── bluetooth ─────────────────────────────────────────────────
# Patched btusb + btmtk (mt7902_temp/linux-X.Y) packaged for DKMS from
# bluetooth-dkms/. Earlier versions overwrote the distribution's own modules,
# so the next kernel update silently took Bluetooth away again and Fedora
# ended up with two btusb copies (.ko.xz and .ko.zst) side by side.
assemble_bt_package() {
    local out="$1" d v
    rm -rf "$out"
    mkdir -p "$out/src"
    cp -r "${SCRIPT_DIR}/bluetooth-dkms/." "$out/"
    for d in "${SCRIPT_DIR}"/mt7902_temp/linux-*/drivers/bluetooth; do
        [ -f "$d/btusb.c" ] || continue
        v=$(basename "$(dirname "$(dirname "$d")")")
        mkdir -p "$out/src/$v"
        cp "$d"/btusb.c "$d"/btmtk.c "$d"/*.h "$out/src/$v/"
    done
}

install_bt() {
    local pkg="${STATE_DIR}/mt7902-bt-src" i

    step "Bluetooth for kernel ${KVER}"

    # Kernel 7.1+ ships btusb/btmtk with MT7902 support. Building the older
    # sources bundled here against it would replace working modules with a
    # downgrade, so leave them alone.
    if bt_intree_supported; then
        ok "Kernel ${KMAJOR}.${KMINOR} carries Bluetooth support for this chip"
        echo -e "      ${DIM}Its own btusb/btmtk are newer than the sources here — not replacing them.${NC}"
        if [ -f /etc/modprobe.d/mt7902-blacklist.conf ]; then
            warn "Removing a stale blacklist that would stop them loading"
            rm -f /etc/modprobe.d/mt7902-blacklist.conf
            ok "Removed /etc/modprobe.d/mt7902-blacklist.conf"
        fi
        return 0
    fi

    # Put back whatever an earlier version of this installer overwrote
    remove_bt_backport
    depmod -a

    step "Installing Bluetooth firmware"
    install_mt7902_firmware BT || return 1
    ok "Firmware in place"

    step "Building btusb + btmtk with MT7902 support"
    mkdir -p "$STATE_DIR"
    assemble_bt_package "$pkg"
    if [ "$USE_DKMS" = true ] && command -v dkms >/dev/null 2>&1; then
        dkms_install_pkg mt7902-bt "$BT_DKMS_VER" "$pkg" || return 1
    else
        manual_install_pkg mt7902-bt "$pkg" btusb btmtk || return 1
    fi

    step "Loading Bluetooth modules"
    rmmod btusb 2>/dev/null || true
    rmmod btmtk 2>/dev/null || true
    if ! try_modprobe btusb; then
        fail "btusb did not load"
        explain_load_failure
        return 1
    fi
    case "$(modinfo -n btusb 2>/dev/null)" in
        */updates/*) ok "Patched btusb loaded ($(modinfo -n btusb))" ;;
        *)           warn "btusb loaded from $(modinfo -n btusb 2>/dev/null) — not the patched copy" ;;
    esac
    for i in $(seq 1 10); do
        ls /sys/class/bluetooth/hci* >/dev/null 2>&1 && break
        sleep 1
    done
    if ls /sys/class/bluetooth/hci* >/dev/null 2>&1; then
        ok "Bluetooth controller is up"
    else
        warn "No Bluetooth controller yet — it usually appears after a reboot"
    fi
}

# ── main ──────────────────────────────────────────────────────
detect_distro
show_banner
show_info_box

# Runs on every kernel, the in-tree case included: that is exactly where a
# stale copy from an old run hides the firmware the distribution keeps current.
check_shadowing_firmware

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
if [ "$DO_WIFI" = true ] && \
   [ "$FORCE_CUSTOM" = false ] && intree_supports_mt7902; then
    echo ""
    echo -e "  ${WHITE}── WiFi ──────────────────────────────────${NC}"
    if use_intree_driver; then
        DO_WIFI=false
        if [ "$DO_BT" = true ] && bt_intree_supported; then
            echo ""
            ok "Kernel ${KMAJOR}.${KMINOR} also carries Bluetooth support for this chip"
            rm -f /etc/modprobe.d/mt7902-blacklist.conf 2>/dev/null &&
                ok "Removed a stale blacklist that would stop btusb/btmtk loading" || true
            DO_BT=false
        fi
        if [ "$DO_BT" = false ]; then
            echo ""
            echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
            echo -e "  ${GREEN}${BOLD}Nothing to install.${NC}"
            echo -e "  ${WHITE}WiFi driver:${NC} ${CYAN}${WIFI_DRIVER_USED}${NC}"
            echo ""
            exit 0
        fi
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

BT_FAILED=false
if [ "$DO_BT" = true ]; then
    echo ""
    echo -e "  ${WHITE}── Bluetooth ─────────────────────────────${NC}"
    install_bt || BT_FAILED=true
fi

mkdir -p "$STATE_DIR"
{
    echo "date=$(date -Is)"
    echo "kernel=${KVER}"
    echo "wifi_driver=${WIFI_DRIVER_USED}"
    echo "wifi_failed=${WIFI_FAILED}"
    echo "bt_failed=${BT_FAILED}"
} > "${STATE_DIR}/last-install"

echo ""
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""
if [ "$WIFI_FAILED" = true ]; then
    echo -e "  ${YELLOW}${BOLD}Installation finished with errors.${NC}"
    echo -e "  ${YELLOW}WiFi could not be installed — no driver loaded.${NC}"
    echo -e "  ${DIM}Stock drivers were left untouched, so your system is unchanged.${NC}"
elif [ "$BT_FAILED" = true ]; then
    echo -e "  ${YELLOW}${BOLD}Installation finished with errors.${NC}"
    echo -e "  ${YELLOW}Bluetooth could not be installed — see above.${NC}"
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
    echo -e "  ${YELLOW}Still having problems?${NC} ${DIM}Try the mt76-based drivers:${NC}"
    echo -e "    ${DIM}sudo ./install.sh --mt7902e   or   sudo ./install.sh --mt76${NC}"
elif [[ "$WIFI_DRIVER_USED" == mt7902e* ]]; then
    echo -e "  ${DIM}Source: ${REPO_URL}${NC}"
    if mt76_supports_kernel; then
        echo -e "  ${DIM}WiFi misbehaving? The newer mt76 driver may do better:${NC}"
        echo -e "    ${DIM}sudo ./install.sh --mt76${NC}"
    fi
elif [[ "$WIFI_DRIVER_USED" == mt76* ]]; then
    echo -e "  ${DIM}Source: ${REPO_URL} — diagnostics: ${SCRIPT_DIR}/mt76/check-driver.sh${NC}"
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
if [ "$NO_REBOOT" = true ]; then
    echo -e "  ${DIM}Not rebooting (--no-reboot). Reboot yourself to finish.${NC}"
    exit 0
fi

echo -e "  ${YELLOW}Rebooting in 10 seconds... (Ctrl+C to cancel)${NC}"
for i in 10 9 8 7 6 5 4 3 2 1; do
    echo -ne "\r  ${BOLD}${i}...${NC}  "
    sleep 1
done
echo ""
reboot
