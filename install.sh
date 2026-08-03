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
    case "$DISTRO" in
        debian) apt-get update -qq && apt-get install -y build-essential linux-headers-$(uname -r) dkms zstd git > /dev/null 2>&1 ;;
        fedora) dnf install -y make gcc kernel-devel kernel-headers dkms zstd git > /dev/null 2>&1 ;;
        arch)   pacman -S --needed --noconfirm base-devel linux-headers dkms zstd git > /dev/null 2>&1 ;;
        suse)   zypper install -y make gcc kernel-devel dkms zstd git > /dev/null 2>&1 ;;
        *)      warn "Unknown distro — install manually: build-essential, linux-headers, dkms, zstd, git"; return ;;
    esac
    ok "Dependencies ready (${DISTRO})"
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

use_intree_driver() {
    step "Using in-tree mt7921e (kernel ${KVER} supports 14c3:7902)"
    # check_wifi_health() looks for the custom mt7902 module by name, so the
    # in-tree driver needs its own check: module loaded and an interface up.
    if try_modprobe mt7921e && sleep 2 && lsmod | grep -q '^mt7921e ' && \
       ip link show 2>/dev/null | grep -qE 'wlan|wlp|wlo'; then
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
    if ! ip link show 2>/dev/null | grep -qE 'wlan|wlp|wlo'; then
        warn "No WiFi interface detected (wlan*/wlp*/wlo*)"
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
        step "Trying the mt76-based driver first (gen4 is the fallback)"
        if install_wifi_fallback; then
            return 0
        fi
        warn "mt76-based driver did not work; trying gen4-mt7902"
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
        cd "$src"
        make -j$(nproc)
        make install -j$(nproc)
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
    modprobe btmtk
    modprobe btusb
    ok "Modules loaded"

    cd "$SCRIPT_DIR"

    step "Installing Bluetooth firmware"
    local fw="${SCRIPT_DIR}/mt7902_temp/mt7902_firmware"
    if [ -d "$fw" ]; then
        mkdir -p "${FW_DIR}/mediatek"
        for f in "$fw"/BT_*.bin.zst "$fw"/BT_*.bin; do
            [ -f "$f" ] && cp "$f" "${FW_DIR}/mediatek/"
        done
    fi
    ok "BT firmware copied"
}

# ── main ──────────────────────────────────────────────────────
detect_distro
show_banner
show_info_box

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
