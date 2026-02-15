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
    -h, --help    Show this message

  Examples:
    sudo $0               # install everything
    sudo $0 --wifi        # wifi driver + firmware only
    sudo $0 --bt          # bluetooth driver + firmware only
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
        debian) apt-get update -qq && apt-get install -y build-essential linux-headers-$(uname -r) dkms zstd > /dev/null 2>&1 ;;
        fedora) dnf install -y make gcc kernel-devel kernel-headers dkms zstd > /dev/null 2>&1 ;;
        arch)   pacman -S --needed --noconfirm base-devel linux-headers dkms zstd > /dev/null 2>&1 ;;
        suse)   zypper install -y make gcc kernel-devel dkms zstd > /dev/null 2>&1 ;;
        *)      warn "Unknown distro — install manually: build-essential, linux-headers, dkms, zstd"; return ;;
    esac
    ok "Dependencies ready (${DISTRO})"
}

# ── wifi ──────────────────────────────────────────────────────
install_wifi() {
    local src="${SCRIPT_DIR}/gen4-mt7902"
    [ -d "$src" ] || { fail "WiFi source not found: $src"; return 1; }

    # detect firmware path (Arch uses /usr/lib/firmware, others use /lib/firmware)
    local FW_DIR="/lib/firmware"
    [ -d "/usr/lib/firmware" ] && ! [ -L "/lib" ] && FW_DIR="/usr/lib/firmware"

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
    [ -d "$src/firmware" ] && cp "$src/firmware/"* "${FW_DIR}/mediatek/" 2>/dev/null || true

    local fw="${SCRIPT_DIR}/mt7902_temp/mt7902_firmware"
    if [ -d "$fw" ]; then
        for f in "$fw"/WIFI_*.bin.zst "$fw"/WIFI_*.bin; do
            [ -f "$f" ] && cp "$f" "${FW_DIR}/mediatek/"
        done
        for f in "$fw"/mt7902_*.bin.zst "$fw"/mt7902_*.bin; do
            [ -f "$f" ] && cp "$f" "${FW_DIR}/mediatek/mt7902/"
        done
    fi
    ok "Firmware copied to ${FW_DIR}/mediatek/"

    step "Blacklisting conflicting stock drivers"
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

    # regenerate initramfs so blacklist takes effect on next boot
    if command -v update-initramfs &>/dev/null; then
        update-initramfs -u 2>/dev/null && ok "initramfs updated (Debian/Ubuntu)"
    elif command -v mkinitcpio &>/dev/null; then
        mkinitcpio -P 2>/dev/null && ok "initramfs updated (Arch)"
    elif command -v dracut &>/dev/null; then
        dracut --force 2>/dev/null && ok "initramfs updated (Fedora/RHEL)"
    fi

    step "Loading WiFi module"
    depmod -a
    # unload any conflicting stock drivers first
    rmmod mt7921e 2>/dev/null || true
    rmmod mt7902e 2>/dev/null || true
    rmmod mt7921_common 2>/dev/null || true
    rmmod mt76_connac_lib 2>/dev/null || true
    rmmod mt7902 2>/dev/null || true
    modprobe mt7902
    ok "mt7902 module loaded"

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
        [ -z "$best" ] && best=$(ls -d "${base}"/linux-*/drivers/bluetooth 2>/dev/null | sort -V | head -1)
        [ -z "$best" ] && { fail "No bluetooth source found"; return 1; }
        bt_dir="$best"
        ok "Using $(basename $(dirname $(dirname $bt_dir)))"
    fi

    step "Building btusb + btmtk modules"
    cd "$bt_dir"
    make -C /lib/modules/$(uname -r)/build/ M=$(pwd) modules

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

if [ "$DO_WIFI" = true ]; then
    echo ""
    echo -e "  ${WHITE}── WiFi ──────────────────────────────────${NC}"
    install_wifi
fi

if [ "$DO_BT" = true ]; then
    echo ""
    echo -e "  ${WHITE}── Bluetooth ─────────────────────────────${NC}"
    install_bt
fi

echo ""
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${GREEN}${BOLD}Installation complete.${NC}"
echo ""
if [ "$DO_WIFI" = true ] && [ "$DO_BT" = true ]; then
    echo -e "  ${DIM}Installed: WiFi + Bluetooth${NC}"
elif [ "$DO_WIFI" = true ]; then
    echo -e "  ${DIM}Installed: WiFi${NC}"
else
    echo -e "  ${DIM}Installed: Bluetooth${NC}"
fi
echo -e "  ${DIM}Reboot for changes to take effect.${NC}"
echo -e "  ${DIM}WiFi flaky? → sudo rmmod mt7902 && sudo modprobe mt7902${NC}"
echo ""
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${YELLOW}Rebooting in 5 seconds... (Ctrl+C to cancel)${NC}"
for i in 5 4 3 2 1; do
    echo -ne "\r  ${BOLD}${i}...${NC}  "
    sleep 1
done
echo ""
reboot
