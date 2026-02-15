#!/bin/bash
#
# MT7902 Driver Uninstaller
# Removes the WiFi and/or Bluetooth drivers installed by install.sh.
#
# Usage: sudo ./uninstall.sh [--all|--wifi|--bt] [--keep-fw]
#

set -e

NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'

RM_WIFI=false
RM_BT=false
KEEP_FW=false

show_banner() {
    echo ""
    echo -e "\033[1;38;2;255;80;60m  ███╗   ███╗████████╗███████╗ █████╗  ██████╗ ██████╗         ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ \033[0m"
    echo -e "\033[1;38;2;240;70;70m  ████╗ ████║╚══██╔══╝╚════██║██╔══██╗██╔═████╗╚════██╗        ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗\033[0m"
    echo -e "\033[1;38;2;220;60;80m  ██╔████╔██║   ██║       ██╔╝╚██████║██║██╔██║ █████╔╝        ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝\033[0m"
    echo -e "\033[1;38;2;200;50;90m  ██║╚██╔╝██║   ██║      ██╔╝  ╚═══██║████╔╝██║██╔═══╝         ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗\033[0m"
    echo -e "\033[1;38;2;180;45;100m  ██║ ╚═╝ ██║   ██║      ██║   █████╔╝╚██████╔╝███████╗███████╗██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║\033[0m"
    echo -e "\033[1;38;2;160;40;110m  ╚═╝     ╚═╝   ╚═╝      ╚═╝   ╚════╝  ╚═════╝ ╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝\033[0m"
    echo ""
}

step_count=0
step() { step_count=$((step_count + 1)); echo -e "  ${CYAN}[${step_count}]${NC} ${BOLD}$1${NC}"; }
ok()   { echo -e "      ${GREEN}✓${NC} $1"; }
warn() { echo -e "      ${YELLOW}!${NC} $1"; }

if [ $# -eq 0 ]; then
    RM_WIFI=true; RM_BT=true
fi

for arg in "$@"; do
    case $arg in
        --all)      RM_WIFI=true; RM_BT=true ;;
        --wifi)     RM_WIFI=true ;;
        --bt)       RM_BT=true ;;
        --keep-fw)  KEEP_FW=true ;;
        -h|--help)  show_banner; echo "  Usage: sudo $0 [--all|--wifi|--bt] [--keep-fw]"; echo ""; exit 0 ;;
        *)          echo "Unknown option: $arg"; exit 1 ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ Run this script with sudo${NC}"; exit 1
fi

show_banner
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""

if [ "$RM_WIFI" = true ]; then
    step "Removing WiFi driver"
    rmmod mt7902 2>/dev/null || true
    command -v dkms &>/dev/null && dkms remove gen4-mt7902/0.1 --all 2>/dev/null || true
    rm -rf /usr/src/gen4-mt7902-0.1
    ok "DKMS module removed"

    if [ "$KEEP_FW" = false ]; then
        step "Removing WiFi firmware"
        rm -f /lib/firmware/mediatek/WIFI_MT7902_patch_mcu_1_1_hdr.bin*
        rm -f /lib/firmware/mediatek/WIFI_RAM_CODE_MT7902_1.bin*
        rm -rf /lib/firmware/mediatek/mt7902/mt7902_*.bin*
        ok "Firmware cleaned"
    fi
fi

if [ "$RM_BT" = true ]; then
    step "Restoring original Bluetooth modules"
    MOD_DIR="/lib/modules/$(uname -r)/kernel/drivers/bluetooth"

    [ -f "${MOD_DIR}/btusb.ko.zst.bak" ] && mv "${MOD_DIR}/btusb.ko.zst.bak" "${MOD_DIR}/btusb.ko.zst"
    [ -f "${MOD_DIR}/btmtk.ko.zst.bak" ] && mv "${MOD_DIR}/btmtk.ko.zst.bak" "${MOD_DIR}/btmtk.ko.zst"

    rmmod btusb 2>/dev/null || true
    rmmod btmtk 2>/dev/null || true
    depmod -a
    modprobe btmtk 2>/dev/null || true
    modprobe btusb 2>/dev/null || true
    ok "Original modules restored"

    if [ "$KEEP_FW" = false ]; then
        step "Removing BT firmware"
        rm -f /lib/firmware/mediatek/BT_RAM_CODE_MT7902_1_1_hdr.bin*
        ok "Firmware cleaned"
    fi
fi

# remove blacklist config files created by installer
step "Removing driver blacklist configs"
rm -f /etc/modprobe.d/blacklist-mt7921.conf 2>/dev/null || true
rm -f /etc/modprobe.d/blacklist-mt7902.conf 2>/dev/null || true
ok "Blacklist configs removed"

# remove late-load systemd service
if command -v systemctl &>/dev/null; then
    systemctl disable mt7902-late.service 2>/dev/null || true
    rm -f /etc/systemd/system/mt7902-late.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
fi

depmod -a

echo ""
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${GREEN}${BOLD}Uninstallation complete.${NC}"
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
