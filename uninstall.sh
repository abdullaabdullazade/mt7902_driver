#!/bin/bash
#
# MT7902 Driver Uninstaller
# Removes whatever install.sh (this version or an older one) put on the
# system: every WiFi driver it can install, the Bluetooth backport, its
# blacklists and services. The distribution's own modules and firmware are
# never touched — only files no package owns.
#
# Usage: sudo ./uninstall.sh [--all|--wifi|--bt] [--keep-fw] [--no-reboot]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'

RM_WIFI=false
RM_BT=false
KEEP_FW=false
NO_REBOOT=false

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
        --all)       RM_WIFI=true; RM_BT=true ;;
        --wifi)      RM_WIFI=true ;;
        --bt)        RM_BT=true ;;
        --keep-fw)   KEEP_FW=true ;;
        --no-reboot) NO_REBOOT=true ;;
        -h|--help)   show_banner
                     echo "  Usage: sudo $0 [--all|--wifi|--bt] [--keep-fw] [--no-reboot]"
                     echo ""; exit 0 ;;
        *)           echo "Unknown option: $arg"; exit 1 ;;
    esac
done
# Only flags that do not pick a component were given: remove everything
if [ "$RM_WIFI" = false ] && [ "$RM_BT" = false ]; then
    RM_WIFI=true; RM_BT=true
fi

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ Run this script with sudo${NC}"; exit 1
fi

show_banner
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""

if [ "$RM_WIFI" = true ]; then
    step "Removing WiFi drivers"

    # gen4-mt7902 (vendor driver)
    rmmod mt7902 2>/dev/null || true
    command -v dkms &>/dev/null && dkms remove gen4-mt7902/0.1 --all >/dev/null 2>&1 || true
    rm -rf /usr/src/gen4-mt7902-0.1 /lib/modules/*/updates/gen4-mt7902
    find /lib/modules -name 'mt7902.ko*' -delete 2>/dev/null || true
    rm -f /etc/modprobe.d/mt7902.conf /etc/modprobe.d/mt7902-noautoload.conf
    if command -v systemctl &>/dev/null; then
        systemctl disable mt7902-late.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/mt7902-late.service
        systemctl daemon-reload 2>/dev/null || true
    fi
    ok "gen4-mt7902 removed"

    # hmtheboy154/mt7902 (mt7902e)
    remove_mt7902e
    ok "mt7902e removed"

    # morrownr/mt76 (*_git modules and its blacklist of the in-kernel mt76)
    remove_mt76 "${SCRIPT_DIR}/mt76"
    ok "mt76 removed"

    rm -f /etc/modprobe.d/blacklist-mt7921.conf /etc/modprobe.d/blacklist-mt7902.conf
    ok "Blacklists of the in-kernel drivers removed"
fi

if [ "$RM_BT" = true ]; then
    step "Removing the Bluetooth backport"
    remove_bt_backport
    rm -f /etc/modprobe.d/mt7902-blacklist.conf
    depmod -a
    modprobe btusb 2>/dev/null || true
    ok "Distribution's btusb/btmtk are back ($(modinfo -n btusb 2>/dev/null || echo 'not present'))"
fi

if [ "$KEEP_FW" = false ]; then
    step "Removing firmware this installer added"
    # Two kinds go: copies that hide a newer one the distribution ships, and
    # the vendor-only files the gen4 driver used. MT7902 firmware that is the
    # only copy on the system stays — on kernel 7.1+ the in-tree driver needs
    # it, and deleting it would leave the card dead.
    removed=0
    for f in $(find_shadowing_firmware); do
        rm -f "$f" && removed=$((removed + 1))
    done
    if [ "$RM_WIFI" = true ]; then
        for f in "${FW_DIR}"/mediatek/mt7902/mt7902_*; do
            [ -e "$f" ] || continue
            pkg_owns "$f" && continue
            rm -f "$f" && removed=$((removed + 1))
        done
        rmdir "${FW_DIR}/mediatek/mt7902" 2>/dev/null || true
    fi
    ok "${removed} file(s) removed"
    for rel in $MT7902_FW_FILES; do
        f="${FW_DIR}/${rel}"
        if [ -e "$f" ] && ! pkg_owns "$f" && ! fw_pkg_variant "$f" >/dev/null; then
            echo -e "      ${DIM}kept ${f} — the only copy; your kernel may need it${NC}"
        fi
    done
fi

rm -f "$MANIFEST" "${STATE_DIR}/last-install"
rm -rf "${STATE_DIR}"/*-src "${STATE_DIR}"/*-src.git
rmdir "$STATE_DIR" 2>/dev/null || true

step "Updating module index and initramfs"
depmod -a
rebuild_initramfs_quiet || true
ok "Done"

echo ""
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${GREEN}${BOLD}Uninstallation complete.${NC}"
echo ""
echo -e "${DIM}────────────────────────────────────────────────────────${NC}"
echo ""
if [ "$NO_REBOOT" = true ]; then
    echo -e "  ${DIM}Not rebooting (--no-reboot). Reboot yourself to finish.${NC}"
    exit 0
fi
echo -e "  ${YELLOW}Rebooting in 5 seconds... (Ctrl+C to cancel)${NC}"
for i in 5 4 3 2 1; do
    echo -ne "\r  ${BOLD}${i}...${NC}  "
    sleep 1
done
echo ""
reboot
