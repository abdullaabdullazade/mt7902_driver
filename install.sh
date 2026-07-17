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

    # fully clean up the failed gen4 driver first
    cleanup_gen4

    step "Cloning hmtheboy154/mt7902"
    rm -rf "$FALLBACK_DIR"
    if ! git clone --depth 1 "$FALLBACK_REPO" "$FALLBACK_DIR" 2>&1; then
        fail "Could not clone ${FALLBACK_REPO}"
        fail "Check your internet connection and try again."
        exit 1
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
    modprobe mt7902e || { fail "Could not load alternative driver either."; exit 1; }
    ok "Alternative driver loaded (mt7902e by hmtheboy154)"

    WIFI_DRIVER_USED="hmtheboy154/mt7902"
}

# ── wifi ──────────────────────────────────────────────────────
install_wifi() {
    local src="${SCRIPT_DIR}/gen4-mt7902"

    # detect firmware path (Arch uses /usr/lib/firmware, others use /lib/firmware)
    local FW_DIR="/lib/firmware"
    [ -d "/usr/lib/firmware" ] && ! [ -L "/lib" ] && FW_DIR="/usr/lib/firmware"

    # ── if --fallback flag used, skip gen4 entirely ────────────
    if [ "$USE_FALLBACK" = true ]; then
        step "Skipping gen4 driver (--fallback flag set)"
        install_wifi_fallback
        return 0
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

    # ── try loading gen4 driver + health check ────────────────
    local gen4_ok=false
    if modprobe mt7902 2>/dev/null; then
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
        if modprobe mt7902 mcu_bypass=1 2>/dev/null; then
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
        install_wifi_fallback
        return 0
    fi

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
echo -e "  ${YELLOW}Rebooting in 5 seconds... (Ctrl+C to cancel)${NC}"
for i in 5 4 3 2 1; do
    echo -ne "\r  ${BOLD}${i}...${NC}  "
    sleep 1
done
echo ""
reboot
