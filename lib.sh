#!/bin/bash
#
# Helpers shared by install.sh and uninstall.sh. Sourced, not run.
#

FW_DIR="/lib/firmware"
STATE_DIR="/var/lib/mt7902-driver"
# Every file this repository puts outside a package manager's view is listed
# here, so uninstall.sh removes exactly those and never a distribution's file.
MANIFEST="${STATE_DIR}/installed-files"

# Firmware the MT7902 drivers in this repository ask for, relative to FW_DIR.
MT7902_FW_FILES="
mediatek/WIFI_MT7902_patch_mcu_1_1_hdr.bin
mediatek/WIFI_RAM_CODE_MT7902_1.bin
mediatek/BT_RAM_CODE_MT7902_1_1_hdr.bin
"

record_installed() {
    mkdir -p "$STATE_DIR"
    grep -qxF "$1" "$MANIFEST" 2>/dev/null || echo "$1" >> "$MANIFEST"
}

# Does the distribution's package manager own this path?
pkg_owns() {
    local p="$1"
    [ -e "$p" ] || return 1
    if command -v dpkg >/dev/null 2>&1 && dpkg -S "$p" >/dev/null 2>&1; then return 0; fi
    # dpkg records the /lib path even on merged-/usr systems, and vice versa
    if command -v dpkg >/dev/null 2>&1 && dpkg -S "${p#/usr}" >/dev/null 2>&1; then return 0; fi
    if command -v rpm >/dev/null 2>&1 && rpm -qf "$p" >/dev/null 2>&1; then return 0; fi
    if command -v pacman >/dev/null 2>&1 && pacman -Qo "$p" >/dev/null 2>&1; then return 0; fi
    return 1
}

# The kernel's firmware loader tries <name> first and only then <name>.zst /
# <name>.xz / <name>.gz. So a copy of any variant already satisfies a driver,
# and an uncompressed copy shadows every compressed one.
fw_any_variant() {
    local p="$1" ext
    for ext in "" .zst .xz .gz; do
        [ -s "${p}${ext}" ] && return 0
    done
    return 1
}

fw_pkg_variant() {
    local p="$1" ext
    for ext in "" .zst .xz .gz; do
        [ -s "${p}${ext}" ] && pkg_owns "${p}${ext}" && { echo "${p}${ext}"; return 0; }
    done
    return 1
}

# Uncompressed or .zst copies of MT7902 firmware that no package owns, sitting
# next to a newer copy the distribution ships. Earlier versions of this
# installer left them behind, and because the loader picks the uncompressed
# file first, the distribution's firmware is never used while they exist.
find_shadowing_firmware() {
    local rel p ext owned
    for rel in $MT7902_FW_FILES; do
        p="${FW_DIR}/${rel}"
        owned=$(fw_pkg_variant "$p") || continue
        for ext in "" .zst .xz .gz; do
            [ -e "${p}${ext}" ] || continue
            [ "${p}${ext}" = "$owned" ] && continue
            pkg_owns "${p}${ext}" && continue
            echo "${p}${ext}"
        done
    done
    return 0
}

rebuild_initramfs_quiet() {
    if command -v update-initramfs >/dev/null 2>&1; then
        update-initramfs -u >/dev/null 2>&1
    elif command -v dracut >/dev/null 2>&1; then
        dracut --force >/dev/null 2>&1
    elif command -v mkinitcpio >/dev/null 2>&1; then
        mkinitcpio -P >/dev/null 2>&1
    fi
}

# Path of the PCI device for the card, empty if absent.
mt7902_pci_dev() {
    local d vendor device
    for d in /sys/bus/pci/devices/*; do
        [ -r "$d/vendor" ] && [ -r "$d/device" ] || continue
        read -r vendor < "$d/vendor"
        read -r device < "$d/device"
        if [ "$vendor" = "0x14c3" ] && [ "$device" = "0x7902" ]; then
            echo "$d"
            return 0
        fi
    done
    return 1
}

# Name of the driver currently bound to the card, empty if none.
mt7902_bound_driver() {
    local d
    d=$(mt7902_pci_dev) || return 1
    [ -L "$d/driver" ] || return 1
    basename "$(readlink "$d/driver")"
}

# ── removal of each driver this repository can install ─────────
# Shared by install.sh (switching from one driver to another, so two
# drivers never compete for the same card at boot) and uninstall.sh.
# Callers provide ok/warn.

MT7902E_DKMS_VER="1.0"
BT_DKMS_VER="1.0"

dkms_has() {
    command -v dkms >/dev/null 2>&1 && dkms status -m "$1" 2>/dev/null | grep -q "$1"
}

remove_mt7902e() {
    local kv
    rmmod mt7902e 2>/dev/null || true
    if dkms_has mt7902e; then
        dkms status -m mt7902e 2>/dev/null | sed -n 's|^mt7902e[/,] *\([^,:/]*\).*|\1|p' | sort -u |
            while read -r v; do dkms remove -m mt7902e -v "$v" --all >/dev/null 2>&1 || true; done
    fi
    rm -rf /usr/src/mt7902e-*
    # `make install` from the upstream repo, as earlier versions of this
    # installer ran it: no DKMS, so it was never rebuilt for a new kernel
    for kv in /lib/modules/*; do
        rm -rf "${kv}/kernel/drivers/net/wireless/mediatek/mt7902e" "${kv}/updates/mt7902e"
    done
    rm -f /etc/modprobe.d/mt7902-blacklist-intree.conf
}

remove_mt76() {
    local dir="$1"
    if [ -f /etc/modprobe.d/mt76_git.conf ] || dkms_has mt76; then
        if [ -f "${dir}/uninstall-driver.sh" ]; then
            ( cd "$dir" && sh uninstall-driver.sh NoPrompt ) >/dev/null 2>&1 </dev/null || true
        else
            dkms remove -m mt76 -v 1.0 --all >/dev/null 2>&1 || true
            rm -rf /usr/src/mt76-1.0 /etc/modprobe.d/mt76_git.conf
            find /lib/modules -name '*_git.ko*' -path '*mt76*' -delete 2>/dev/null || true
        fi
    fi
}

remove_bt_backport() {
    local kv f
    rmmod btusb 2>/dev/null || true
    rmmod btmtk 2>/dev/null || true
    if dkms_has mt7902-bt; then
        dkms remove -m mt7902-bt -v "$BT_DKMS_VER" --all >/dev/null 2>&1 || true
    fi
    rm -rf /usr/src/mt7902-bt-* /lib/modules/*/updates/mt7902-bt
    # Earlier versions overwrote the distribution's own btusb/btmtk and kept
    # the originals as *.bak — put those back wherever they are.
    for kv in /lib/modules/*; do
        for f in "${kv}"/kernel/drivers/bluetooth/bt{usb,mtk}.ko*.bak; do
            [ -f "$f" ] && mv -f "$f" "${f%.bak}"
        done
        # Where the distribution compresses modules with xz (Fedora) the old
        # .ko.zst copies landed next to the real .ko.xz instead of over it.
        for f in "${kv}"/kernel/drivers/bluetooth/bt{usb,mtk}.ko*; do
            [ -f "$f" ] || continue
            pkg_owns "$f" && continue
            local stem="${f%.ko*}" sib
            for sib in "${stem}.ko" "${stem}.ko.xz" "${stem}.ko.zst" "${stem}.ko.gz"; do
                if [ "$sib" != "$f" ] && pkg_owns "$sib"; then
                    rm -f "$f"
                    break
                fi
            done
        done
    done
}
