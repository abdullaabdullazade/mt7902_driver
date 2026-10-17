# SPDX-License-Identifier: GPL-2.0
#
# Builds btusb + btmtk with MT7902 support from the source tree that matches
# the target kernel best: the newest linux-X.Y/ that is not newer than the
# kernel, or the oldest one when every tree is newer (with a compat shim for
# headers that moved). DKMS calls this with KVER set to the kernel it is
# building for, which is not necessarily the running one.

KVER ?= $(shell uname -r)
KSRC ?= /lib/modules/$(KVER)/build
PKGDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD := $(PKGDIR)/build

KMAJ := $(word 1,$(subst ., ,$(KVER)))
KMIN := $(word 2,$(subst ., ,$(KVER)))
KNUM := $(shell echo $$(( $(KMAJ) * 1000 + $(KMIN) )))

TREES := $(shell sh $(PKGDIR)/select-src.sh $(KVER))

# Clang-built kernels (CachyOS, Chimera, ...) need their modules built by clang.
ifeq ($(shell grep -qs '^CONFIG_CC_IS_CLANG=y' $(KSRC)/.config && echo y),y)
LLVM ?= 1
export LLVM
endif

# <linux/unaligned.h> is the 6.12+ name; older kernels only have <asm/unaligned.h>
ifeq ($(shell [ $(KNUM) -lt 6012 ] && echo y),y)
COMPAT_INC := -I$(PKGDIR)/compat
endif

# Try the best-matching tree first; if it does not compile against this
# kernel's headers, fall through to the next candidate.
all:
	@for src in $(TREES); do \
		echo "mt7902-bt: kernel $(KVER), trying $$(basename $$src)"; \
		$(MAKE) --no-print-directory SRC=$$src prepare && \
		$(MAKE) --no-print-directory -C $(KSRC) M=$(BUILD) modules && \
		cp -f $(BUILD)/btusb.ko $(BUILD)/btmtk.ko $(PKGDIR)/ && \
		echo "mt7902-bt: built from $$(basename $$src)" && exit 0; \
		echo "mt7902-bt: $$(basename $$src) does not build here, trying the next one"; \
	done; echo "mt7902-bt: no bundled source builds against $(KVER)"; exit 1

# The MediaTek half of btusb is compiled only when the kernel's own config
# enables it; force it on so a kernel built without it still gets a working
# MT7902 driver. MODULE_VERSION is bumped so DKMS's version sanity check
# treats these as newer than the stock modules instead of refusing to install.
# MT7902 USB IDs that upstream Linux has and an older tree may lack are added
# here rather than in mt7902_temp/, which is kept identical to its upstream.
MT7902_IDS := 0x0489:0xe156 0x0e8d:0x1ede 0x13d3:0x3579 0x13d3:0x3580 0x13d3:0x3594 0x13d3:0x3596

prepare:
	rm -rf $(BUILD)
	mkdir -p $(BUILD)
	cp $(SRC)/btusb.c $(SRC)/btmtk.c $(SRC)/*.h $(BUILD)/
	sed -i 's/^#define VERSION "\([0-9.]*\)"/#define VERSION "\1.7902"/' \
		$(BUILD)/btusb.c $(BUILD)/btmtk.c
	for id in $(MT7902_IDS); do \
		v=$${id%%:*}; p=$${id#*:}; \
		grep -q "USB_DEVICE($$v, $$p)" $(BUILD)/btusb.c && continue; \
		sed -i "/Realtek Bluetooth devices \*\//i\\	{ USB_DEVICE($$v, $$p), .driver_info = BTUSB_MEDIATEK |\n\t\t\t\t\t\t     BTUSB_WIDEBAND_SPEECH },  /* MT7902 */" $(BUILD)/btusb.c; \
	done
	# Kernels with the hci_dev quirk_flags rework (6.17, and distribution
	# kernels that backported it, e.g. Ubuntu's 6.14) have no hdev->quirks.
	if grep -qs 'define hci_set_quirk' $(KSRC)/include/net/bluetooth/hci_core.h; then \
		sed -E -i 's/\b(set|clear|test)_bit\((HCI_QUIRK_[A-Z0-9_]+), *&([a-z_>.-]+)->quirks\)/hci_\1_quirk(\3, \2)/g' \
			$(BUILD)/btusb.c $(BUILD)/btmtk.c; \
	fi
	printf '%s\n' 'obj-m += btusb.o btmtk.o' \
		'ccflags-y += -DCONFIG_BT_HCIBTUSB_MTK=1 $(COMPAT_INC)' > $(BUILD)/Kbuild

clean:
	rm -rf $(BUILD) $(PKGDIR)/btusb.ko $(PKGDIR)/btmtk.ko

.PHONY: all prepare clean
