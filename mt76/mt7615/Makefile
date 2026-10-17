# SPDX-License-Identifier: BSD-3-Clause-Clear

ccflags-y += -DCONFIG_MT76_LEDS

obj-m += mt7615_common_git.o

ifneq ($(CONFIG_PCI),)
obj-m += mt7615e_git.o
endif

obj-m += mt7663_usb_sdio_common_git.o
obj-m += mt7663u_git.o

ifneq ($(CONFIG_MMC),)
obj-m += mt7663s_git.o
endif

CFLAGS_trace.o := -I$(src)

mt7615_common_git-y := main.o init.o mcu.o eeprom.o mac.o \
		       debugfs.o trace.o
mt7615_common_git-$(CONFIG_NL80211_TESTMODE) += testmode.o

mt7615e_git-y := pci.o pci_init.o dma.o pci_mac.o mmio.o
mt7615e_git-$(CONFIG_MT7622_WMAC) += soc.o

mt7663_usb_sdio_common_git-y := usb_sdio.o
mt7663u_git-y := usb.o usb_mcu.o
mt7663s_git-y := sdio.o sdio_mcu.o
