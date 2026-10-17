# SPDX-License-Identifier: BSD-3-Clause-Clear

obj-m += mt7921_common_git.o

ifneq ($(CONFIG_PCI),)
obj-m += mt7921e_git.o
endif

ifneq ($(CONFIG_MMC),)
obj-m += mt7921s_git.o
endif

obj-m += mt7921u_git.o

mt7921_common_git-y := mac.o mcu.o regd.o main.o init.o debugfs.o
mt7921_common_git-$(CONFIG_NL80211_TESTMODE) += testmode.o
mt7921e_git-y := pci.o pci_mac.o pci_mcu.o
mt7921s_git-y := sdio.o sdio_mac.o sdio_mcu.o
mt7921u_git-y := usb.o
