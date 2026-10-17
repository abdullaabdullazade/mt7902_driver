# SPDX-License-Identifier: BSD-3-Clause-Clear

ccflags-y += -DCONFIG_MT76_LEDS

ifneq ($(CONFIG_PCI),)
obj-m += mt7915e_git.o
endif

mt7915e_git-y := pci.o init.o dma.o eeprom.o main.o mcu.o mac.o \
		 debugfs.o mmio.o

mt7915e_git-$(CONFIG_NL80211_TESTMODE) += testmode.o
mt7915e_git-$(CONFIG_MT798X_WMAC) += soc.o
mt7915e_git-$(CONFIG_DEV_COREDUMP) += coredump.o
