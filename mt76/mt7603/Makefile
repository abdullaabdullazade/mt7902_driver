# SPDX-License-Identifier: BSD-3-Clause-Clear
ccflags-y += -Werror -DCONFIG_MT76_LEDS

ifneq ($(CONFIG_PCI),)
obj-m += mt7603e_git.o
endif

mt7603e_git-y := \
	pci.o soc.o main.o init.o mcu.o \
	core.o dma.o mac.o eeprom.o \
	beacon.o debugfs.o
