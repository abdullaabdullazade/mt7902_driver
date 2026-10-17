# SPDX-License-Identifier: BSD-3-Clause-Clear

ccflags-y += -DCONFIG_MT76_LEDS

ifneq ($(CONFIG_PCI),)
obj-m += mt7996e_git.o
endif

mt7996e_git-y := pci.o init.o dma.o eeprom.o main.o mcu.o mac.o \
		 debugfs.o mmio.o

mt7996e_git-$(CONFIG_MT7996_NPU) += npu.o
mt7996e_git-$(CONFIG_DEV_COREDUMP) += coredump.o
