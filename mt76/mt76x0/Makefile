# SPDX-License-Identifier: GPL-2.0-only

obj-m += mt76x0_common_git.o
obj-m += mt76x0u_git.o

ifneq ($(CONFIG_PCI),)
obj-m += mt76x0e_git.o
endif

mt76x0_common_git-y := init.o main.o eeprom.o phy.o

mt76x0u_git-y := usb.o usb_mcu.o
mt76x0e_git-y := pci.o pci_mcu.o
