# SPDX-License-Identifier: BSD-3-Clause-Clear

obj-m += mt76x2_common_git.o
obj-m += mt76x2u_git.o

ifneq ($(CONFIG_PCI),)
obj-m += mt76x2e_git.o
endif

mt76x2_common_git-y := \
	eeprom.o mac.o init.o phy.o mcu.o

mt76x2e_git-y := \
	pci.o pci_main.o pci_init.o pci_mcu.o \
	pci_phy.o

mt76x2u_git-y := \
	usb.o usb_init.o usb_main.o usb_mac.o usb_mcu.o \
	usb_phy.o
