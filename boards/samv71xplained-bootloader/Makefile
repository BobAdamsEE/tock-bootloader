# Makefile for building the Tock bootloader for SAMV71 platforms using CDC-ACM
# over USB.

TOCK_ARCH=cortex-m7
TARGET=thumbv7em-none-eabihf
PLATFORM=samv71xplained-bootloader

include ../Common.mk

TOCKLOADER=tockloader


# 2026-01-27 Commented out, not planning on using for now
# OPENOCD=openocd
# OPENOCD_OPTIONS=-f openocd.cfg

# Upload the kernel over JTAG
# .PHONY: flash
# flash: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/release/$(PLATFORM).bin
# 	$(OPENOCD) $(OPENOCD_OPTIONS) -c "program $<; verify_image $<; reset halt; shutdown;"

# .PHONY: flash
# flash-debug: $(TOCK_ROOT_DIRECTORY)target/$(TARGET)/debug/$(PLATFORM).bin
# 	$(OPENOCD) $(OPENOCD_OPTIONS) -c "program $<; verify_image $<; reset halt; shutdown;"
