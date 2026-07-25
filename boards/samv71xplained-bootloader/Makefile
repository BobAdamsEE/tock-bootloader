# Makefile for building the Tock bootloader for SAMV71 platforms using CDC-ACM
# over USB.

TOCK_ARCH=cortex-m7
TARGET=thumbv7em-none-eabihf
PLATFORM=samv71xplained-bootloader

# Build into this board's own target/ rather than the repo-root one, so that
# `make` and a bare `cargo build --release` share artifacts instead of
# maintaining two separate multi-GB build trees. Must have a trailing slash --
# Common.mk builds TARGET_PATH by direct concatenation.
TARGET_DIRECTORY := $(abspath .)/target/

include ../Common.mk

# Keep the committed, flashable image in sync with every build.
#
# flash_bootloader_kernel.jlink loads ./$(PLATFORM).bin, and that file is what
# gets committed -- but cargo only ever writes into target/, so building
# refreshes the ELF and leaves the .bin untouched. That is how this repo ended
# up with a Jun 23 .bin next to a Jul 10 ELF. Making the copy the default goal
# means the two cannot drift apart.
#
# NOTE: there is no `make` on the Windows side of this project; use build.ps1
# there, which performs the identical objcopy (same OBJCOPY_FLAGS) and so
# produces a byte-identical image.
.DEFAULT_GOAL := flashable

.PHONY: flashable
flashable: $(PLATFORM).bin

$(PLATFORM).bin: $(TARGET_PATH)/release/$(PLATFORM).bin
	$(Q)cp $< $@
	@echo "  BIN       $@ (flashable image, commit this)"

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
