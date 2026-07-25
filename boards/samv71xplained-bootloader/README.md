Microchip SAMV71-Xplained Tock Bootloader
===================

This is the implementation of the Tock bootloader for the Microchip SAMV71-Xplained
board. The bootloader runs using the Debugger UART. It is a WIP as of Jan 2026.

Compiling
---------

On Windows (the primary build environment for this port), run:

```
.\build.ps1
```

Under WSL/Linux, `make` does the same thing:

```
make
```

Both build the ELF **and** regenerate `samv71xplained-bootloader.bin` in this
directory using identical objcopy flags, so they produce a byte-identical image.

Do **not** build with a bare `cargo build --release`. Cargo only writes an ELF
into `target/`; the flashable `.bin` in this directory is produced by objcopy as
a separate step. Running cargo alone refreshes the ELF and silently leaves the
`.bin` stale — which is how this repo once ended up with a three-week-old `.bin`
sitting next to a fresh ELF.

Note that this board depends on the Tock chip crate at
`../../../tock/chips/samv71q21b`, so changes over there change this binary too.

The `.bin` is committed to git because `flash_bootloader_kernel.jlink` loads it
directly. Commit it whenever the build reports `CHANGED`.

Flashing
--------

J-Link tools are required to flash the target. Openocd support may be added later

Entering
--------

Entering the bootloader is done by holding SW0 during reset.
