Microchip SAMV71-Xplained Tock Bootloader
===================

This is the implementation of the Tock bootloader for the Microchip SAMV71-Xplained
board. The bootloader runs using the Debugger UART. It is a WIP as of Jan 2026.

Compiling
---------

To compile the bootloader, simply run the `make` command.

```
make
```

Flashing
--------

J-Link tools are required to flash the target. Openocd support may be added later

Entering
--------

Entering the bootloader is done by holding SW0 during reset.
