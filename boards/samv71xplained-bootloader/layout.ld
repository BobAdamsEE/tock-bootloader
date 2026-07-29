MEMORY
{
  /* Bootloader occupies the first 64 KB of flash (aliased at 0x00000000).
     Only ~24 KB is used today. The rest is reserved deliberately: adding
     signature verification later costs about 12 KB, and growing this region
     after the fact would move the kernel, which is the one change that cannot
     be deployed over CAN or UART -- the bootloader doing the update is the
     thing being replaced. Reserving now makes that a drop-in bootloader swap.
     See the design document, section 14. */
  rom  (rx)  : ORIGIN = 0x00000000, LENGTH = 64K

  /* Kernel image starts immediately after the bootloader. */
  prog (rx)  : ORIGIN = 0x00010000, LENGTH = 1984K

  /* SAMV71Q21B internal SRAM: 384 KB at 0x20400000–0x2045FFFF.
     Reserve the last 16 bytes for the double-reset scratch word. */
  ram  (rwx) : ORIGIN = 0x20400000, LENGTH = 384K - 16

  /* 16-byte retained region at the very top of SRAM.
     Survives soft resets without any extra configuration. */
  retained (rwx) : ORIGIN = 0x2045FFF0, LENGTH = 0x10
}

MPU_MIN_ALIGN = 8K;
PAGE_SIZE     = 512;

/* Put the attribute table in the last 8 KB erase block of the bootloader
   region, on its own.

   The EFC erases 16 pages (8 KB) at a time, so rewriting the table at its
   conventional 0x400/0x600 would erase the vector table and the first pages of
   .text -- the code doing the erasing. Measured: the instruction cache carries
   execution just far enough to write one page back, then the board is gone and
   needs a debugger. Section 13.11 of the design document has the evidence.

   0xE000 leaves 56 KB for code (29 KB used today, and section 14 wants about
   12 KB more for signature verification), and its block 0xE000-0xFFFF holds
   nothing but this table. */
ATTRIBUTE_TABLE_ADDR = 0x0000E000;

INCLUDE ../kernel_layout.ld

SECTIONS
{
  /* Place retained/noinit variables in the reserved top-of-SRAM region. */
  .retained (NOLOAD) :
  {
    KEEP(*(.retained .retained.* .noinit .noinit.*))
    . = ALIGN(4);
  } > retained
}
