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
