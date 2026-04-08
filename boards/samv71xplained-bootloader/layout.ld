MEMORY
{
  rom (rx)  : ORIGIN = 0x00000000, LENGTH = 32K
  prog (rx) : ORIGIN = 0x00008000, LENGTH = 2016K

  /* Standard system SRAM – full 384 KB available by default */
  ram (rwx) : ORIGIN = 0x20000000, LENGTH = 384K - 16   /* reserve last 16 bytes */

  /* Small retained region at the very top of physical SRAM */
  /* → survives soft resets (no extra config needed for main SRAM on soft reset) */
  /* → safe from typical stack growth (which starts lower and grows downward) */
  retained (rwx) : ORIGIN = 0x2005FFF0, LENGTH = 0x10   /* 16 bytes: 0x2005FFF0 → 0x2005FFFF */
}

MPU_MIN_ALIGN = 8K;
PAGE_SIZE     = 4K;

INCLUDE ../kernel_layout.ld

/* Add this SECTIONS block at the end (or in a separate included file if preferred) */
SECTIONS
{
  /* Place any retained/noinit variables here */
  .retained (NOLOAD) :
  {
    KEEP(*(.retained .retained.* .noinit .noinit.*))   /* catch variables with __attribute__((section(".retained"))) or .noinit */
    . = ALIGN(4);

    /* Optional: define symbols for easy access in code */
    __retained_start = .;
    /* Example placeholder for double-reset flag (u32 + optional padding/magic) */
    . = . + 4;   /* reserve 4 bytes for the flag itself */
    __double_reset = . - 4;
    . = ALIGN(4);
    __retained_end = .;
  } > retained
}