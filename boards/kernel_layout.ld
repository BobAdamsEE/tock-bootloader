/*
 * This is the generic linker script for Tock. For most developers, it should
 * be sufficient to define {ROM/RAM}_{ORIGIN/LENGTH} (6 variables, the
 * start and length for each) and MPU_MIN_ALIGN (the minimum alignment
 * granularity supported by the MPU).
 *
 * --------------------------------------------------------------------------
 *
 * If you wish to create your own linker script from scratch, you must define
 * the following symbols:
 *
 * `_etext`, `_srelocate`, `_erelocate`
 *    The `_etext` symbol marks the end of data stored in flash that should
 *    stay in flash. `_srelocate` and `_erelocate` mark the address range in
 *    SRAM that mutable program data is copied to.
 *
 *    Tock will copy `_erelocate` - `_srelocate` bytes of data from the
 *    `_etext` pointer to the `_srelocate` pointer.
 *
 * `_szero`, `_ezero`
 *
 *    The `_szero` and `_ezero` symbols define the range of the BSS, SRAM that
 *    Tock will zero on boot.
 */


SECTIONS
{
    .stack (NOLOAD) :
    {
        /* Kernel stack.
         *
         * Tock places the kernel stack at the bottom of SRAM so that the
         * kernel will trigger memory fault if it exceeds its stack depth,
         * rather than silently overwriting valuable data.
         */
        . = ALIGN(8);
         _sstack = .;

         /* For GNU LD, we can just advance the location pointer (".") here to
          * reserve space for the stack. That, however, doesn't seem to work
          * for LLVM LLD. The resulting ELF has a stack section that shows the
          * correct size, but the next section (in our case .relocate) is not
          * moved down as well, instead it sits at the same address as .stack.
          * To work around this, we declare a dummy buffer and then insert it
          * here in the .stack section. This sets the stack size correctly and
          * places the .relocate section at the correct address. */
         KEEP(*(.stack_buffer))
         /*. = . + 0x1000;*/  /*This is the original method. */

         . = ALIGN(8);
         _estack = .;
    } > ram

    /* STATIC ELEMENTS FOR TOCK KERNEL */
    .vector_table :
    {
        . = ALIGN(4);
        _textstart = .;     /* Symbol expected by some MS build toolchains */
        _stext = .;         /* First of standard s,e (start/end) pair */

        /* Place vector table at the beginning of ROM.
         *
         * The first 16 entries in the ARM vector table are defined by ARM and
         * are common among all ARM chips. The remaining entries are
         * chip-specific, which Tock defines in a separate .irqs section
         *
         * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0553a/BABIFJFG.html
         */
        KEEP(*(.vectors .vectors.*))
        KEEP(*(.irqs))
    } > rom

    .attribute :
    {
        . = ALIGN(1024);
        _attribute_table_start = .;
        _flags_address = .;
        KEEP(*(.flags))
        /* Start attributes on next page */
        FILL(0x0)
        . = _attribute_table_start + 512;
        _attributes_address = .;
        /* Remaining attributes */
        KEEP(*(.attributes .attribute.*))
        FILL(0x0)
        /* This end address needs to be large enough that attributes are
           on a different page than the start of .text. */
        . = _attribute_table_start + 3072;
    } > rom

    .text :
    {
        /* .text and .rodata hold most program code and immutable constants */
        /* .gnu.linkonce hold C++ elements with vague linkage
                https://gcc.gnu.org/onlinedocs/gcc/Vague-Linkage.html */
        *(.text .text.* .gnu.linkonce.t.*)
        *(.rodata .rodata* .gnu.linkonce.r.*)

        /* C++ exception unwinding information */
        *(.ARM.extab* .gnu.linkonce.armextab.*)

        /* glue_7 and glue_7t hold helper functions emitted by the compiler to
           support interworking (linking between functions in ARM and THUMB
           mode). Note that Cortex-M's do not support ARM mode, but this is left
           here to save someone headache if they ever attempt to port Tock to a
           Cortex-A core.  */
        *(.glue_7t) *(.glue_7)


        /* Constructor and destructor sections:

           - init/fini
              Defined by ELF as sections that hold `process
              initialization/termination code`
           - {pre}{init/fini}_array_{start/end}
              Symbols used by the C runtime for initialization / termination
           - ctors/dtors
              Symbols used by the C++ runtime for initialization / termination
        */
        . = ALIGN(4);
        KEEP(*(.init))
        . = ALIGN(4);
        __preinit_array_start = .;
        KEEP (*(.preinit_array))
        __preinit_array_end = .;

        . = ALIGN(4);
        __init_array_start = .;
        KEEP (*(SORT(.init_array.*)))
        KEEP (*(.init_array))
        __init_array_end = .;

        . = ALIGN(4);
        KEEP (*crtbegin.o(.ctors))
        KEEP (*(EXCLUDE_FILE (*crtend.o) .ctors))
        KEEP (*(SORT(.ctors.*)))
        KEEP (*crtend.o(.ctors))

        . = ALIGN(4);
        KEEP(*(.fini))

        . = ALIGN(4);
        __fini_array_start = .;
        KEEP (*(.fini_array))
        KEEP (*(SORT(.fini_array.*)))
        __fini_array_end = .;

        KEEP (*crtbegin.o(.dtors))
        KEEP (*(EXCLUDE_FILE (*crtend.o) .dtors))
        KEEP (*(SORT(.dtors.*)))
        KEEP (*crtend.o(.dtors))
        /* End constructor/destructor */
    } > rom


    /* ARM Exception support
     *
     * This contains compiler-generated support for unwinding the stack,
     * consisting of key-value pairs of function addresses and information on
     * how to unwind stack frames.
     * https://wiki.linaro.org/KenWerner/Sandbox/libunwind?action=AttachFile&do=get&target=libunwind-LDS.pdf
     *
     * .ARM.exidx is sorted, so has to go in its own output section.
     */
    PROVIDE_HIDDEN (__exidx_start = .);
    .ARM.exidx :
    {
      /* (C++) Index entries for section unwinding */
      *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > rom
    PROVIDE_HIDDEN (__exidx_end = .);

    /* Region for on-chip kernel non-volatile storage.
     * Align on 512 bytes since that is the page size.
     * Volumes within this region are allocated with the
     * storage_volume! macro in utils.rs. */
    . = ALIGN(512);
    .storage :
    {
      _sstorage = .;
      *(.storage* storage*)
      _estorage = .;
      . = ALIGN(512);
    } > rom
    . = ALIGN(512);

    /* Mark the end of static elements */
    . = ALIGN(4);
    _etext = .;
    _textend = .;   /* alias for _etext expected by some MS toolchains */


    /* Customer configuration is most often located
     * at the end of the rom. It is conditional, and won't
     * be written if not specified in the board specific linker
     * file. */
    .ccfg : {
        KEEP(*(.ccfg))
    } > ccfg



    /* Kernel data that must be relocated. This is program data that is
     * expected to live in SRAM, but is initialized with a value. This data is
     * physically placed into flash and is copied into SRAM by Tock. The
     * symbols here will be defined with addresses in SRAM.
     *
     * Tock assumes the relocation section follows all static elements and will
     * copy (_erelocate - _srelocate) bytes from _etext to _srelocate.
     */
    .relocate :
    {
        . = ALIGN(4);
        _srelocate = .;
        *(.ramfunc .ramfunc.*);
        *(.data .data.*);

        . = ALIGN(4);
        _erelocate = .;
    } > ram AT > rom



    .sram (NOLOAD) :
    {
        /* Kernel BSS section. Memory that is expected to be initialized to
         * zero.
         *
         * Elements in this section do not contribute to the binary size. Tock
         * initialization will write zeros to the memory between _szero and
         * _ezero.
         *
         * Elements placed in the .bss and .COMMON sections are simply used to
         * measure amount of memory to zero out.
         */
        . = ALIGN(4);
        _szero = .;

        *(.bss .bss.*)
        *(COMMON)

        . = ALIGN(4);
        _ezero = .;
    } > ram


    /* Attribute table, relocated out of the image's own erase block.
     *
     * Opt-in, and off unless a board defines ATTRIBUTE_TABLE_ADDR. Boards that
     * do not define it are completely unaffected: no input section matches, no
     * space is reserved, and the table stays at 0x400/0x600 as before.
     *
     * Why a board would want this. Erasing flash takes a whole block with it --
     * 8 KB on the SAMV71 -- so a table the running image has to *rewrite* cannot
     * share a block with that image's code. The default position at 0x400 does
     * share one: erasing it deletes the code performing the erase, which on the
     * SAMV71 leaves a board that needs a debugger. A board that wants its
     * attributes writable at runtime therefore puts them somewhere with nothing
     * else in the block, and uses .flags_relocated / .attributes_relocated
     * instead of .flags / .attributes.
     *
     * Placed after .relocate on purpose. `_etext` marks where the initialised
     * data image starts, and Tock copies from there at boot, so nothing may be
     * inserted between the two -- this section goes after both and takes an
     * absolute address of its own.
     */
    .attribute_relocated (DEFINED(ATTRIBUTE_TABLE_ADDR) ? ATTRIBUTE_TABLE_ADDR : .) :
    {
        _relocated_table_start = .;
        _relocated_flags_address = .;
        KEEP(*(.flags_relocated))
        FILL(0x0)
        /* Attributes start on the page after the flags, as at 0x400/0x600. */
        . = DEFINED(ATTRIBUTE_TABLE_ADDR) ? _relocated_table_start + 512 : .;
        _relocated_attributes_address = .;
        KEEP(*(.attributes_relocated))
        FILL(0x0)
        /* Room for all 16 records, so an unwritten slot reads as zeroes rather
           than as whatever follows. */
        . = DEFINED(ATTRIBUTE_TABLE_ADDR) ? _relocated_table_start + 1536 : .;
    } > rom
}
