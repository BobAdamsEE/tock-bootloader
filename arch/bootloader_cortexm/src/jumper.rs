pub struct CortexMJumper {}

impl CortexMJumper {
    pub fn new() -> CortexMJumper {
        CortexMJumper {}
    }
}

impl bootloader::interfaces::Jumper for CortexMJumper {
    fn jump(&self, address: u32) -> ! {
        use core::arch::asm;
        // VTOR register: SCB offset 0x8 within SCS at 0xE000E000.
        // Pass as a register input to avoid GNU-as pseudo-instructions (ldr =addr)
        // which are not supported by LLVM's integrated assembler.
        let vtor: u32 = 0xe000_ed08;
        let addr = address;
        unsafe {
            asm!(
                "str {addr}, [{vtor}]",     // VTOR = payload vector table address
                "ldr {vtor}, [{addr}]",     // load payload initial SP
                "mov sp, {vtor}",
                "ldr {addr}, [{addr}, #4]", // load payload entry point
                "bx  {addr}",
                addr = inout(reg) addr => _,
                vtor = inout(reg) vtor => _,
                options(nostack),
            );
        }
        unreachable!()
    }
}
