extern crate bootloader_attributes;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed=../kernel_layout.ld");

    // Emit the same link args that Common.mk would pass via RUSTFLAGS so that
    // `cargo build` works without the Makefile wrapper.
    let board_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rustc-link-arg=-L{}", board_dir.display());
    println!("cargo:rustc-link-arg=-Tlayout.ld");
    println!("cargo:rustc-link-arg=-nmagic");
    println!("cargo:rustc-link-arg=-icf=all");

    let mut f = bootloader_attributes::get_file();
    let version = if let Ok(v) = env::var("BOOTLOADER_VERSION") {
        v
    } else {
        String::from("1.1.3")
    };
    // _flags_address is where the bootloader writes its flag page; 0x8000 is
    // the kernel start address stored in the flags page so the jumper knows
    // where to jump.
    bootloader_attributes::write_flags(&mut f, &version, 0x8000);
    bootloader_attributes::write_attribute(&mut f, "board", "samv71xplained");
    bootloader_attributes::write_attribute(&mut f, "arch", "cortex-m7");
    bootloader_attributes::write_attribute(&mut f, "appaddr", "0x40000");
    if let Ok(h) = env::var("BOOTLOADER_HASH") {
        bootloader_attributes::write_attribute(&mut f, "boothash", &h);
    }
    if let Ok(h) = env::var("BOOTLOADER_KERNEL_HASH") {
        bootloader_attributes::write_attribute(&mut f, "kernhash", &h);
    }
}
