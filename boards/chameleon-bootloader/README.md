Chameleon Tock Bootloader
=========================

Bootloader for the Chameleon board (PCA-0001-01). **This is a draft.** It builds
against `tock-2.3`, but nothing here has run on Chameleon hardware.

The boot-entry logic is shared with the Xplained board through
`chips/bootloader_samv71/src/entry.rs`, as is the flash adapter. This board's
`main.rs` holds its wiring and policy.

Differences from `samv71xplained-bootloader`
--------------------------------------------

| | Xplained Ultra | Chameleon |
|---|---|---|
| Crystal | 12 MHz | 20 MHz |
| Early pin setup | LED only | `safe_state`: `MAIN_HOLD` on, U17 off, every load off |
| Servers | tockloader on UART, UDS on CAN | UDS on CAN B only |
| Double reset | 500 ms | off: there is no reset button |
| CAN knock | 100 ms | 100 ms, until `FLASH_EN` is proven |
| `FLASH_EN` | PE3, internal pull-up, not wired | PE3, J1 pin 22, R54 pull-up |
| Activity LED | PC9 | none |

There is no UART here, because USART1's pins are LIN A. A board that cannot be
reached over CAN needs SWD on J2.

Compiling
---------

On Windows run `.\build.ps1`; under WSL or Linux run `make`. Both build the ELF
and regenerate `chameleon-bootloader.bin`. A bare `cargo build --release` leaves
the `.bin` stale.

Flashing
--------

From this directory:

```
JLink.exe -device ATSAMV71Q21B -if SWD -speed 4000 -CommandFile flash.jlink
```

To check on the first board
---------------------------

* Time from power-up to `WD_SET0` high, against U17's 92.7 ms. A failure here
  looks like a board that resets by itself and never reaches the kernel.
* `FLASH_EN` with a 9 V battery on J1 pin 22, positive terminal to ground. PE3
  must read below VIL and hold there for `FLASH_EN_HOLD_MS`. With R54 at 10k the
  divider only reaches about 1.14 V, so measure this before trusting it.
* `FLASH_EN` with J1 pin 22 open and with it grounded: PE3 must read high.
* Then set `CAN_ENTRY_WINDOW_MS` to 0.

Known gap
---------

A bootloader that stays resident holds `MAIN_HOLD` until the 12 V supply goes,
and nothing times it out. That is fine on a bench, and wrong in a parked car.
