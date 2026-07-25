<#
.SYNOPSIS
Build the SAMV71 tock-bootloader and regenerate the flashable .bin.

.DESCRIPTION
`cargo build` only ever writes an ELF into target/. The image that actually
gets flashed -- and that is committed to git -- is ./samv71xplained-bootloader.bin
in this directory, produced by objcopy. Running cargo directly refreshes the
ELF and silently leaves that .bin stale; that is exactly how the repo ended up
with a Jun 23 .bin sitting next to a Jul 10 ELF.

This script does both steps as one operation, so the two cannot drift apart.
Use it instead of `cargo build --release`.

The objcopy flags match boards/Common.mk (OBJCOPY_FLAGS) so this produces a
byte-identical image to `make release`.

.EXAMPLE
.\build.ps1
#>
[CmdletBinding()]
param(
    # Skip the cargo build and only re-run objcopy on the existing ELF.
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Platform = 'samv71xplained-bootloader'
$Target   = 'thumbv7em-none-eabihf'
$BoardDir = $PSScriptRoot
$Elf      = Join-Path $BoardDir "target\$Target\release\$Platform"
$Bin      = Join-Path $BoardDir "$Platform.bin"

Push-Location $BoardDir
try {
    # ---- 1. Build -----------------------------------------------------------
    if (-not $NoBuild) {
        Write-Host "  CARGO     building $Platform (release)" -ForegroundColor Cyan
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
    }

    if (-not (Test-Path $Elf)) { throw "ELF not found: $Elf" }

    # ---- 2. Locate llvm-objcopy --------------------------------------------
    # Shipped by the rustup `llvm-tools` component; path moves with the
    # toolchain, so discover it rather than hard-coding a version.
    $sysroot = (rustc --print sysroot).Trim()
    $objcopy = Get-ChildItem -Path (Join-Path $sysroot 'lib\rustlib') `
                             -Filter 'llvm-objcopy.exe' -Recurse -ErrorAction SilentlyContinue |
               Select-Object -First 1 -ExpandProperty FullName
    if (-not $objcopy) {
        throw "llvm-objcopy not found under $sysroot. Install it with: rustup component add llvm-tools"
    }

    # ---- 3. objcopy ---------------------------------------------------------
    # Flags mirror OBJCOPY_FLAGS in boards/Common.mk:
    #   --strip-sections   keep the image from ballooning when SRAM is below flash
    #   --strip-all        drop non-allocated sections outside segments
    #   --remove-section .apps   .apps is an ELF-only placeholder for appended apps
    $prevHash = if (Test-Path $Bin) { (Get-FileHash $Bin -Algorithm SHA256).Hash } else { $null }

    & $objcopy --output-target=binary --strip-sections --strip-all --remove-section .apps $Elf $Bin
    if ($LASTEXITCODE -ne 0) { throw "llvm-objcopy failed (exit $LASTEXITCODE)" }

    # ---- 4. Report ----------------------------------------------------------
    $size = (Get-Item $Bin).Length
    $hash = (Get-FileHash $Bin -Algorithm SHA256).Hash
    Write-Host "  BIN       $Platform.bin  $size bytes" -ForegroundColor Green
    Write-Host "  SHA256    $hash"

    if ($null -eq $prevHash) {
        Write-Host "  NOTE      .bin created (did not exist before)" -ForegroundColor Yellow
    } elseif ($prevHash -ne $hash) {
        Write-Host "  CHANGED   .bin differs from the previous build - commit it" -ForegroundColor Yellow
    } else {
        Write-Host "  UNCHANGED .bin is identical to the previous build"
    }

    Write-Host ""
    Write-Host "Flash with: JLink.exe -device ATSAMV71Q21B -if SWD -speed 4000 -CommandFile ..\..\..\flash_bootloader_kernel.jlink"
}
finally {
    Pop-Location
}
