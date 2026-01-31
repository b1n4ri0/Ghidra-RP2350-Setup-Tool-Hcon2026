# Ghidra-RP2350-Setup-Tool-Hcon2026

## Project Overview

The `hcon26_rp2350-ctf_auto_setup.py` script is designed to automate the initial configuration and static analysis environment for firmware targeting the Raspberry Pi RP2350 (RISC-V Hazard3 core). This tool is specifically developed to support the reverse engineering tasks associated with the [**H-Con 2026 Hardware Hacking Challenge**](https://github.com/therealdreg/hcon2026hwctf).

Raw binary firmware inherently lacks the file headers and symbol tables required for automatic loading. This forces analysts to manually configure memory maps, entry points, and processor states before any code becomes readable. This tool automates that entire process, instantly preparing the binary for reverse engineering.

## Purpose

This script eliminates the manual setup overhead typically required for embedded firmware analysis. By automating the loading process, it ensures a consistent and functional Ghidra project, allowing participants to focus immediately on vulnerability research and logic analysis rather than environment configuration.

## Key Features

- **Automated Environment Configuration:** Instantly establishes the correct memory layout for the RP2350, defining the Flash (XIP) and SRAM regions with the appropriate permissions required by the decompiler.

- **Entry Point Detection:** Scans for RP2350-specific headers to identify the true execution start address, handling non-standard boot vectors often encountered in "On-RAM" compiled binaries.

- **Context Resolution:** Automatically initializes the Global Pointer `gp` register. This ensures that references to global variables and static data are correctly resolved in the decompiler, rather than appearing as broken offsets.

- **Data Section Reconstruction:** Identifies and relocates initialized sections from Flash to RAM, replicating the boot process. This ensures that string literals and global variables appear in their correct memory locations during analysis.

- **Symbol Recovery:** Heuristically identifies the main application logic and the runtime initialization sequence, allowing the analyst to jump directly to the user code without tracing the entire bootloader manually.


## Installation

1. Download this repository or the `con26_rp2350-ctf_auto_setup.py` file directly.

```bash
git clone https://github.com/b1n4ri0/Ghidra-RP2350-Setup-Tool-Hcon2026.git 
```

2. Copy the script file into the `ghidra_scripts` directory of your Ghidra installation.

```bash
cd Ghidra-RP2350-Setup-Tool-Hcon2026

cp hcon26_rp2350-ctf_auto_setup.py $GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/ghidra_scripts
```

## Usage

1. Import the target `.bin` file into Ghidra (RV32).

2. Open the file in the `Code Browser`.

3. **Auto-Analysis:** When prompted to analyze the file, select `No`.

4. Open the Script Manager `Window > Script Manager`.

5. Search for `hcon26_rp2350-ctf_auto_setup.py` located in the `RP2350` category.

6. Run the script and wait for the console output to confirm completion. Be sure to read the `Next Steps` information displayed in the console.

7. After the setup script finishes, execute the **RP2350 SVD Loader** to map hardware registers and peripherals. 
    * **RP2350 SVD Loader**: https://github.com/b1n4ri0/SVD-Loader-PyGhidra-RP2350