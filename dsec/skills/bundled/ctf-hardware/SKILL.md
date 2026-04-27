# SKILL: CTF Hardware / IoT / RF

## Description
Methodology for hardware-based CTF challenges, including firmware analysis, UART/JTAG debugging, logic analyzers, and SDR.

## Trigger Phrases
hardware, iot, firmware, binwalk, uart, jtag, spi, i2c, sdr, gqrx, logic analyzer, saleae

## Methodology

### Firmware Analysis
1. **Extraction:**
   - `binwalk -e <firmware.bin>` to extract file systems (SquashFS, JFFS2).
   - If encrypted/compressed, look for entropy (`binwalk -E`).
2. **Analysis:**
   - Run `firmwalker` on the extracted file system to find hardcoded passwords, keys, and certificates.
   - Look for web servers (lighttpd, httpd) and analyze their CGI binaries using Ghidra.
3. **Emulation:**
   - Use `firmadyne` or `qemu-user-static` combined with `chroot` to run the binaries locally.
   - Example: `cp /usr/bin/qemu-arm-static squashfs-root/ && sudo chroot squashfs-root /bin/sh`.

### Hardware Interfaces (UART, SPI, I2C, JTAG)
1. **UART (Serial):**
   - Identify TX, RX, GND. Connect via FTDI adapter.
   - Find baud rate (common: 9600, 115200) using a logic analyzer or brute force.
   - Connect: `screen /dev/ttyUSB0 115200` or `minicom`. Look for U-Boot prompts or root shells.
2. **SPI / I2C:**
   - Often used to communicate with EEPROM/Flash chips.
   - Use `flashrom` with a bus pirate or CH341A programmer to dump the memory: `flashrom -p ch341a_spi -r dump.bin`.
3. **JTAG:**
   - Look for 4-5 pin headers (TDI, TDO, TCK, TMS, TRST).
   - Use `OpenOCD` or `Jlink` to pause execution, read memory, and extract firmware directly from the MCU.

### Logic Analyzers (Saleae / PulseView)
1. Open `.sal` or `.sr` files in Saleae Logic or PulseView.
2. Apply protocol decoders (UART, I2C, SPI) to the channels.
3. Export decoded data and search for flags or passwords.

### Software Defined Radio (SDR)
1. **Analysis:** Open `.wav`, `.cfile`, or `.iq` in **Inspectrum** or **Gqrx**.
2. **Modulation:** Identify modulation (OOK, FSK, PSK). Look for repeating preambles.
3. **Decoding:** Use `Universal Radio Hacker (URH)` to demodulate, find bit lengths, and decode Manchester or NRZ encodings to binary.

## Tools
- `binwalk`, `qemu-user-static`, `firmwalker`
- `flashrom`, `OpenOCD`
- **PulseView** / **Saleae Logic** (for `.sal` captures)
- `Universal Radio Hacker (URH)`, `Inspectrum`
