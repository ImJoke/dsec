# SKILL: CTF Steganography (Stego)

## Description
Steganography methodology for CTF challenges involving hidden data in images, audio, video, and text.

## Trigger Phrases
stego, steganography, hidden, invisible, lsb, zsteg, steghide, spectrogram

## Methodology

### Image Steganography (PNG/JPG/BMP)
1. **Basic Analysis:**
   - `file <image>` and `exiftool <image>` to check metadata, copyright, or comments.
   - `strings <image> | grep -i flag` (check top and bottom of the output).
   - `binwalk -e <image>` or `foremost -i <image>` to extract embedded archives or hidden files.

2. **Visual/Color Analysis:**
   - Open in **Stegsolve** (Java tool). Flip through color planes (Red 0, Green 0, Blue 0) to find LSB modifications.
   - Look for QR codes or hidden text in specific bit planes.
   - Use Data Extract feature in Stegsolve for specific channels.

3. **LSB (Least Significant Bit) & Payloads:**
   - For PNG/BMP: `zsteg -a <image>` (checks all LSB, MSB, and common payloads).
   - For JPG: `steghide info <image>` and `steghide extract -sf <image>`. (May require a password; use `stegseek` to crack).
   - Other tools: `stegano`, `outguess`, `jphide`.

4. **Corrupt Headers/Chunks:**
   - `pngcheck -v <image>` to find CRC errors or hidden IDAT chunks.
   - Fix magic bytes using a hex editor (`xxd`, `hexeditor`) if the image won't open. (e.g., PNG must start with `89 50 4E 47 0D 0A 1A 0A`).

### Audio Steganography (WAV/MP3)
1. **Spectrogram Analysis:**
   - Open in **Audacity** or **Sonic Visualiser**.
   - Switch view from Waveform to **Spectrogram**. Look for drawn text or flags in the high/low frequencies.

2. **Phase Coding & LSB:**
   - Use `steghide` on WAV files.
   - Check if the audio contains Morse code or DTMF tones. (Use online decoders or scripts).

### Text/Whitespace Steganography
1. **Invisible Characters:**
   - Highlight text or use a hex editor to look for trailing spaces/tabs (`snow` steganography).
   - Zero-width characters: use Unicode decoders or scripts to extract binary from zero-width joiners/non-joiners.
2. **Esoteric languages:** Whitespace, Brainfuck, Malbolge.

## Tools
- `exiftool`, `binwalk`, `strings`, `xxd`
- `zsteg` (Ruby), `steghide`, `stegseek`
- **Stegsolve.jar**
- **Audacity**, `sox`
- `stegsnow` (for text)
