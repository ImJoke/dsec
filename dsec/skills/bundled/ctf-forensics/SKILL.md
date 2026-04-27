# SKILL: CTF Forensics

## Description
Forensics analysis methodology for CTF challenges involving memory dumps, disk images, PCAPs, and document analysis.

## Trigger Phrases
forensics, pcap, wireshark, volatility, memory dump, disk image, autopsy, usb traffic

## Methodology

### Network Traffic Analysis (PCAP/PCAPNG)
1. **Initial inspection:** Open in Wireshark. Look at Protocol Hierarchy and Endpoints.
2. **Cleartext protocols:** Filter for `http`, `ftp`, `telnet`, `smtp`. Follow TCP/UDP streams to read conversations.
3. **File extraction:** File -> Export Objects -> HTTP/SMB/TFTP.
4. **USB traffic:** Filter for `usb.transfer_type == 0x01` (Interrupt) for keystrokes or mouse movements. Use tshark to extract `usb.capdata` and map to keyboard scancodes.
5. **TLS/SSL:** Look for SSLKEYLOGFILE or private keys provided in the challenge to decrypt traffic (Edit -> Preferences -> Protocols -> TLS).

### Memory Forensics (Volatility)
1. **Identify profile (Vol 2):** `volatility -f mem.dmp imageinfo` or `kdbgscan`. (For Vol 3: `vol.py -f mem.dmp windows.info`).
2. **Process list:** `pslist`, `psscan`, `pstree`. Look for suspicious processes (e.g., cmd.exe, powershell.exe, unknown binaries).
3. **Command line history:** `cmdline`, `consoles`, `cmdscan`.
4. **Network connections:** `netscan`.
5. **File extraction:** `filescan` (grep for flag, passwords, keys) -> `dumpfiles -Q <offset>`.
6. **Process dumping:** `procdump`, `memdump` -> run `strings` or `grep` on the dumped memory.
7. **Registry/Hashes:** `hivelist`, `hashdump`, `lsadump`.

### Disk Forensics
1. **Mounting:** Mount the image read-only or use Autopsy/Sleuthkit.
2. **File recovery:** `fls`, `icat`, `photorec`, `extundelete`. Look in recycle bins, unallocated space, and swap files.
3. **Linux artifacts:** `~/.bash_history`, `/var/log/*`, `/etc/shadow`.
4. **Windows artifacts:** Registry hives (SAM, SYSTEM, SOFTWARE), Prefetch, Amcache, Event Logs (.evtx), `$MFT`.

### Document Forensics
1. **PDFs:** `pdfid`, `pdf-parser`, `peepdf` to find hidden JavaScript, embedded files, or annotations.
2. **Office Docs:** Unzip `.docx`/`.xlsx` and grep `word/document.xml`. Use `olevba` or `maldoca` for malicious macros.

## Tools
- `wireshark`, `tshark`, `NetworkMiner`
- `volatility2`, `volatility3`
- `Autopsy`, `The Sleuth Kit (TSK)`
- `exiftool`, `binwalk` (for embedded files)
