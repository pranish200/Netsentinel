# NetSentinel IDS
### Network Intrusion Detection System
Built by praanishh (0xPRX)

## Features
- Real-time Port Scan, DDoS, ARP Spoofing detection
- WiFi Threat Scanner via NodeMCU ESP8266
- Email alerts with cooldown
- IP Geolocation Map
- Block IP via Windows Firewall
- PDF Export
- Login Page
- Statistics Dashboard

## Installation

### Requirements
- Python 3.10 or 3.11 (NOT 3.13)
- Npcap installed (https://npcap.com/#download)
- Windows OS

### Steps
1. Clone or download this project
2. Install dependencies:
   pip install -r requirements.txt
3. Run as Administrator:
   python app.py
4. Open browser:
   http://127.0.0.1:5000
5. Login with:
   Username: admin
   Password: admin123

## NodeMCU Setup
1. Flash the Arduino code from nodemcu/wifi_scanner.ino
2. Update WiFi credentials and PC IP in the code
3. Upload to NodeMCU ESP8266

## Tech Stack
- Python, Flask, Scapy, SQLite
- Chart.js, OpenStreetMap
- Arduino, ESP8266