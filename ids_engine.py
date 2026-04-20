from scapy.all import sniff, ARP, IP, TCP
from collections import defaultdict
from datetime import datetime
import threading
import database
import logging
import time

logger = logging.getLogger(__name__)

# --- Email cooldown ---
last_email_time = {}
EMAIL_COOLDOWN = 300  # 5 minutes

# --- Tracking dictionaries ---
port_scan_tracker = defaultdict(set)   # src_ip -> set of ports
ddos_tracker = defaultdict(int)        # src_ip -> packet count
arp_tracker = {}                       # ip -> mac

# --- Reset trackers every 5 minutes ---
def reset_trackers():
    global port_scan_tracker, ddos_tracker
    port_scan_tracker = defaultdict(set)
    ddos_tracker = defaultdict(int)
    threading.Timer(300, reset_trackers).start()

# --- Detection Logic ---
def analyze_packet(packet):
    try:
        # 1. Port Scan Detection
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            port_scan_tracker[src_ip].add(dst_port)
            ddos_tracker[src_ip] += 1

            if len(port_scan_tracker[src_ip]) >= 10:
                log_alert(src_ip, "Port Scan", "High", dst_ip, dst_port, "TCP")
                port_scan_tracker[src_ip].clear()

            # 2. DDoS Detection
            if ddos_tracker[src_ip] >= 100:
                log_alert(src_ip, "DDoS Attempt", "Critical", dst_ip, dst_port, "TCP")
                ddos_tracker[src_ip] = 0

        # 3. ARP Spoofing Detection
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            if src_ip in arp_tracker:
                if arp_tracker[src_ip] != src_mac:
                    log_alert(src_ip, "ARP Spoofing (MITM)", "Critical")
            else:
                arp_tracker[src_ip] = src_mac

    except Exception as e:
        logger.error(f"Error analyzing packet: {e}")

# --- Save alert to database ---
def log_alert(src_ip, attack_type, severity, dst_ip=None, dst_port=None, protocol=None):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.warning(f"[ALERT] {timestamp} | {attack_type} | {src_ip} | {severity}")
        database.insert_alert(timestamp, src_ip, attack_type, severity)

        # Send email for critical alerts with cooldown
        if severity == "Critical":
            current_time = time.time()
            last_time = last_email_time.get(src_ip, 0)
            if current_time - last_time > EMAIL_COOLDOWN:
                from app import send_email_alert
                send_email_alert(attack_type, src_ip, severity)
                last_email_time[src_ip] = current_time

    except Exception as e:
        logger.error(f"Error logging alert: {e}")

# --- Start sniffing ---
def start_ids():
    try:
        reset_trackers()
        logger.info("IDS: Starting packet capture...")
        sniff(prn=analyze_packet, store=False)
    except Exception as e:
        logger.error(f"IDS packet capture error: {e}")