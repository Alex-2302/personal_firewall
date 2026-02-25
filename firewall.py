from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
import logging

# Setup logging
logging.basicConfig(filename="firewall.log",
                    level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# Load rules
with open("rules.json") as f:
    rules = json.load(f)

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check blocked IP
        if src_ip in rules["blocked_ips"]:
            logging.warning(f"Blocked IP detected: {src_ip}")
            print(f"[BLOCKED IP] {src_ip}")
            return

        # Check protocol
        if ICMP in packet and "ICMP" in rules["blocked_protocols"]:
            logging.warning("Blocked ICMP packet")
            print("[BLOCKED PROTOCOL] ICMP")
            return

        # Check ports
        if TCP in packet:
            if packet[TCP].dport in rules["blocked_ports"]:
                logging.warning(f"Blocked TCP port {packet[TCP].dport}")
                print(f"[BLOCKED PORT] {packet[TCP].dport}")
                return

        print(f"[ALLOWED] {src_ip} → {dst_ip}")

sniff(prn=process_packet, store=False)
