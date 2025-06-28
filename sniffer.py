from scapy.all import sniff, IP
import csv
from datetime import datetime

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        with open("packets_log.csv", mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, protocol])

        print(f"[{timestamp}] {src_ip} -> {dst_ip} (Protocol: {protocol})")

# CSV headers
with open("packets_log.csv", mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol"])

print("🟢 Starting packet capture... Press CTRL+C to stop.")
sniff(prn=process_packet, store=False)
