from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def analyze_packet(packet):
    print("\n--- Packet Captured ---")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        # Detect protocol
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Src Port: {tcp_layer.sport} | Dst Port: {tcp_layer.dport}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Src Port: {udp_layer.sport} | Dst Port: {udp_layer.dport}")
        elif packet.haslayer(ICMP):
            print("Protocol: ICMP")
        else:
            print("Protocol: Other")

        # Show some payload if available
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload[:100]}")
    else:
        print("Non-IP packet")

# Start sniffing
print("Starting packet capture... Press Ctrl+C to stop.\n")
sniff(prn=analyze_packet, store=False)
