from scapy.all  import sniff, IP, TCP, UDP, ICMP

# Function to process and display packet information
def process_packet(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet(IP)   # Extract the IP layer
        protocol = None
    
    # Determine the protocol used in the packet
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "Other"

    # Extract source and destination IP addresses
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    # Extract payload (if any)
    payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else None

    # Print the packet information
    print(f"Packet Captured: ")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Protocol: {protocol}")
    if payload:
        print(f"Payload: {payload[:20]}... (truncated)")  # Truncated payload for readability
    print("-" * 50)  # Separator for readability

def start_sniffing(interface="eth0"):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, prn=process_packet, store=False)



