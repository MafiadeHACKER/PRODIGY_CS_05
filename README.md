# PRODIGY_CS_05

# Network Packet Sniffer
This is a simple network packet sniffer tool implemented in Python using the scapy library. The tool captures and analyzes network packets, displaying key information such as source and destination IP addresses, protocol type, and payload data.

# Features
Captures network packets on the specified network interface.
Supports analysis of packets with the following protocols:
TCP (Transmission Control Protocol)
UDP (User Datagram Protocol)
ICMP (Internet Control Message Protocol)
Other protocols
Displays key details including:
Source IP
Destination IP
Protocol used
Truncated payload (for readability)

# Prerequisites
Python 3.x install on your system
Install the scapy library:
    pip install scapy

# How to Use
1. Run the Sniffer with Elevated Privileges
Packet sniffing requires elevated privileges to access raw network sockets. Use sudo on Linux/macOS or run as an Administrator on Windows.

On Linux/macOS:
    sudo python3 sniffer.py
On Windows:
Run your Command Prompt as Administrator and navigate to the script folder:
    python sniffer.py

2. Input the Network Interface
When prompted, input the name of the network interface on which you want to capture packets.

For a wired connection, the interface is often eth0.
For a wireless connection, the interface might be wlan0.

Example:
Enter the network interface to sniff on (e.g., eth0, wlan0): eth0

3. Viewing Captured Packets
The tool will display information for each captured packet in the following format:
Packet Captured:
Source IP: 192.168.1.10
Destination IP: 8.8.8.8
Protocol: TCP
Payload: b'GET / HTTP/1.1'... (truncated)
--------------------------------------------------

4. Stop the Sniffer
To stop the sniffer, press Ctrl+C in the terminal.

# Ethical Use
This tool is meant for educational purposes only. Please ensure you have proper authorization to monitor network traffic. Unauthorized packet sniffing may violate privacy laws or company policies.

# Example Output
Starting packet sniffing on interface: eth0
Packet Captured:
Source IP: 192.168.0.2
Destination IP: 192.168.0.1
Protocol: TCP
Payload: b'\x16\x03\x03\x00...'... (truncated)
--------------------------------------------------

# License
This project is licensed for educational purposes. Ensure legal and ethical usage.