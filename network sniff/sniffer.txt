import matplotlib.pyplot as plt
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from collections import defaultdict
import threading
import time
import dpkt
import socket

# Dictionary to store packet counts
packet_counts = defaultdict(int)
hostnames = defaultdict(int)
app_traffic = defaultdict(int)

# Function to extract hostname from HTTP request
def get_http_hostname(packet):
    if packet.haslayer(HTTPRequest):
        return packet[HTTPRequest].Host.decode()

# Function to extract SNI from TLS packet
def get_sni(packet):
    try:
        if packet.haslayer(TCP) and packet[TCP].dport == 443:
            raw = bytes(packet[TCP].payload)
            record = dpkt.ssl.TLSRecord(raw)
            if record.type == 22:  # Handshake
                handshake = dpkt.ssl.TLSHandshake(record.data)
                if isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                    for ext_type, ext_data in handshake.data.extensions:
                        if ext_type == 0x00:  # SNI
                            return ext_data[5:].decode()
    except Exception:
        pass
    return None

# Function to categorize traffic as websites or apps
def categorize_traffic(packet, hostname):
    if hostname:
        if "google" in hostname or "facebook" in hostname or "youtube" in hostname:
            app_traffic['Web Browsing'] += 1
        else:
            app_traffic['Other Apps'] += 1
    else:
        app_traffic['Background Apps'] += 1

# Packet callback function
def packet_callback(packet):
    if IP in packet:
        hostname = None
        if packet.haslayer(TCP):
            if packet.haslayer(HTTPRequest):
                hostname = get_http_hostname(packet)
                if hostname:
                    hostnames[hostname] += 1
                    packet_counts['HTTP'] += 1
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                hostname = get_sni(packet)
                if hostname:
                    hostnames[hostname] += 1
                    packet_counts['HTTPS'] += 1
                else:
                    packet_counts['HTTPS'] += 1
            else:
                packet_counts['TCP'] += 1
        elif packet.haslayer(UDP):
            packet_counts['UDP'] += 1
        else:
            packet_counts['Other'] += 1

        # Categorize traffic
        categorize_traffic(packet, hostname)

# Function to start sniffing
def start_sniffing(interface=None):
    print(f"Starting packet capture on {interface or 'all interfaces'}...")
    sniff(prn=packet_callback, iface=interface, store=0)

# Function to plot and save the packet count statistics
def plot_packet_statistics(interval=10):
    while True:
        time.sleep(interval)
        plt.figure(figsize=(12, 8))

        plt.subplot(2, 1, 1)
        labels = packet_counts.keys()
        sizes = packet_counts.values()
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title('Network Traffic Analysis')

        plt.subplot(2, 1, 2)
        app_labels = app_traffic.keys()
        app_sizes = app_traffic.values()
        plt.barh(list(app_labels), list(app_sizes))
        plt.title('Traffic Categorization')
        plt.xlabel('Number of Packets')

        plt.tight_layout()
        plt.savefig('network_traffic_analysis.png')
        plt.clf()  # Clear the plot for the next interval

        # Print the packet counts to console for monitoring
        print(f"Packet counts: {dict(packet_counts)}")
        print(f"Hostnames: {dict(hostnames)}")
        print(f"App Traffic: {dict(app_traffic)}")

if __name__ == "__main__":
    # Start sniffing in a separate thread
    interface = 'eth0'  # Replace with your network interface or set to None for all interfaces
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.start()

    # Start plotting in the main thread
    plot_packet_statistics(interval=10)









print('Ip')
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, HTTPResponse
import socket
def get_domain_name(ip):
    try:
        domain_name = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain_name = None
    return domain_name
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_dst = packet[IP].dst
        
        # Resolve the destination IP to a domain name
        domain_name = get_domain_name(ip_dst)
        
        if domain_name:
            print(f"Detected Website: {domain_name}")
            print(f"IP Address: {ip_dst}")
            print("-" * 50)
def main():
    print("Starting network sniffer to detect websites...")
    try:
        sniff(filter="tcp port 80 or tcp port 443", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Stopping network sniffer...")

if __name__ == "__main__":
    main()
