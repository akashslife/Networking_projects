from scapy.all import rdpcap
from collections import Counter
import matplotlib.pyplot as plt
import socket

#captured .pcap file
pcap_file = "cd/dell/akash/networking/traffic.pcap"
packets = rdpcap(pcap_file)
packet_count = 0
total_bytes = 0
protocols = []
timestamps = []
src_ips = []
dst_ips = []

for pkt in packets:
    packet_count += 1
    total_bytes += len(pkt)

    if pkt.haslayer("IP"):
        ip_layer = pkt["IP"]
        proto = ip_layer.proto
        if proto == 6:
            protocols.append("TCP")
        elif proto == 17:
            protocols.append("UDP")
        elif proto == 1:
            protocols.append("ICMP")
        else:
            protocols.append(str(proto))


        src_ips.append(ip_layer.src)
        dst_ips.append(ip_layer.dst)

    # Timestamp
    # timestd_ = timestamps.add(pkt.time)
    timestamps.append(pkt.time)
duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 1
throughput = total_bytes / duration
latency = (min(timestamps[1:] or [0]) - timestamps[0]) * 1000  # in ms


print(f"\n📊 Network Traffic Summary for: {pcap_file}")
print(f"Total Packets: {packet_count}")
print(f"Total Data Transferred: {total_bytes / 1024:.2f} KB")
print(f"Capture Duration: {duration:.2f} seconds")
print(f"Estimated Throughput: {throughput / 1024:.2f} KB/s")
print(f"Estimated Latency: {latency:.2f} ms")
print(f"\nProtocol Distribution: {Counter(protocols)}")
print(f"\nTop 5 Source IPs: {Counter(src_ips).most_common(5)}")
print(f"Top 5 Destination IPs: {Counter(dst_ips).most_common(5)}")

def plot_pie(counter_dict, title):
    labels = list(counter_dict.keys())
    sizes = list(counter_dict.values())
    plt.figure(figsize=(5, 5))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title(title)
    plt.axis('equal')
    plt.show()


plot_pie(Counter(protocols), "Protocol Distribution")
