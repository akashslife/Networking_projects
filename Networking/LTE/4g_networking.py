# req.Python, Scapy, Wireshark
# Wireshark
# intallation: pip install scapy
from scapy.all import rdpcap
from collections import Counter
import datetime

# (.pcap file)
packets = rdpcap("cd/dell/akash/networking/traffic.pcap") #replace with your pcap file path

# initialize metrics
packet_count = 0
total_bytes = 0
protocols = []
timestamps = []

# analyze packets
for pkt in packets:
    packet_count += 1
    total_bytes += len(pkt)
    
    # cllect protocols
    if pkt.haslayer("IP"):
        proto = pkt["IP"].proto
        if proto == 6:
            protocols.append("TCP")
        elif proto == 17:
            protocols.append("UDP")
        elif proto == 1:
            protocols.append("ICMP")
        else:
            protocols.append(str(proto))
    
    # collect timestamps
    timestamps.append(pkt.time)

# throughput Calculation for the entire capture
duration = timestamps[-1] - timestamps[0]
throughput = total_bytes / duration if duration > 0 else 0


latency = min(timestamps[1:] or [0]) - timestamps[0] if len(timestamps) > 1 else 0
#output results
print("Network Traffic Analysis Results:")
print(f"Total Packets: {packet_count}")
print(f"Total Data: {total_bytes / 1024:.2f} KB")
print(f"Duration: {duration:.2f} sec")
print(f"Approx. Throughput: {throughput / 1024:.2f} KB/s")
print(f"Approx. Latency: {latency * 1000:.2f} ms")
print("Protocol Distribution:", Counter(protocols))
