"""
Encoding: UTF-8
Description:
"""
import csv
import os

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapReader, wrpcap
from scapy.all import rdpcap

from source.basis.ics_basis import ics_protocol_ports
from source.config.config import *


def get_ip_list(ip_list_file):
    """Load valid IPs from a label CSV."""
    valid_ips = set()
    with open(ip_list_file, mode="r", encoding="utf-8") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            if row["valid"] == "1":
                valid_ips.add(row["ip"])
    return valid_ips


def is_ics_port_by_protocol(port, protocol):
    """Check whether a port belongs to the given ICS protocol."""
    return port in ics_protocol_ports.get(protocol, [])


def get_tcp_payload_size(packet):
    """Calculate the TCP payload size without Ethernet padding."""
    if packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        tcp_header_length = tcp_layer.dataofs * 4
        ip_total_length = ip_layer.len
        ip_header_length = ip_layer.ihl * 4
        return ip_total_length - ip_header_length - tcp_header_length
    return -1


def extract_valid_packets(folder_path, pcap_file, ip_list_file):
    """
    Extract all packets from a pcap file and return them in a list.

    Parameters
    ----------
    pcap_file: filepath of pcap file
    ip_list_file: filepath of ip_list csv file

    Returns
    -------
    valid_packets: a list of packets with valid ips
    """
    valid_ips = get_ip_list(ip_list_file)
    valid_packets = []
    total_packet_count = 0
    valid_packet_count = 0
    print(f"pcap file: {pcap_file}")
    pcap_file_path = os.path.join(folder_path, f"{pcap_file}.pcap")
    ip_set = set()
    with PcapReader(pcap_file_path) as pcap_reader:
        for pkt in pcap_reader:
            total_packet_count += 1
            if IP in pkt and (pkt[IP].src in valid_ips or pkt[IP].dst in valid_ips):
                ip_set.add(pkt[IP].src)
                ip_set.add(pkt[IP].dst)
                valid_packets.append(pkt)
                valid_packet_count +=1
            # Output progress every 1000 packets
            if total_packet_count % 50000 == 0:
                print(f"Processed {total_packet_count} packets...")
    pcap_file_filtered_path = os.path.join(folder_path, f"{pcap_file}_filtered.pcap")
    print(f"The total number of IPs: {len(ip_set)}")
    wrpcap(pcap_file_filtered_path, valid_packets)


def extract_operations(root_path, protocol):
    """
    Extract operations from all pcap files in a folder.
    Parameters
    ----------
    root_path
    protocol

    Returns
    -------

    """
    pcap_directory = dataset_path("pcap", f"{protocol} operation pcaps")
    pcap_files = [f for f in os.listdir(pcap_directory) if f.endswith(".pcap")]
    pcap_files.sort()  # sort files by the file name
    if not pcap_files:
        print(f"No pcap files found in {pcap_directory}")
        return []
    operation_maps = {}
    for pcap_file in pcap_files:
        pcap_path = os.path.join(pcap_directory, pcap_file)
        print(f"pcap file: {pcap_path}")
        packets = rdpcap(pcap_path)
        if packets:
            pkt = packets[0]
            if get_tcp_payload_size(pkt) > 4 and is_ics_port_by_protocol(pkt[TCP].dport, protocol):  # get_tcp_payload_size(pkt) > 4 can ignore some unrelated payloads like [TCP ZeroWindowProbe] with b'\x00'
                operation = pkt[Raw].load[0:4] + pkt[Raw].load[8:]
                operation_maps[operation] = pcap_file[:-5]

    print(operation_maps)


if __name__ == '__main__':
    root_path = dataset_path()
    protocol = "enip"
    region = "au"
    file_number = 69
    start_file_index = 1
    ip_list_file = None

    if protocol == "modbus":
        ip_list_file = protocol_device_info_file("modbus")
    elif protocol == "s7":
        ip_list_file = protocol_device_info_file("s7")
    elif protocol == "enip":
        ip_list_file = protocol_device_info_file("enip")
    for i in range(0, file_number):
        folder_path = protocol_pcap_directory(protocol, region)
        pcap_file = f"{protocol}_more_round{start_file_index + i}_{region}"
        extract_valid_packets(folder_path, pcap_file, ip_list_file)

    # extract_operations(root_path, protocol)
