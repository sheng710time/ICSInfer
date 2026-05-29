# Encoding: utf-8
# Version: 1.0.0

import csv
import hashlib
import re
from collections import defaultdict

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapReader

from source.basis.ics_basis import ics_ports, ics_protocol_ports, enip_operations
from source.semantic_identification.semantic_util import calculate_semantic_hash, \
    calculate_semantic_total_hash
from source.label_utils import load_ip_labels
from source.config.config import *


def get_ip_list(ip_list_file):
    """
    Load ip set from ip_list_file

    Parameters
    ----------
    ip_list_file: filepath of ip_list csv file

    Returns
    -------
    valid_ips: set, a set of valid ips
    """
    valid_ips = set()
    with open(ip_list_file, mode="r") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            if row["valid"]=="1":
                valid_ips.add(row["ip"])
    return valid_ips


def get_ip_labels(ip_label_file):
    """
    Load ip labels from ip_label_file

    Parameters
    ----------
    ip_label_file: filepath of ip_list csv file

    Returns
    -------
    ip_labels: dictionary, {ip: label}
    """
    return load_ip_labels(ip_label_file)


def get_packets_inlist(pcap_file, ip_list_file):
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
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            total_packet_count += 1
            if IP in pkt and (pkt[IP].src in valid_ips or pkt[IP].dst in valid_ips):
                valid_packets.append(pkt)
                valid_packet_count +=1
            # Output progress every 1000 packets
            if total_packet_count % 50000 == 0:
                print(f"Processed {total_packet_count} packets...")
    return valid_packets


def get_packets_inlist_others(pcap_file, valid_ips):
    """
    Extract all packets from a pcap file and return them in a list.

    Parameters
    ----------
    pcap_file: filepath of pcap file
    valid_ips:

    Returns
    -------
    valid_packets: a list of packets with valid ips
    """
    valid_packets = []
    total_packet_count = 0
    valid_packet_count = 0
    print(f"pcap file: {pcap_file}")
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            total_packet_count += 1
            if IP in pkt and (pkt[IP].src in valid_ips or pkt[IP].dst in valid_ips):
                valid_packets.append(pkt)
                valid_packet_count +=1
            # Output progress every 1000 packets
            if total_packet_count % 50000 == 0:
                print(f"Processed {total_packet_count} packets...")
    return valid_packets


def get_packets(pcap_file):
    """
    Extract all packets from a pcap file and return them in a list.
    Parameters
    ----------
    pcap_file: filepath of pcap file

    Returns
    -------
    total_packets: a list of packets
    """
    total_packets = []
    packet_count = 0
    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            packet_count += 1
            total_packets.append(packet)
            # Output progress every 1000 packets
            if packet_count % 50000 == 0:
                print(f"Processed {packet_count} packets...")
    # total_packets = rdpcap(pcap_file)
    return total_packets


def is_ics_port(port):
    """
    Determine if the port is an ICS port

    Parameters
    ----------
    port

    Returns
    -------
    True: an ICS port, False: otherwise
    """
    if port in ics_ports.keys():
        return True
    return False


def is_ics_port_by_protocol(port, protocol):
    """
    Determine if the port is an ICS port

    Parameters
    ----------
    port
    protocol

    Returns
    -------
    True: an ICS port, False: otherwise
    """
    my_ports = ics_protocol_ports.get(protocol, []) # Sometime, ICS ports may be used as source ports, like 44818 of enip
    if port in my_ports:
        return True
    return False


def filter_packets_train(all_packets, protocol):
    """
    Filter out all unrelated packets, including non-ICS packets, non_TCP packets, handshake packets, and rest packets.

    Parameters
    ----------
    all_packets: all packets from the pcap file

    Returns
    -------
    other_filtered_packets: filtered packets from the pcap file
    """
    # Filter out packets of non-ICS and non-TCP packets
    ip_filtered_packets = [pkt for pkt in all_packets if TCP in pkt and (is_ics_port_by_protocol(pkt[TCP].sport, protocol) or is_ics_port_by_protocol(pkt[TCP].dport, protocol))]

    # Filter out handshake packets (SYN, SYN-ACK, ACK after SYN-ACK, and Rest)
    other_filtered_packets = []
    handshake_tracker = {}  # Dictionary to track SYN and SYN-ACK packets by TCP connection (based on IP and ports)
    ip_set = set()
    for pkt in ip_filtered_packets:
        if IP in pkt and TCP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            # Create a connection identifier
            connection_id = (ip_src, src_port, ip_dst, dst_port)
            # Check for SYN packet
            if pkt[TCP].flags == "S":  # SYN
                handshake_tracker[connection_id] = "SYN_SENT"
            # Check for SYN-ACK packet in response to SYN
            elif pkt[TCP].flags == "SA":  # SYN-ACK, including retransmitted SYN-ACK
                handshake_tracker[(ip_dst, dst_port, ip_src, src_port)] = "SYN-ACK_SENT"
            # Check for final ACK packet that completes the handshake
            elif pkt[TCP].flags == "A" and handshake_tracker.get(connection_id) == "SYN-ACK_SENT":
                # Reset the tracker for this connection if needed
                del handshake_tracker[connection_id]
            # Check for RST packets
            elif pkt[TCP].flags == "R":  # Reset
                continue
            # Check for RST, ACK packets
            elif pkt[TCP].flags == "RA":  # Reset
                continue
            else:
                other_filtered_packets.append(pkt)
                ip_set.add(pkt[IP].src)
                ip_set.add(pkt[IP].dst)
    print(f"The total number of packets: {len(all_packets)}")
    print(f"The total number of IPs: {len(ip_set)}")
    print(f"The size of ip_filtered_packets: {len(ip_filtered_packets)}")
    print(f"The size of handshake_filtered_packets: {len(other_filtered_packets)}")
    return other_filtered_packets


def filter_packets_others(all_packets, protocol):
    """
    Filter out all unrelated packets, including non-ICS packets, non_TCP packets, and rest packets, but include handshake packets.

    Parameters
    ----------
    all_packets: all packets from the pcap file

    Returns
    -------
    other_filtered_packets: filtered packets from the pcap file
    """
    # Filter out packets of non-ICS and non-TCP packets
    ip_filtered_packets = [pkt for pkt in all_packets if TCP in pkt and (is_ics_port_by_protocol(pkt[TCP].sport, protocol) or is_ics_port_by_protocol(pkt[TCP].dport, protocol))]

    # Filter out handshake packets (SYN, SYN-ACK, ACK after SYN-ACK, and Rest)
    other_filtered_packets = []
    handshake_tracker = {}  # Dictionary to track SYN and SYN-ACK packets by TCP connection (based on IP and ports)
    for pkt in ip_filtered_packets:
        if IP in pkt and TCP in pkt:
            if pkt[TCP].flags == "R":  # Reset
                continue
            # Check for RST, ACK packets
            elif pkt[TCP].flags == "RA":  # Reset
                continue
            else:
                other_filtered_packets.append(pkt)
    print("The number of total packets: " + str(all_packets.__len__()))
    print("Size of ip_filtered_packets: " + str(ip_filtered_packets.__len__()))
    print("Size of handshake_filtered_packets: " + str(other_filtered_packets.__len__()))
    return other_filtered_packets


def packet_hash(packet):
    """
    Create a hash based on key header fields to uniquely identify packet data.

    Parameters
    ----------
    packet:

    Returns
    -------
    : hash value of a packet
    """
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        # Select header fields to hash (IP + TCP headers, including sequence and ack numbers)
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        proto = packet[IP].proto
        seq = packet[TCP].seq  # the response packet to the retransmission packet will have a different sequence number, when some new packets are sent before the duplicate response packets
        ack = packet[TCP].ack  # But its ack number still keeps consistent with the retransmission packet.
        flags = packet[TCP].flags.value
        payload = bytes(packet[TCP].payload)

        # Hash considering flags
        hash1 = hashlib.md5(f"{src}-{dst}-{sport}-{dport}-{proto}-{ack}-{flags}-{payload}".encode()).hexdigest()
        # Hash considering seq and the packets with payload, because the seq of packets like ACK and FIN ACK won't change. Therefore, hash2 is not applicable
        hash2 = hashlib.md5(f"{src}-{dst}-{sport}-{dport}-{proto}-{ack}-{seq}-{payload}".encode()).hexdigest() if payload else None
        return hash1, hash2
    return None, None


def filter_retransmission(packets):
    """
    Filter out retransmission packets and their corresponding response packets, if response packets are also duplicate.

    Parameters
    ----------
    packets

    Returns
    -------
    filtered_packets: packets without retransmission
    """
    filtered_packets = []
    seen_hashes1 = set()
    seen_hashes2 = set()# Track packet hashes
    for pkt in packets:
        pkt_hash1, pkt_hash2 = packet_hash(pkt)
        if pkt_hash1 and pkt_hash1 in seen_hashes1:
            continue
                # print("Resubmission detected:", pkt.summary())
        elif pkt_hash2 and pkt_hash2 in seen_hashes2:
            continue
        else:
            if pkt_hash1: seen_hashes1.add(pkt_hash1)
            if pkt_hash2: seen_hashes2.add(pkt_hash2)
            filtered_packets.append(pkt)
    return filtered_packets


def split_packets_by_ip(all_packets, protocol):
    """
    Split packets by ICS device IPs

    Parameters
    ----------
    all_packets: from function filter_retransmission()
    protocol: ICS protocol

    Returns
    -------
    device_packets: dictionary, {device_ip: list of packets}
    """
    device_packets = defaultdict(list)
    for pkt in all_packets:
        if is_ics_port_by_protocol(pkt[TCP].dport, protocol):
            device_packets[pkt[IP].dst].append(pkt)
        elif is_ics_port_by_protocol(pkt[TCP].sport, protocol):
            device_packets[pkt[IP].src].append(pkt)
    return device_packets


def split_packets_by_port(packets, protocol):
    """
    Split packets by ICS ports

    Parameters
    ----------
    packets

    Returns
    -------
    port_packets: dictionary, {ics_port: list of packets}
    """
    port_packets = defaultdict(list)
    for pkt in packets:
        ics_port = None
        if is_ics_port_by_protocol(pkt[TCP].sport, protocol):
            ics_port = pkt[TCP].sport
        elif is_ics_port_by_protocol(pkt[TCP].dport, protocol):
            ics_port = pkt[TCP].dport
        if ics_port:
            port_packets[ics_port].append(pkt)

    return port_packets


def get_5_tuple(pkt):
    """
    Create a normalized 5-tuple key for bidirectional flows.

    Parameters
    ----------
    pkt: A packet

    Returns
    -------
    flow_key: The 5-tuple
    """
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            # If not TCP or UDP, ignore the packet
            return None
        # Create a bidirectional key (sorted by IP and port pairs)
        flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        return flow_key
    return None


def create_flows(all_packets, interval_time):
    """
    Create TCP flows

    Parameters
    ----------
    all_packets: all filtered packets
    interval_time: time threshold for splitting flows of the same 5-tuple

    Returns
    -------
    flows: dictionary, {flow_key: packet list}
    """

    # Dictionary to store flows, using the 5-tuple as the key with the event_time
    flows = defaultdict(list)
    # Loop through each packet, and add it to the corresponding flow
    for pkt in all_packets:
        flow_key = get_5_tuple(pkt)
        if flow_key:
            flows[flow_key].append(pkt)

    # further split flow by a time interval, because different rounds may contain flows of the same 5_tuple that are combined at first step
    split_flows = {}
    for flow_key, flow_list in flows.items():
        flow_list.sort(key=lambda pkt: pkt.time)# Sort packets by their `time` attribute
        # Group packets based on the time interval
        current_flow = []
        current_time = flow_list[0].time
        flow_index = 0
        for pkt in flow_list:
            if pkt.time - current_time < interval_time:
                current_flow.append(pkt)
                current_time = pkt.time
            else:
                split_flows[flow_key + (f"f_{flow_index}",)] = current_flow
                current_flow = [pkt]
                current_time = pkt.time
                flow_index += 1
        if len(current_flow) > 0:
            split_flows[flow_key + (f"f_{flow_index}",)] = current_flow

    return split_flows


def get_tcp_payload_size(packet):
    """
    Calculate the size of the TCP payload without Ethernet Padding.

    Parameters
    ----------
    packet: packet to analyze

    Returns
    -------
    tcp_payload_length: size of the TCP payload without Ethernet Padding.
    """
    # Ensure the packet has Ethernet, IP, and TCP layers
    if packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP):
        eth_layer = packet[Ether]
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Calculate the TCP header length (in bytes)
        tcp_header_length = tcp_layer.dataofs * 4  # dataofs is in 32-bit words

        # Calculate the total length of the IP packet
        ip_total_length = ip_layer.len

        # IP header length (in bytes)
        ip_header_length = ip_layer.ihl * 4  # ihl is in 32-bit words

        # Calculate the TCP payload length
        tcp_payload_length = ip_total_length - ip_header_length - tcp_header_length
        return tcp_payload_length
    else:
        return -1


def extract_modbus_operation(flow_packets, protocol):
    """
    Extract modbus operation

    Parameters
    ----------
    flow_packets: list of packets

    Returns
    -------
    operation:
    """
    operation = None
    for pkt in flow_packets:
        # The first packet with payload to an ICS device is considered as a request packet.
        if get_tcp_payload_size(pkt) > 4 and is_ics_port_by_protocol(pkt[TCP].dport, protocol):  # get_tcp_payload_size(pkt) > 4 can ignore some unrelated payloads like [TCP ZeroWindowProbe] with b'\x00'
            operation = pkt[Raw].load
            break
    return operation


def extract_s7_operation(flow_packets, protocol):
    """
    Extract s7 operation

    Parameters
    ----------
    flow_packets: list of packets

    Returns
    -------
    operation
    """
    operation = None
    request_index = 0;
    for pkt in flow_packets:
        # The third packet with payload to an ICS device is considered as a request packet.
        if get_tcp_payload_size(pkt) > 4 and is_ics_port_by_protocol(pkt[TCP].dport, protocol):  # get_tcp_payload_size(pkt) > 4 can ignore some unrelated payloads like [TCP ZeroWindowProbe] with b'\x00'
            request_index += 1
            if request_index == 3:
                operation = pkt[Raw].load
                break
    return operation


def extract_enip_operation(flow_packets, protocol):
    """
    Extract enip operation

    Parameters
    ----------
    flow_packets: list of packets

    Returns
    -------
    operation
    """
    operation = None
    candidates = []
    for pkt in flow_packets:
        if get_tcp_payload_size(pkt) > 4 and is_ics_port_by_protocol(pkt[TCP].dport, protocol):  # get_tcp_payload_size(pkt) > 4 can ignore some unrelated payloads like [TCP ZeroWindowProbe] with b'\x00'
            candidate = pkt[Raw].load[0:4] + pkt[Raw].load[8:]  # [5:9] is the session handle, which may change after registering a session
            candidates.append(candidate)

    for candidate in candidates:
        if candidate in enip_operations.keys():
            operation = candidate
            break

    return operation

    # if len(candidates) == 1 and has_response:  # has_response filter out the register session request without response, because we cannot determine the true operation
    #     operation = candidates[0][0:4] + candidates[0][8:]
    # elif len(candidates) >= 2:
    #     operation = candidates[-2][0:4] + candidates[-2][8:]
    # # elif len(candidates) > 2:
    # #     operation = candidates[-2][0:4] + candidates[-2][-6:]
    # if operation == b'f\x00\x00\x00\x00\x00\x00\x00\x00\x00' or operation == b'e\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00':  # Re
    #     print(f"{pkt[TCP].sport}, {pkt[TCP].dport}")
    return operation


def extract_operation(flow_packets, protocol):
    """
    Automatically extract the operation of a flow
    Parameters
    ----------
    flow_packets: list of packets

    Returns
    -------
    operation:
    """
    if len(flow_packets) == 0:
        return None
    # Get ICS port
    ics_port = None
    if is_ics_port_by_protocol(flow_packets[0][TCP].sport, protocol):
        ics_port = flow_packets[0][TCP].sport
    elif is_ics_port_by_protocol(flow_packets[0][TCP].dport, protocol):
        ics_port = flow_packets[0][TCP].dport
    # Get Operation
    operation = None
    if ics_port == 502 or ics_port == 503:
        operation = extract_modbus_operation(flow_packets, protocol)
    elif ics_port == 102:
        operation = extract_s7_operation(flow_packets, protocol)
    elif ics_port == 44818:
        operation = extract_enip_operation(flow_packets, protocol)
    return operation


def group_flows(flows, protocol):
    """
    Group flows based on their operations

    Parameters
    ----------
    flows: from function create_flows()

    Returns
    -------
    operation_flows: dictionary, {operation: flow list}
    operations: set, all operations
    """
    operation_flows = defaultdict(list)
    operations = set()
    for flow_key, packets in flows.items():
        operation = extract_operation(packets, protocol)
        if operation:
            operations.add(operation)
            operation_flows[operation].append({flow_key: packets})
    return operation_flows, operations


def group_flows_excluded(flows, excluded_operations, protocol):
    """
    Group flows based on their operations

    Parameters
    ----------
    flows: from function create_flows()
    excluded_operations: operations not considered

    Returns
    -------
    operation_flows: dictionary, {operation: flow list}
    operations: set, all operations
    """
    operation_flows = defaultdict(list)
    operations = set()
    for flow_key, packets in flows.items():
        operation = extract_operation(packets, protocol)
        if operation and operation not in excluded_operations:
            operations.add(operation)
            operation_flows[operation].append({flow_key: packets})
    return operation_flows, operations


def extract_flow_ts_packets(operation_flows, protocol):
    """
    Extract temporal-spacial formulas of packets from operation_flows.

    Parameters
    ----------
    operation_flows: from function group_flows()

    Returns
    -------
    grouped_flow_ts_packets: dictionary, {operation: [flow_key: list{(relative time, relative position, directional length)}]}
    """
    grouped_flow_ts_packets = defaultdict(list)
    for operation, flows in operation_flows.items():
        flow_ts_packets = defaultdict(list)
        for flow in flows:
            for flow_key, packets in flow.items():
                if len(packets) == 1:
                    if is_ics_port_by_protocol(packets[0].dport, protocol):
                        flow_ts_packets[flow_key].append((0, 0, f"C-{len(packets[0])}"))
                    elif is_ics_port_by_protocol(packets[0].sport, protocol):
                        flow_ts_packets[flow_key].append((0, 0, f"S-{len(packets[0])}"))
                    break
                else:
                    start_time = packets[0].time
                    flow_duration = packets[-1].time - start_time
                    # flow_duration = 1  # when flow_duration = 1, the relative_time becomes an absolute time
                    for i in range(len(packets)):
                        relative_time = (packets[i].time - start_time) / flow_duration
                        if is_ics_port_by_protocol(packets[i][TCP].dport, protocol):
                            flow_ts_packets[flow_key].append((relative_time, i, f"C-{len(packets[i])}"))
                        elif is_ics_port_by_protocol(packets[i][TCP].sport, protocol):
                            flow_ts_packets[flow_key].append((relative_time, i, f"S-{len(packets[i])}"))
        grouped_flow_ts_packets[operation] = flow_ts_packets
    return grouped_flow_ts_packets


def extract_packet_length(packet):
    """
    Extract packet length from packet.

    Parameters
    ----------
    packet

    Returns
    -------

    """
    pkt_length = 0
    if IP in packet and TCP in packet:
        # Extract IP header length
        pkt_length += packet[IP].ihl * 4
        # Extract TCP header length
        pkt_length += packet[TCP].dataofs * 4
    return len(packet)


def extract_flow_ts_packets_semantic(operation_flows, protocol):
    """
    Extract temporal-spacial formulas of packets from operation_flows.

    Parameters
    ----------
    operation_flows: from function group_flows()

    Returns
    -------
    grouped_flow_ts_packets: dictionary, {operation: [flow_key: list{(relative time, relative position, directional length, packet)}]}
    """
    grouped_flow_ts_packets = defaultdict(list)
    for operation, flows in operation_flows.items():
        flow_ts_packets = defaultdict(list)
        for flow in flows:
            for flow_key, packets in flow.items():
                if len(packets) == 1:
                    if is_ics_port_by_protocol(packets[0].dport, protocol):
                        flow_ts_packets[flow_key].append((0, 0, f"C-{extract_packet_length(packets[0])}", packets[0]))
                    elif is_ics_port_by_protocol(packets[0].sport, protocol):
                        flow_ts_packets[flow_key].append((0, 0, f"S-{extract_packet_length(packets[0])}", packets[0]))
                    break
                else:
                    start_time = packets[0].time
                    flow_duration = packets[-1].time - start_time
                    # flow_duration = 1  # when flow_duration = 1, the relative_time becomes an absolute time
                    for i in range(len(packets)):
                        relative_time = (packets[i].time - start_time) / flow_duration
                        if is_ics_port_by_protocol(packets[i][TCP].dport, protocol):
                            flow_ts_packets[flow_key].append((relative_time, i, f"C-{extract_packet_length(packets[i])}", packets[i]))
                        elif is_ics_port_by_protocol(packets[i][TCP].sport, protocol):
                            flow_ts_packets[flow_key].append((relative_time, i, f"S-{extract_packet_length(packets[i])}", packets[i]))
        grouped_flow_ts_packets[operation] = flow_ts_packets
    return grouped_flow_ts_packets


def extract_flow_ts_packets_semantic_hash(operation_flows, protocol):
    """
    Extract semantic temporal-spacial formulas of packets from operation_flows.

    Parameters
    ----------
    operation_flows: from function group_flows()

    Returns
    -------
    grouped_flow_ts_packets: dictionary, {operation: [flow_key: list{(relative time, relative position, directional length, semantic_hash)}]}
    """
    grouped_flow_ts_packets = defaultdict(list)
    for operation, flows in operation_flows.items():
        flow_ts_packets = defaultdict(list)
        for flow in flows:
            for flow_key, packets in flow.items():
                if len(packets) == 1:
                    if is_ics_port_by_protocol(packets[0].dport, protocol):
                        flow_ts_packets[flow_key].append((0, 0, f"C-{extract_packet_length(packets[0])}", calculate_semantic_hash(packets[0])))
                    elif is_ics_port_by_protocol(packets[0].sport, protocol):
                        flow_ts_packets[flow_key].append((0, 0, f"S-{extract_packet_length(packets[0])}", calculate_semantic_hash(packets[0])))
                    break
                else:
                    start_time = packets[0].time
                    flow_duration = packets[-1].time - start_time
                    # flow_duration = 1  # when flow_duration = 1, the relative_time becomes an absolute time
                    for i in range(len(packets)):
                        relative_time = (packets[i].time - start_time) / flow_duration
                        if is_ics_port_by_protocol(packets[i][TCP].dport, protocol):
                            flow_ts_packets[flow_key].append((relative_time, i, f"C-{extract_packet_length(packets[i])}", calculate_semantic_hash(packets[i])))
                        elif is_ics_port_by_protocol(packets[i][TCP].sport, protocol):
                            flow_ts_packets[flow_key].append((relative_time, i, f"S-{extract_packet_length(packets[i])}", calculate_semantic_hash(packets[i])))
        grouped_flow_ts_packets[operation] = flow_ts_packets
    return grouped_flow_ts_packets


def extract_flow_ts_packets_semantic_double(operation_flows, protocol):
    """
    Extract semantic temporal-spacial formulas of packets from operation_flows.

    Parameters
    ----------
    operation_flows: from function group_flows()

    Returns
    -------
    grouped_flow_ts_packets: dictionary, {operation: [flow_key: list{(relative time, relative position, directional length, semantic_hash)}]}
    """
    grouped_flow_ts_packets = defaultdict(list)
    for operation, flows in operation_flows.items():
        flow_ts_packets = defaultdict(list)
        for flow in flows:
            for flow_key, packets in flow.items():
                if len(packets) == 1:
                    if is_ics_port_by_protocol(packets[0].dport, protocol):
                        flow_ts_packets[flow_key].append((0, 0, f"C-{extract_packet_length(packets[0])}", calculate_semantic_hash(packets[0]), packets[0]))
                    elif is_ics_port_by_protocol(packets[0].sport, protocol):
                        flow_ts_packets[flow_key].append((0, 0, f"S-{extract_packet_length(packets[0])}", calculate_semantic_hash(packets[0]), packets[0]))
                    break
                else:
                    start_time = packets[0].time
                    flow_duration = packets[-1].time - start_time
                    # flow_duration = 1  # when flow_duration = 1, the relative_time becomes an absolute time
                    for i in range(len(packets)):
                        relative_time = (packets[i].time - start_time) / flow_duration
                        if is_ics_port_by_protocol(packets[i][TCP].dport, protocol):
                            flow_ts_packets[flow_key].append((relative_time, i, f"C-{extract_packet_length(packets[i])}", calculate_semantic_hash(packets[i]), packets[0]))
                        elif is_ics_port_by_protocol(packets[i][TCP].sport, protocol):
                            flow_ts_packets[flow_key].append((relative_time, i, f"S-{extract_packet_length(packets[i])}", calculate_semantic_hash(packets[i]), packets[0]))
        grouped_flow_ts_packets[operation] = flow_ts_packets
    return grouped_flow_ts_packets


def generate_flow_semantic_packets(operation_flow_ts_packets):
    """
    Generate semantic packets from operation_flows where each flow has a semantic hash.

    Parameters
    ----------
    operation_flow_ts_packets: from function extract_flow_ts_packets_semantic()

    Returns
    -------
    operation_flow_semantic_packets: dictionary, {operation: [flow_key: list{(relative time, relative position, directional length, packet)}]}
    """
    operation_flow_semantic_packets = defaultdict(list)
    for operation, flow_ts_packets in operation_flow_ts_packets.items():
        flow_semantic_packets = defaultdict()
        for flow_key, flow_ts in flow_ts_packets.items():
            packets = [item[-1] for item in flow_ts]
            my_hash = calculate_semantic_total_hash(packets)
            flow_semantic_packets[flow_key] = (flow_ts, my_hash)
        operation_flow_semantic_packets[operation] = flow_semantic_packets
    return operation_flow_semantic_packets


def extract_length(device_sequences):
    """
    Extract all existing lengths from device_sequences without considering directions

    Parameters
    ----------
    device_sequences: {"device_ip", list(sequence)}

    Returns
    -------
    lengths: directional length set
    """
    lengths = set()
    for sequences in device_sequences.values():
        for sequence in sequences:
            for item in sequence:
                # Determine numeric values and directions for p1
                lens = item.split("-")[1] if "-" in item else 0
                # Extract all numbers using regular expressions
                numbers = re.findall(r'\d+', lens)
                # Convert the extracted strings to integers
                numbers = list(map(int, numbers))
                lengths.update(numbers)
    return lengths


def filter_length(packets, existing_lengths):
    """
    Filter out the packets of which lengths do not appear in existing_lengths

    Parameters
    packets: packets
    existing_lengths: all packet lengths of training data

    Returns
    length_filtered_packets: filtered packets according to the packet length
    """
    length_filtered_packets = []
    for packet in packets:
        if len(packet) in existing_lengths:
            length_filtered_packets.append(packet)

    print("The number of total packets: " + str(packets.__len__()))
    print("Size of length_filtered_packets: " + str(length_filtered_packets.__len__()))
    return length_filtered_packets


def main():
    """ Call packet_filter()
    root_path = dataset_path("examples", "DeviceImageTest")
    pcap_file = os.path.join(root_path, "188.165.48.108.pcap")
    valid_ip_csv = os.path.join(root_path, "valid_ip_list.csv")
    output_filepath = os.path.join(root_path, "filtered_188.165.48.108.pcap")
    filter_packet(pcap_file, valid_ip_csv, output_filepath)
    """

    """ Call flow_reassemble()
    root_path = dataset_path("examples", "DeviceImageTest")
    pcap_file = os.path.join(root_path, "filtered_138.99.244.75.pcap")
    flows = reassemble_flow(pcap_file)
    """

    """ Call packet_pairing()
    root_path = dataset_path("examples", "DeviceImageTest")
    pcap_file = os.path.join(root_path, "188.165.48.108.pcap")
    src_ip_csv = os.path.join(root_path, "valid_ip_list.csv")
    flows = reassemble_flow(pcap_file)
    packet_length_pairs = pair_packets(src_ip_csv, flows)
    """

    """ Call aggregate_pair()
    root_path = dataset_path("examples", "DeviceImageTest")
    pcap_file = os.path.join(root_path, "138.99.244.75.pcap")
    src_ip_csv = os.path.join(root_path, "valid_ip_list.csv")
    flows = reassemble_flow(pcap_file)
    src_ips = get_src_ips(src_ip_csv)
    packet_length_pairs = pair_packets(src_ips, flows)
    device_pairs, device_flow_numbers = aggregate_pairs(src_ips, packet_length_pairs) 
    """
    print("")


# if __name__ == "__main__":
#     main()
