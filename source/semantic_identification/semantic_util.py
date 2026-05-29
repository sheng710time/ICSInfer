"""
Encoding: UTF-8
Description:
"""
from nilsimsa import Nilsimsa, compare_digests
from scapy.layers.inet import IP, TCP


def modify_packet(packet):
    return modify_packet_all(packet)


def modify_packet_all(packet):
    """
    Remove MAC and IP addresses from a packet, and return bytes of the altered packet.
    """
    serialized_data = b""
    if IP not in packet:
        return serialized_data
    current_layer = packet
    while current_layer:
        if type(current_layer) == IP:
            # unify IP fields
            packet[IP].src = "0.0.0.0"
            packet[IP].dst = "0.0.0.0"

            # unify TCP fields
            # packet[TCP].seq = 0
            # packet[TCP].ack = 0
            # packet[TCP].sport = 0
            # packet[TCP].dport = 0
            # packet[TCP].chksum = 0
            serialized_data += bytes(current_layer)
            break
        current_layer = current_layer.payload
    return serialized_data


def modify_packet_header(packet):
    """
    Extract IP and TCP headers, modify MAC and IP addresses, and return bytes of the altered packet.
    """
    serialized_data = b""
    if IP in packet and TCP in packet:
        # unify IP fields
        packet[IP].src = "0.0.0.0"
        packet[IP].dst = "0.0.0.0"

        # unify TCP fields
        # packet[TCP].seq = 0
        # packet[TCP].ack = 0
        # packet[TCP].sport = 0
        # packet[TCP].dport = 0
        # packet[TCP].chksum = 0

        # Extract IP header
        ip_layer = packet[IP]
        ip_header_length = ip_layer.ihl * 4  # Internet Header Length (ihl) is in 32-bit words
        ip_header = bytes(ip_layer)[:ip_header_length]
        serialized_data += ip_header

        # Extract TCP header
        tcp_layer = packet[TCP]
        tcp_header_length = tcp_layer.dataofs * 4  # Data Offset (dataofs) is in 32-bit words
        tcp_header = bytes(tcp_layer)[:tcp_header_length]
        serialized_data += tcp_header
        return serialized_data
    else:
        return serialized_data


def calculate_semantic_hash(packet):
    """
    Calculate the semantic hash of a packet.
    """
    return calculate_nilsimsa_hash(packet)


def calculate_nilsimsa_hash(packet):
    """
    Calculate the Nilsimsa hash of a packet with specified fields ignored.
    """
    serialized_data = modify_packet(packet)

    # Generate the Nilsimsa hash
    nilsimsa = Nilsimsa(serialized_data)
    return nilsimsa.hexdigest()


def calculate_semantic_total_hash(packets):
    """
    Calculate the semantic hash of a set of packets.
    """
    return calculate_nilsimsa_total_hash(packets)


def calculate_nilsimsa_total_hash(packets):
    """
    Calculate the Nilsimsa hash of a set of packets.
    """
    serialized_data = b""
    for packet in packets:
        # Extract fields from all layers
        serialized_data += modify_packet(packet)

    # Generate the Nilsimsa hash
    nilsimsa = Nilsimsa(serialized_data)
    return nilsimsa.hexdigest()


def compare_semantic_hashes(hash1, hash2):
    """
    Compare two semantic hashes.
    Parameters
    ----------
    hash1
    hash2

    Returns
    -------
    similarity score
    """
    return compare_digests(hash1, hash2)