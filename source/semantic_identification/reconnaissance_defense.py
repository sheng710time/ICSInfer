"""
Encoding: UTF-8
Description:
"""

from scapy.all import *
import copy
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from source.basis.dataprocess import is_ics_port_by_protocol, extract_packet_length
from source.config.config import *


def defense_padding_packets(train_device_packets, protocol):
    """
    Pad "Response" application-layer payloads to multiples of 16 bytes with 0x00,
    and reconstruct packet to recalculate IP/TCP headers for traffic fingerprinting.

    Args:
        train_device_packets (list): A list of Scapy packets (e.g., from rdpcap)
        protocol (str): Protocol name (currently unused, reserved for future extension)

    Returns:
        list: A list of new Scapy packets with padded payload and recalculated headers
    """
    padded_packets = []
    padded_count = 0
    for pkt in train_device_packets:
        # pre_length = extract_packet_length(pkt)
        pkt_copy = copy.deepcopy(pkt)
        # Ensure packet has TCP and Raw layers
        if pkt_copy.haslayer(TCP) and pkt_copy.haslayer(Raw) and is_ics_port_by_protocol(pkt_copy[TCP].sport, protocol):
            # Pad payload
            raw_payload = pkt_copy[Raw].load
            change_len = 16
            pad_len = (change_len - (len(raw_payload) % change_len)) % change_len
            pkt_copy[Raw].load = raw_payload + b'\x00' * pad_len

            # Manually trigger recalculation of IP/TCP fields
            if pkt_copy.haslayer(IP):
                # Recalculate IP.len and IP.chksum
                pkt_copy[IP].len = None
                pkt_copy[IP].chksum = None
            if pkt_copy.haslayer(TCP):
                pkt_copy[TCP].chksum = None

            # Force build & parse back to update values in-place
            pkt_copy = Ether(bytes(pkt_copy)) if pkt_copy.haslayer(Ether) else pkt_copy.__class__(bytes(pkt_copy))
            # Restore the original timestamp
            pkt_copy.time = pkt.time
            padded_count += 1
            # post_length = extract_packet_length(pkt_copy)

        padded_packets.append(pkt_copy)
    print(f"Padded {padded_count} packets (protocol={protocol}).")
    return padded_packets


def defense_encryption_packets(train_device_packets, protocol):
    """
    Apply AES encryption (CBC mode) to Raw payloads of ICS response packets.

    Args:
        train_device_packets (list): List of Scapy packets
        protocol (str): Protocol name, e.g., "Modbus"

    Returns:
        list: List of packets with encrypted payloads
    """
    encrypted_packets = []
    encrypted_count = 0

    # Fixed 16-byte AES key and IV (for testing)
    key = b'0123456789abcdef'
    iv = b'abcdef0123456789'

    for pkt in train_device_packets:
        # pre_length = extract_packet_length(pkt)
        pkt_copy = copy.deepcopy(pkt)
        if pkt_copy.haslayer(TCP) and pkt_copy.haslayer(Raw) and is_ics_port_by_protocol(pkt_copy[TCP].sport, protocol):
            raw_payload = pkt_copy[Raw].load

            # PKCS#7 padding + AES-CBC encryption
            padded_data = pad(raw_payload, AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_payload = cipher.encrypt(padded_data)

            # Replace payload with encrypted version
            pkt_copy[Raw].load = encrypted_payload

            # Mark header fields dirty
            if pkt_copy.haslayer(IP):
                # Recalculate IP.len and IP.chksum
                pkt_copy[IP].len = None
                pkt_copy[IP].chksum = None
            if pkt_copy.haslayer(TCP):
                pkt_copy[TCP].chksum = None

            # Rebuild packet to recalculate fields
            pkt_copy = Ether(bytes(pkt_copy)) if pkt_copy.haslayer(Ether) else pkt_copy.__class__(bytes(pkt_copy))
            # Restore the original timestamp
            pkt_copy.time = pkt.time
            encrypted_count += 1
            # post_length = extract_packet_length(pkt_copy)

        encrypted_packets.append(pkt_copy)

    print(f"Encrypted {encrypted_count} packets (protocol={protocol}).")
    return encrypted_packets


def defense_different_encryption_packets(train_device_packets, protocol):  # TODO test
    """
    Apply AES encryption (CBC mode) to Raw payloads of ICS response packets.
    A new AES key/IV is randomly generated for each source IP per function call.

    Args:
        train_device_packets (list): List of Scapy packets
        protocol (str): Protocol name, e.g., "Modbus"

    Returns:
        list: List of packets with encrypted payloads
    """
    encrypted_packets = []
    encrypted_count = 0
    # Per-function-call random AES key/IV per IP
    ip_keys = {}  # src_ip: (key, iv)

    for pkt in train_device_packets:
        pkt_copy = copy.deepcopy(pkt)

        if pkt_copy.haslayer(TCP) and pkt_copy.haslayer(Raw) and is_ics_port_by_protocol(pkt_copy[TCP].sport, protocol):
            ics_ip = pkt_copy[IP].src
            # Assign a new key/iv per IP in this call
            if ics_ip not in ip_keys:
                key = os.urandom(16)  # 128-bit AES key
                iv = os.urandom(16)   # 128-bit IV
                ip_keys[ics_ip] = (key, iv)

            key, iv = ip_keys[ics_ip]

            raw_payload = pkt_copy[Raw].load
            padded_data = pad(raw_payload, AES.block_size)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_payload = cipher.encrypt(padded_data)
            pkt_copy[Raw].load = encrypted_payload

            # Invalidate headers for recalculation
            pkt_copy[IP].len = None
            pkt_copy[IP].chksum = None
            pkt_copy[TCP].chksum = None

            # Force rebuild
            pkt_copy = Ether(bytes(pkt_copy)) if pkt_copy.haslayer(Ether) else pkt_copy.__class__(bytes(pkt_copy))
            pkt_copy.time = pkt.time  # Restore timestamp

            encrypted_count += 1

        encrypted_packets.append(pkt_copy)

    print(f"Encrypted {encrypted_count} packets (protocol={protocol}) with new keys per IP.")
    return encrypted_packets


def defense_noise_packets(train_device_packets, protocol):
    """
    Inject random noise (4-16 bytes) into Raw payloads of ICS response packets.

    Args:
        train_device_packets (list): List of Scapy packets
        protocol (str): Protocol name, e.g., "Modbus"

    Returns:
        list: List of packets with injected random noise
    """
    injected_packets = []
    injected_count = 0

    for pkt in train_device_packets:
        pre_length = extract_packet_length(pkt)
        pkt_copy = copy.deepcopy(pkt)
        if pkt_copy.haslayer(TCP) and pkt_copy.haslayer(Raw) and is_ics_port_by_protocol(pkt_copy[TCP].sport, protocol):
            raw_payload = pkt_copy[Raw].load

            # Generate random noise (4 to 16 bytes)
            noise_len = random.randint(4, 16)
            noise = os.urandom(noise_len)

            # Inject noise into payload
            pkt_copy[Raw].load = raw_payload + noise

            # Mark headers for recalculation
            if pkt_copy.haslayer(IP):
                pkt_copy[IP].len = None
                pkt_copy[IP].chksum = None
            if pkt_copy.haslayer(TCP):
                pkt_copy[TCP].chksum = None

            # Rebuild packet to recalculate fields
            pkt_copy = Ether(bytes(pkt_copy)) if pkt_copy.haslayer(Ether) else pkt_copy.__class__(bytes(pkt_copy))
            # Restore the original timestamp
            pkt_copy.time = pkt.time
            injected_count += 1
            post_length = extract_packet_length(pkt_copy)
            # print(f"Injected noise: length {pre_length} -> {post_length}, +{noise_len} bytes")

        injected_packets.append(pkt_copy)

    print(f"Injected noise into {injected_count} packets (protocol={protocol}).")
    return injected_packets


def remove_response_packets(train_device_packets, protocol):  # TODO test
    remained_packets = []
    removed_count = 0
    for pkt in train_device_packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and is_ics_port_by_protocol(pkt[TCP].sport, protocol):
            removed_count += 1
            continue
        remained_packets.append(pkt)

    print(f"Removed {removed_count} response packets (protocol={protocol}).")
    return remained_packets


root_path = dataset_path()
if __name__ == '__main__':
    file_name = "honeypot_modbus_au_round1"
    input_packets = rdpcap(protocol_pcap_file("modbus", "au", file_name, "analysis"))
    defense_mode = "diff"
    if defense_mode == "pad":
        modified_packets = defense_padding_packets(input_packets, protocol="modbus")
    elif defense_mode == "encry":
        modified_packets = defense_encryption_packets(input_packets, protocol="modbus")
    elif defense_mode == "noise":
        modified_packets = defense_noise_packets(input_packets, protocol="modbus")
    elif defense_mode == "remove":
        modified_packets = remove_response_packets(input_packets, protocol="modbus")
    elif defense_mode == "diff":
        modified_packets = defense_different_encryption_packets(input_packets, protocol="modbus")
    else:
        print(f"Bad defense mode: {defense_mode}")

    output_file = results_path("pcap", "modbus_au", "analysis", f"{file_name}_{defense_mode}.pcap", create_parent=True)
    wrpcap(output_file, modified_packets)
