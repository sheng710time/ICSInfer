"""
Encoding: UTF-8
Description:
"""
import os
from collections import defaultdict
from itertools import zip_longest
from collections import defaultdict, Counter

from source.basis.dataprocess import (
    create_flows,
    extract_flow_ts_packets,
    extract_flow_ts_packets_semantic_hash,
    filter_packets_train,
    filter_retransmission,
    get_packets_inlist,
    group_flows_excluded,
    is_ics_port_by_protocol,
    split_packets_by_ip,
    split_packets_by_port,
)
from source.config.config import *


def network_dynamics_analysis(protocol, region, excluded_operations):
    ip_list_file = None
    if protocol == "modbus":
        ip_list_file = protocol_device_info_file("modbus")
    elif protocol == "s7":
        ip_list_file = protocol_device_info_file("s7")
    elif protocol == "enip":
        ip_list_file = protocol_device_info_file("enip")
    train_all_packets = []

    pcap_directory = protocol_pcap_directory(protocol, region, "analysis")
    pcap_files = [f for f in os.listdir(pcap_directory) if f.endswith(".pcap")]
    pcap_files.sort()  # sort files by the file name
    if not pcap_files:
        print(f"No pcap files found in {pcap_directory}")
        return []
    device_dir_len_sequences = defaultdict(list)
    round = 0
    for pcap_file in pcap_files:
        pcap_path = os.path.join(pcap_directory, pcap_file)
        round_packets = get_packets_inlist(pcap_path, ip_list_file)
        train_device_packets = split_packets_by_ip(round_packets, protocol)
        for device_ip, d_packets in train_device_packets.items():
            port_packets = split_packets_by_port(d_packets, protocol)
            for port, p_packets in port_packets.items():
                split_flows = create_flows(p_packets, interval_time = 100)
                all_flows = list(split_flows.values())
                all_flows.sort(key=lambda flow: flow[0].time)
                flow_dir_len_sequences = list()
                for flow in all_flows:
                    dir_len_sequence = list()
                    for packet in flow:
                        if is_ics_port_by_protocol(packet.dport, protocol):
                            dir_len_sequence.append(f"C-{len(packet)}")
                        elif is_ics_port_by_protocol(packet.sport, protocol):
                            dir_len_sequence.append(f"S-{len(packet)}")
                    flow_dir_len_sequences.append(dir_len_sequence)
        device_dir_len_sequences[(device_ip, port, round)] = flow_dir_len_sequences
        round += 1

    device_index_round_sequences = defaultdict(list)
    for device, device_sequences in device_dir_len_sequences.items():
        # print(device)
        device_ip, port = device[0], device[1]
        for a in range(len(device_sequences)):
            device_index_round_sequences[(device_ip, port, a)].append(device_sequences[a])
            # print(device_sequences[a])

    for device, device_sequences in device_index_round_sequences.items():
        print(device)
        # for sequence in device_sequences:
        #     print(sequence)
        for row in zip_longest(*device_sequences, fillvalue="--"):
            print(row)
        # for row in zip(*device_sequences):
        #     print(row)
    # print(device_dir_len_sequences)



    # train_filtered_packets = filter_retransmission(train_all_packets)  # Call filter_retransmission() before filter_packets_train(), because filter_retransmission() is unrelated to other factors, but filter_packets_train() can be impacted by retransmission packets
    # train_filtered_packets = filter_packets_train(train_filtered_packets, protocol)
    # train_device_packets = split_packets_by_ip(train_all_packets, protocol)
    # interval_time = 100  # time threshold for splitting flows of the same 5-tuple [s]
    # device_operations_sequences = defaultdict(list)
    # device_operations_statistics = defaultdict(int)
    # for device_ip, d_packets in train_device_packets.items():
    #     port_packets = split_packets_by_port(d_packets, protocol)
    #     for port, p_packets in port_packets.items():
    #         all_flows = create_flows(p_packets, interval_time)
    #         operation_flows, operations = group_flows_excluded(all_flows, excluded_operations, protocol)
    #         operation_flow_ts_packets = extract_flow_ts_packets(operation_flows, protocol)
    #         operation_dir_len_sequence = defaultdict(list)
    #         operation_dir_len_statistics = defaultdict(int)
    #         for operation, flow_ts_packets in operation_flow_ts_packets.items():
    #             for flow in flow_ts_packets:
    #                 dir_len_sequence = ''.join([t[1] for t in flow])
    #                 operation_dir_len_sequence[operation].append(dir_len_sequence)
    #             operation_dir_len_statistics[operation].append(len(set(operation_dir_len_sequence[operation])))
    #         device_operations_sequences[(device_ip, port)] = operation_dir_len_sequence
    #         device_operations_statistics[(device_ip, port)] = operation_dir_len_statistics
    # print(device_operations_sequences)
    # print(device_operations_statistics)


def network_dynamics_analysis_NVS(protocol, region, excluded_operations=None,
                             interval_time=100, max_rounds=20,
                             use_filtered_packets=True,
                             drop_non_ics_packets=True,
                             join_with_delim=True):
    """
    For each device and each pcap round:
        build ONE ordered dir-len token sequence from ALL packets in that pcap (time-ordered),
        then compare sequences across rounds to count variants.

    Device key: (device_ip, port) by default.
      - If you want per-IP only: replace dev_key = (device_ip, port) with dev_key = device_ip.

    A "variant" is the entire ordered token sequence in one round, represented as tuple[str] (hashable).

    Returns:
        dist: Counter {k_variants: num_devices}
        per_device_k: {(device_ip, port): k_variants}
        per_device_variants: {(device_ip, port): set(tuple(tokens))}
    """

    # ---- choose ip list file ----
    if protocol == "modbus":
        ip_list_file = protocol_device_info_file("modbus")
    elif protocol == "s7":
        ip_list_file = protocol_device_info_file("s7")
    elif protocol == "enip":
        ip_list_file = protocol_device_info_file("enip")
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    # ---- locate pcap files ----
    pcap_directory = protocol_pcap_directory(protocol, region, "analysis")
    pcap_files = [f for f in os.listdir(pcap_directory) if f.endswith(".pcap")]
    pcap_files.sort()

    if not pcap_files:
        print(f"No pcap files found in {pcap_directory}")
        return Counter(), {}, {}

    pcap_files = pcap_files[:max_rounds]

    # ---- variants across rounds (per device) ----
    per_device_variants = defaultdict(set)  # {(ip,port): set(tuple(tokens))}

    for round_idx, pcap_file in enumerate(pcap_files):
        pcap_path = os.path.join(pcap_directory, pcap_file)

        # packets for this round
        round_packets = get_packets_inlist(pcap_path, ip_list_file)

        if use_filtered_packets:
            round_packets = filter_retransmission(round_packets)
            round_packets = filter_packets_train(round_packets, protocol)

        # split by device ip
        round_device_packets = split_packets_by_ip(round_packets, protocol)

        for device_ip, d_packets in round_device_packets.items():
            # split by port (so one device may have multiple endpoints)
            port_packets = split_packets_by_port(d_packets, protocol)

            for port, p_packets in port_packets.items():
                if not p_packets:
                    continue

                # IMPORTANT: this round+device+port -> ONE ordered sequence from ALL packets
                # Sort all packets by timestamp (scapy packets usually have .time)
                p_packets_sorted = sorted(p_packets, key=lambda pkt: getattr(pkt, "time", 0))

                tokens = []
                for pkt in p_packets_sorted:
                    # Keep only packets involving the ICS port for this protocol
                    is_dport_ics = is_ics_port_by_protocol(pkt.dport, protocol)
                    is_sport_ics = is_ics_port_by_protocol(pkt.sport, protocol)

                    if drop_non_ics_packets and (not is_dport_ics) and (not is_sport_ics):
                        continue

                    if is_dport_ics:
                        tokens.append(f"C-{len(pkt)}")  # client -> server
                    elif is_sport_ics:
                        tokens.append(f"S-{len(pkt)}")  # server -> client

                # Optionally, skip empty sequence
                if not tokens:
                    continue

                # Variant representation
                # Use tuple for hashing. If you prefer a single string, you can join it.
                if join_with_delim:
                    variant = tuple(tokens)  # robust + no delimiter collision
                else:
                    variant = tuple(tokens)

                # device key
                dev_key = (device_ip, port)
                # If you want per-IP only, use:
                # dev_key = device_ip

                per_device_variants[dev_key].add(variant)

    # ---- distribution: k variants -> num devices ----
    per_device_k = {dev: len(vset) for dev, vset in per_device_variants.items()}
    dist = Counter(per_device_k.values())

    print(f"[network_dynamics_analysis] protocol={protocol}, region={region}, rounds={len(pcap_files)}")
    for k in sorted(dist):
        print(f"  {k} variants: {dist[k]} devices")
    print(f"  total devices: {len(per_device_k)}")

    return dist, per_device_k, per_device_variants


root_path = dataset_path()
if __name__ == '__main__':
    protocol = "enip"  # ICS protocol
    region = "au"  # The origin of the dataset

    """ For the ablation experiment """
    # excluded_operations = [b'\x00\x01\x00\x00\x00\x05\x01+\x0e\x01\x00',
    #                        b'\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x01',
    #                        b'\x00\x01\x00\x00\x00\x06\x01\x02\x00\x00\x00\x01',
    #                        b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01',
    #                        b'\x00\x01\x00\x00\x00\x02\x01\x11']  # for modbus
    # excluded_operations = [b'\x03\x00\x00!\x02\xf0\x802\x07\x00\x00\x00\x01\x00\x08\x00\x08\x00\x01\x12\x04\x11D\x01\x00\xff\t\x00\x04\x00\x11\x00\x00',
    #                        b'\x03\x00\x00!\x02\xf0\x802\x07\x00\x00\x00\x01\x00\x08\x00\x08\x00\x01\x12\x04\x11D\x01\x00\xff\t\x00\x04\x00\x12\x00\x00',
    #                        b'\x03\x00\x00!\x02\xf0\x802\x07\x00\x00\x00\x01\x00\x08\x00\x08\x00\x01\x12\x04\x11D\x01\x00\xff\t\x00\x04\x00\x13\x00\x00',
    #                        b'\x03\x00\x00!\x02\xf0\x802\x07\x00\x00\x00\x01\x00\x08\x00\x08\x00\x01\x12\x04\x11D\x01\x00\xff\t\x00\x04\x00\x14\x00\x00']  # for s7
    excluded_operations = []

    # network_dynamics_analysis(protocol, region, excluded_operations)
    network_dynamics_analysis_NVS(protocol, region, excluded_operations)
