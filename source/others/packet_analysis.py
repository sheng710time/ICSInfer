# Encoding: utf-8
# Version: 1.0.0
import os
from collections import OrderedDict

from numpy import average

from source.basis.dataprocess import *
from source.basis.tsm_generation import *
from source.config.config import *


def extract_device_operation_flows(filepath):
    """
    Extract device_operation_flows from a pcap file

    Parameters
    ----------
    filepath: pcap filepath

    Returns
    -------
    device_operation_flows: dictionary, {device_ip: {operation: [flow]}}
    """
    train_all_packets = []
    train_all_packets.extend(get_packets(filepath))
    train_filtered_packets = filter_retransmission(train_all_packets)  # Call filter_retransmission() before filter_packets_train(), because filter_retransmission() is unrelated to other factors, but filter_packets_train() can be impacted by retransmission packets
    train_filtered_packets = filter_packets_train(train_filtered_packets)
    train_device_packets = split_packets_by_ip(train_filtered_packets)
    device_operation_flows  = defaultdict(list)
    for device_ip, packets in train_device_packets.items():
        all_flows = create_flows(packets)
        operation_flows, operations = group_flows(all_flows)
        operation_flow_ts_packets = extract_flow_ts_packets(operation_flows)
        device_operation_flows[device_ip].append(operation_flow_ts_packets)
    return device_operation_flows


def output_device_operation_flows(output_path, headers, str_all_device_operation_flows):
    """
    Output all device_operation_flows.

    Parameters
    ----------
    output_path: output file path
    headers: ["device_ip", "operation", "flow"]
    str_all_device_operation_flows: list, [{"device_ip": , "operation": , "flow": ...}]

    Returns
    -------
    None
    """
    os.makedirs(output_path, exist_ok=True)
    # Output CSV file name
    csv_file = os.path.join(output_path, "device_operation_flows_absolute_time.csv")
    # Write to CSV
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=headers)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(str_all_device_operation_flows)


def aggregate_device_operation_flows():
    """
    Aggregate all device_operation_flows from some pcap files.

    Returns
    -------
    None
    """
    output_dir = results_path(ANALYSIS_DIR_NAME, "pcap")
    all_device_operation_flows  = defaultdict(list)
    train_pcap_files = [
        protocol_pcap_file("modbus", "au", f"modbus_more_round{round_id}_au")
        for round_id in range(18, 21)
    ]
    for train_pcap_file in train_pcap_files:
        my_device_operation_flows = extract_device_operation_flows(train_pcap_file)
        for device_ip, operation_flows in my_device_operation_flows.items():
            all_device_operation_flows[device_ip].extend(operation_flows)

    str_all_device_operation_flows = []
    for device_ip, operation_flows_list in all_device_operation_flows.items():
        operation_flows_dict = defaultdict(list)
        for operation_flows in operation_flows_list:
            for operation, flows in operation_flows.items():
                operation_flows_dict[operation].append(flows)

        for operation, flows in operation_flows_dict.items():
            for flow in flows:
                only_value = next(iter(flow.values()))
                str_flow = ", ".join(f"({float(a):.6f}::{b}::{c})" for a, b, c in only_value)
                str_all_device_operation_flows.append({"device_ip": device_ip, "operation": operation, "flow": str_flow})

    headers = ["device_ip", "operation", "flow"]
    output_device_operation_flows(output_dir, headers, str_all_device_operation_flows)


def extract_device_flow_distributions_from_pcap(filepath, ip_list_file, csv_file):
    interval_time = 100
    train_all_packets = []
    train_all_packets.extend(get_packets_inlist(filepath, ip_list_file))
    # train_filtered_packets = filter_retransmission(train_all_packets)  # Call filter_retransmission() before filter_packets_train(), because filter_retransmission() is unrelated to other factors, but filter_packets_train() can be impacted by retransmission packets
    # train_filtered_packets = filter_packets_train(train_filtered_packets)
    train_device_packets = split_packets_by_ip(train_all_packets)

    device_operation_flows  = defaultdict()
    operation_set = set()
    for device_ip, d_packets in train_device_packets.items():
        # print(f"Device ip: {device_ip}")
        port_packets = split_packets_by_port(d_packets)
        for port, p_packets in port_packets.items():
            # print(f"Port: {port}")
            all_flows = create_flows(p_packets, interval_time)
            operation_flows, operations = group_flows(all_flows)
            # operation_flows, operations = group_flows_excluded(all_flows, excluded_operations)
            device_operation_flows[(device_ip, port)]= operation_flows
            operation_set.update(operations)

    device_operation_flows_str = []
    for ip_port, operation_flows in device_operation_flows.items():
        device_flow_str = {"ip_port": ip_port}
        for ope, flows in operation_flows.items():
            pkt_count = 0
            for flow in flows:
                for flow_key, packets in flow.items():
                    pkt_count += len(packets)
            device_flow_str[ope] = pkt_count
        device_operation_flows_str.append(device_flow_str)

    # Write to CSV
    header = ["ip_port"]
    operations = list(operation_set)
    operations.sort()
    header.extend(operations)
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=list(header))
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(device_operation_flows_str)


def extract_device_flow_distributions(protocol, country):
    # protocol = "s7"
    # country = "au"
    file_number = 20
    start_file_index = 41
    ip_list_file = None

    if protocol == "modbus":
        ip_list_file = protocol_device_info_file("modbus")
    elif protocol == "s7":
        ip_list_file = protocol_device_info_file("s7")

    for i in range(0, file_number):
        pcap_file = protocol_pcap_file(protocol, country, f"{protocol}_more_round{start_file_index + i}_{country}_filtered")
        csv_file = results_path("pcap", f"{protocol}_{country}", f"{protocol}_more_round{start_file_index + i}_{country}_flows.csv", create_parent=True)
        extract_device_flow_distributions_from_pcap(pcap_file, ip_list_file, csv_file)


def analyze_device_flow_distributions(protocol, country):
    # protocol = "modbus"
    # country = "cn"
    file_number = 15
    start_file_index = 41
    # device_round_flows = defaultdict(lambda: defaultdict(list))
    device_round_flows = []
    header = []
    get_header = False
    for i in range(0, file_number):
        round = start_file_index + i
        csv_file = results_path("pcap", f"{protocol}_{country}", f"{protocol}_more_round{round}_{country}_flows.csv")
        with open(csv_file, mode="r") as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                device_round_flow = defaultdict()
                device_round_flow["round"] = round
                if not get_header:
                    for item in row.items():
                        header.append(item[0])
                    header.append("round")
                    get_header = True

                for item in row.items():
                    device_round_flow[item[0]] = item[1]
                device_round_flows.append(device_round_flow)

    ip_round_count = defaultdict(list)
    for item in device_round_flows:
        ip_round_count[item["ip_port"]].append(item["round"])

    # Write to CSV
    output_file = results_path("pcap", f"{protocol}_{country}", f"{protocol}_more_{country}_flows(21-35).csv", create_parent=True)
    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=list(header))
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(device_round_flows)

    print()


def analyze_directional_packet_sequence_distributions_by_round(protocol, country):
    """
    Extract directional packet sequences distributed in 20 rounds per device, for example, device A has 5 different numbers and device B has 10 different numbers
    Parameters
    ----------
    protocol
    country

    Returns
    -------

    """
    # protocol = "s7"
    # country = "au"
    file_number = 10
    start_file_index = 41
    ip_list_file = None

    if protocol == "modbus":
        ip_list_file = protocol_device_info_file("modbus")
    elif protocol == "s7":
        ip_list_file = protocol_device_info_file("s7")

    ip_port_all_packets = defaultdict(list)
    for i in range(0, file_number):
        pcap_file = protocol_pcap_file(protocol, country, f"{protocol}_more_round{start_file_index + i}_{country}_filtered")
        my_all_packets = get_packets_inlist(pcap_file, ip_list_file)
        device_round_all_packets = split_packets_by_ip(my_all_packets, protocol)
        for device_ip, d_packets in device_round_all_packets.items():
            port_packets = split_packets_by_port(d_packets, protocol)
            for port, p_packets in port_packets.items():
                packet_directional_length = []
                for pkt in p_packets:
                    if is_ics_port_by_protocol(pkt.dport, protocol):
                        packet_directional_length.append(f"C-{extract_packet_length(pkt)}")
                    elif is_ics_port_by_protocol(pkt.sport, protocol):
                        packet_directional_length.append(f"S-{extract_packet_length(pkt)}")
                packet_directional_length_str = ", ".join(packet_directional_length)
                ip_port_all_packets[(device_ip, port)].append(packet_directional_length_str)

    ip_port_len_frequencies = defaultdict(list)
    len_frequencies_count = defaultdict(int)
    for ip_port, packet_lens in ip_port_all_packets.items():
        freq = Counter(packet_lens)
        ip_port_len_frequencies[ip_port] = len(freq.keys())
        len_frequencies_count[len(freq.keys())] += 1

    # Sort by key and convert to OrderedDict
    sorted_len_frequencies_count = OrderedDict(sorted(len_frequencies_count.items()))
    print("sorted_len_frequencies_count: ")
    for item in sorted_len_frequencies_count.items():
        print(item[0], item[1])


def analyze_directional_packet_sequence_distributions_by_operation(protocol, country):
    """
    Extract directional packet sequences distributed in 20 rounds per device, for example, device A has 5 different numbers and device B has 10 different numbers
    Parameters
    ----------
    protocol
    country

    Returns
    -------

    """
    # protocol = "s7"
    # country = "au"
    file_number = 10
    start_file_index = 41
    ip_list_file = None

    if protocol == "modbus":
        ip_list_file = protocol_device_info_file("modbus")
    elif protocol == "s7":
        ip_list_file = protocol_device_info_file("s7")

    operation_sequences = defaultdict(list)
    for i in range(0, file_number):
        pcap_file = protocol_pcap_file(protocol, country, f"{protocol}_more_round{start_file_index + i}_{country}_filtered")
        my_all_packets = get_packets_inlist(pcap_file, ip_list_file)
        device_round_all_packets = split_packets_by_ip(my_all_packets, protocol)
        for device_ip, d_packets in device_round_all_packets.items():
            port_packets = split_packets_by_port(d_packets, protocol)
            for port, p_packets in port_packets.items():
                all_flows = create_flows(p_packets, interval_time = 100)
                operation_flows, operations = group_flows(all_flows, protocol)
                for operation, flows in operation_flows.items():
                    packet_directional_length = []
                    for flow in flows:
                        for flow_key, packets in flow.items():
                            for pkt in packets:
                                if is_ics_port_by_protocol(pkt.dport, protocol):
                                    packet_directional_length.append(f"C-{extract_packet_length(pkt)}")
                                elif is_ics_port_by_protocol(pkt.sport, protocol):
                                    packet_directional_length.append(f"S-{extract_packet_length(pkt)}")
                    packet_directional_length_str = ", ".join(packet_directional_length)
                    operation_sequences[operation].append(packet_directional_length_str)

    len_frequencies_count = defaultdict(int)
    for operation, sequences in operation_sequences.items():
        freq = Counter(sequences)
        len_frequencies_count[operation] = freq

    sorted_len_frequencies_count = OrderedDict(sorted(len_frequencies_count.items()))
    print("sorted_len_frequencies_count: ")
    for item in sorted_len_frequencies_count.items():
        print(item[0], item[1])


def scanning_duration_for_device(protocol, country, test_file_suffix, root_path):
    ip_list_file = None
    if protocol == "modbus":
        ip_list_file = source_device_info_file("modbus", "honeypot")
    elif protocol == "s7":
        ip_list_file = source_device_info_file("s7", "honeypot")
    test_pcap_file1 = protocol_pcap_file(protocol, country, f"{protocol}_{test_file_suffix}_{country}_filtered")
    test_all_packets = []
    test_all_packets.extend(get_packets_inlist(test_pcap_file1, ip_list_file))
    test_device_packets = split_packets_by_ip(test_all_packets, protocol)
    interval_time = 100  # time threshold for splitting flows of the same 5-tuple [s]
    durations = list()
    for device_ip, d_packets in test_device_packets.items():
        port_packets = split_packets_by_port(d_packets, protocol)
        for port, p_packets in port_packets.items():
            all_flows = create_flows(p_packets, interval_time)
            total_time = 0
            for flow in all_flows.values():
                total_time += float(flow[-1].time - flow[0].time)
            durations.append(total_time)
    print(f"average duration: {average(durations)}")


def calculate_total_bytes_of_csv():
    file_path = analysis_file("modbus\\device_models_state_semantic_ip(41-56)_au_align_0.8", create_parent=False)

    with open(file_path, 'rb') as f:
        content = f.read()  # Read the raw binary data.

    total_bytes = len(content)
    print(f"Total size of CSV file: {total_bytes} bytes")
    print(f"Average size of device signatures: {total_bytes/595/1000} KB")


def parse_enip():
    pcap_file = dataset_path("external", "CORMAND2", "ABB_report operation data39.pcapng")
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


def main():
    # filepath = dataset_path("ics", "modbus", "modbus_more_round55_cn.pcap")
    # ip_list_file = protocol_device_info_file("modbus")
    # csv_file = results_path("pcap", "modbus_cn", "modbus_more_round55_cn_flows.csv", create_parent=True)
    # extract_device_flow_distributions_from_pcap(filepath, ip_list_file, csv_file)
    protocol = "modbus"
    country = "au"
    # extract_device_flow_distributions(protocol, country)
    # analyze_device_flow_distributions(protocol, country)
    # analyze_device_packet_distributions(protocol, country)
    # analyze_directional_packet_sequence_distributions_by_round(protocol, country)
    # analyze_directional_packet_sequence_distributions_by_operation(protocol, country)
    # scanning_duration_for_device(protocol, country, "more_round57", dataset_path())
    # calculate_total_bytes_of_csv()
    parse_enip()

    print()


if __name__ == '__main__':
    main()
