"""
Encoding: UTF-8
Description:
"""
import os

from source.basis.dataprocess import *
from source.identification.device_model import DeviceModel
from source.basis.feature_packet_extraction import *
from source.basis.tsm_generation import *
from source.label_utils import load_ip_labels
from source.config.config import *


def reset_all_models(device_models):
    """
    Reset all device_models to their initial values.

    Parameters
    ----------
    device_models: dictionary, {device_ip: device_model}

    Returns
    -------
    None
    """
    for device_model in device_models.values():
        device_model.reset()


def evaluate_device_models(device_models):
    """
    Evaluate the distribution of device_models.

    Parameters
    ----------
    device_models: dictionary, {device_ip_port: device_model}

    Returns
    -------
    None
    """
    model_distribution = defaultdict(int)
    for device_ip_port, device_model in device_models.items():
        model_distribution[len(device_model.operations)] +=1

    print(f"Total number of device_models: {len(device_models)}")
    # Sort keys by descending order
    for key in sorted(model_distribution, reverse=True):
        print(f"Length: {key}, Number: {model_distribution[key]}")


def output_device_models(output_path, headers, str_device_models):
    """
    Output all device_models with their length sequences and time_distributions.

    Parameters
    ----------
    output_path: output file path
    headers: set of strings appearing in the keys of str_device_models
    str_device_models: list, [{"device_ip": , operation: ...}]

    Returns
    -------
    None
    """
    # Output CSV file name
    csv_file = analysis_file("device_models")
    # Write to CSV
    fieldnames = ["device_ip", "port"] + list(headers)
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(str_device_models)


def load_device_models(model_path):
    """
    Load device models from device_models csv file

    Parameters
    ----------
    model_path: file path of device_models csv file

    Returns
    -------
    device_models: device models
    """
    # root_path = results_path(ANALYSIS_DIR_NAME)
    device_models_file = analysis_file("(18-26 common1-3)device_models", create_parent=False)
    with open(device_models_file, mode="r") as file:
        csv_reader = csv.DictReader(file)
        device_models = defaultdict(list)
        for row in csv_reader:
            device_ip = row["device_ip"]
            port = int(row["port"])
            tsms = []
            for item in row.items():
                if item[0] != "device_ip" and item[0] != "port":
                    if item[1] != "":
                        # Convert string to bytes
                        operation = eval(item[0])
                        tsms.append(TemporalStateModel.construct_str_tsm(operation, item[1]))
            device_models[(device_ip, port)] = DeviceModel(device_ip, port, tsms)
    return device_models


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


def train():
    round_number = 9
    common_threshold = round_number * 1/3
    interval_time = 100  # time threshold for splitting flows of the same 5-tuple [s]
    ip_list_file = protocol_device_info_file("modbus")
    train_pcap_files = [
        protocol_pcap_file("modbus", "au", "119.52.189.9_27"),
        protocol_pcap_file("modbus", "au", "119.52.189.9_28"),
        protocol_pcap_file("modbus", "au", "119.52.189.9_29_1-2"),
        protocol_pcap_file("modbus", "au", "119.52.189.9_30"),
    ]
    train_all_packets = []
    for train_pcap_file in train_pcap_files:
        train_all_packets.extend(get_packets_inlist(train_pcap_file, ip_list_file))
    # train_all_packets.extend(get_packets_inlist(train_pcap_file5, ip_list_file))
    # train_all_packets.extend(get_packets_inlist(train_pcap_file6, ip_list_file))
    # train_all_packets.extend(get_packets_inlist(train_pcap_file7, ip_list_file))
    # train_all_packets.extend(get_packets_inlist(train_pcap_file8, ip_list_file))
    # train_all_packets.extend(get_packets_inlist(train_pcap_file9, ip_list_file))
    train_filtered_packets = filter_retransmission(train_all_packets)  # Call filter_retransmission() before filter_packets_train(), because filter_retransmission() is unrelated to other factors, but filter_packets_train() can be impacted by retransmission packets
    train_filtered_packets = filter_packets_train(train_filtered_packets)
    train_device_packets = split_packets_by_ip(train_filtered_packets)
    device_models = defaultdict(list)
    for device_ip, d_packets in train_device_packets.items():
        port_packets = split_packets_by_port(d_packets)
        for port, p_packets in port_packets.items():
            all_flows = create_flows(p_packets, interval_time)
            operation_flows, operations = group_flows(all_flows)
            operation_flow_ts_packets = extract_flow_ts_packets_semantic(operation_flows)
            device_tsms = []
            for operation, flow_ts_packets in operation_flow_ts_packets.items():
                init_clusters = cluster_ts_packets_strict(flow_ts_packets)
                if len(init_clusters) == 0:
                    # print(f"init_clusters: {device_ip}, {port}, {operation}")
                    continue
                split_clusters = split_init_clusters_strict(len(flow_ts_packets), init_clusters)
                if len(split_clusters) == 0:
                    # print(f"split_clusters: {device_ip}, {port}, {operation}")
                    continue
                flow_ts_packets = aggregate_ts_packets(split_clusters)
                flow_ts_packets = align_flows(len(flow_ts_packets), flow_ts_packets)
                if len(flow_ts_packets) == 0:  # if there is no representative flow_ts_packets, ignore this operation
                    continue
                device_tsms.append(TemporalStateModel.construct_flows(operation, flow_ts_packets))
            if len(device_tsms) > 0:  # filter out empty list
                device_models[(device_ip, port)] = DeviceModel(device_ip, port, device_tsms)
    print()
    """ Evaluate device_models"""
    evaluate_device_models(device_models)
    """ Output device_models """
    str_device_models = []
    model_headers = set()
    for device_model in device_models.values():
        model_headers.update(device_model.operations)
        str_device_models.append(device_model.to_string())
    # output_device_models(root_path, model_headers, str_device_models)


def count():
    interval_time = 100
    round_number = 9
    ip_list_file = protocol_device_info_file("modbus")
    pcap_file_paths = [
        protocol_pcap_file("modbus", "au", f"modbus_more_round{round_id}_au")
        for round_id in range(18, 27)
    ]

    device_round_operation = defaultdict(lambda: [None] * round_number)
    for file_index in range(len(pcap_file_paths)):
        all_packets = get_packets_inlist(pcap_file_paths[file_index], ip_list_file)
        train_device_packets = split_packets_by_ip(all_packets)
        for device_ip, d_packets in train_device_packets.items():
            port_packets = split_packets_by_port(d_packets)
            for port, p_packets in port_packets.items():
                all_flows = create_flows(p_packets, interval_time)
                operation_flows, operations = group_flows(all_flows)
                device_round_operation[(device_ip, port)][file_index] = len(operation_flows)
    for ip_port, operations in device_round_operation.items():
        print(f"ip_port: {ip_port}, operations: {operations}")


root_path = dataset_path()
if __name__ == '__main__':
    train()
    # count()
