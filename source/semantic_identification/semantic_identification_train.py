# Encoding: utf-8
# Version: 1.0.0
import os

from source.basis.dataprocess import *
from source.semantic_identification.semantic_device_model import SemanticDeviceModel
from source.basis.feature_packet_extraction import *
from source.semantic_identification.semantic_temporal_state_model_state import \
    SemanticTemporalStateModelState
from source.basis.tsm_generation import *
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


def evaluate_device_models(device_models, protocol, model_file_name):
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
    str_device_models = []
    model_headers = set()
    for device_ip_port, device_model in device_models.items():
        model_distribution[len(device_model.operations)] +=1
        # model_headers.update(device_model.operations)
        # str_device_models.append(device_model.to_string_statistical())
    # sorted_str_device_models = sorted(str_device_models, key=lambda d: d['device_ip'])
    # output_device_models(root_path, model_headers, sorted_str_device_models, f"{protocol}\\statistical_{model_file_name}")
    print(f"Total number of device_models: {len(device_models)}")
    # Sort keys by descending order
    for key in sorted(model_distribution, reverse=True):
        print(f"Length: {key}, Number: {model_distribution[key]}")


def output_device_models(output_path, headers, str_device_models, file_name):
    """
    Output all device_models with their length sequences and time_distributions.

    Parameters
    ----------
    output_path: output file path
    headers: set of strings appearing in the keys of str_device_models
    str_device_models: list, [{"device_ip": , operation: ...}]
    file_name:

    Returns
    -------
    None
    """
    # Output CSV file name
    csv_file = analysis_file(file_name)
    # Write to CSV
    fieldnames = ["device_ip", "port"] + list(headers)
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(str_device_models)


def train_file(protocol, stsm_type, model_file_name, region, excluded_operations):
    require_supported_protocol(protocol)
    ip_list_file = protocol_device_info_file(protocol)
    require_existing_file(ip_list_file, f"{protocol} device information CSV")
    train_all_packets = []
    pcap_directory = protocol_pcap_directory(protocol, region, "train")
    require_existing_directory(pcap_directory, f"{protocol} training pcap directory")
    pcap_files = [f for f in os.listdir(pcap_directory) if f.endswith(".pcap")]
    pcap_files.sort()  # sort files by the file name
    if not pcap_files:
        print(f"No pcap files found in {pcap_directory}")
        return []
    for pcap_file in pcap_files:
        pcap_path = os.path.join(pcap_directory, pcap_file)
        train_all_packets.extend(get_packets_inlist(pcap_path, ip_list_file))

    train_filtered_packets = filter_retransmission(train_all_packets)  # Call filter_retransmission() before filter_packets_train(), because filter_retransmission() is unrelated to other factors, but filter_packets_train() can be impacted by retransmission packets
    train_filtered_packets = filter_packets_train(train_filtered_packets, protocol)
    train_device_packets = split_packets_by_ip(train_filtered_packets, protocol)
    train_packets(protocol, train_device_packets, stsm_type, model_file_name, excluded_operations)


def train_packets(protocol, train_device_packets, stsm_type, model_file_name, excluded_operations):
    if stsm_type != "state":
        raise ValueError(f"Unsupported stsm_type: {stsm_type}. Only 'state' is supported.")
    train_state(protocol, train_device_packets, stsm_type, model_file_name, excluded_operations)


def train_state(protocol, train_device_packets, stsm_type, model_file_name, excluded_operations):
    interval_time = 100  # time threshold for splitting flows of the same 5-tuple [s]
    device_models = defaultdict(list)
    for device_ip, d_packets in train_device_packets.items():
        port_packets = split_packets_by_port(d_packets, protocol)
        for port, p_packets in port_packets.items():
            all_flows = create_flows(p_packets, interval_time)
            operation_flows, operations = group_flows_excluded(all_flows, excluded_operations, protocol)
            operation_flow_ts_packets = extract_flow_ts_packets_semantic_hash(operation_flows, protocol)
            device_tsms = []
            for operation, flow_ts_packets in operation_flow_ts_packets.items():
                flow_number = len(flow_ts_packets)
                init_clusters = cluster_ts_packets_strict(flow_number, flow_ts_packets)
                if len(init_clusters) == 0:
                    continue
                split_clusters = split_init_clusters_strict(flow_number, init_clusters)
                if len(split_clusters) == 0:
                    continue
                flow_ts_packets = aggregate_ts_packets(split_clusters)
                flow_ts_packets = align_flows(flow_number/2, flow_ts_packets)
                if len(flow_ts_packets) == 0:  # if there is no representative flow_ts_packets, ignore this operation
                    continue
                device_tsms.append(SemanticTemporalStateModelState.construct_flows(operation, flow_ts_packets))
            if len(device_tsms) > 0:  # filter out empty list
                device_models[(device_ip, port)] = SemanticDeviceModel(device_ip, port, device_tsms)
    """ Evaluate device_models"""
    evaluate_device_models(device_models, protocol, f"{protocol}\\{model_file_name}")
    """ Output device_models """
    str_device_models = []
    model_headers = set()
    for device_model in device_models.values():
        model_headers.update(device_model.operations)
        str_device_models.append(device_model.to_string(stsm_type))
    output_device_models(root_path, model_headers, str_device_models, f"{protocol}\\{model_file_name}")


root_path = dataset_path()
if __name__ == '__main__':
    protocol = "enip"  # ICS protocol
    stsm_type = "state"  # The type of the identification system
    region = "au"  # The origin of the dataset
    file_number = 16  # The number of train PCAP files
    start_file_index = 50  # The index of the first training PCAP file
    print(f"DM_bias = {GLOBAL_DM_BIAS}")
    print(f"DL_ratio = {GLOBAL_DL_RATIO}")
    print(f"alignment_threshold = {GLOBAL_TALI}")
    print(f"operation_match_ratio >= {GLOBAL_OPERATION_MATCH}")
    print(f"packet_match_ratio >= {GLOBAL_PACKET_MATCH}")
    model_file_name = f"device_models_{stsm_type}_semantic_ip({start_file_index}-{start_file_index + file_number -1})_{region}_align_{GLOBAL_TALI}_no_pay"

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
    # excluded_operations = [
    #     b'c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00']#,
        # b'o\x00\x16\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x06\x00\x01\x02 \x01$\x01',
        # b'd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        # b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00']  # for ENIP
    excluded_operations = []
    train_file(protocol, stsm_type, model_file_name, region, excluded_operations)
