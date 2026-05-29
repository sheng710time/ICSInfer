"""
Encoding: UTF-8
Description:
"""
import datetime
import os
import random
import time
from collections import defaultdict

import sklearn
from sklearn.metrics import accuracy_score

from source.basis.dataprocess import get_packets_inlist, filter_retransmission, \
    split_packets_by_ip, get_ip_labels, filter_packets_train, get_ip_list
from source.semantic_identification.semantic_identification_normalization import \
    evaluate, predict_packets, load_device_models
from source.semantic_identification.semantic_identification_train import train_packets
from source.config.config import *


def load_data(protocol, stsm_type, model_file_name, region, test_file_suffix, excluded_operations, file_number, start_file_index):
    ip_list_file = None
    if protocol == "modbus":
        ip_list_file = protocol_device_info_file("modbus")
    elif protocol == "s7":
        ip_list_file = protocol_device_info_file("s7")
    elif protocol == "enip":
        ip_list_file = protocol_device_info_file("enip")
    all_file_packets = defaultdict(dict)

    for i in range(0, file_number):
        train_pcap_file = protocol_pcap_file(protocol, region, f"{protocol}_more_round{start_file_index + i}_{region}_filtered")
        all_file_packets[f"file{i}"] = get_packets_inlist(train_pcap_file, ip_list_file)

    all_file_device_packets = {}
    all_device_ips = set()
    valid_ips = get_ip_list(ip_list_file)
    for file_key, file_packets in all_file_packets.items():
        file_packets_filtered = filter_retransmission(file_packets)
        file_packets_filtered = filter_packets_train(file_packets_filtered, protocol)
        all_file_device_packets[file_key] = split_packets_by_ip(file_packets_filtered, protocol)
        all_file_device_packets[file_key] = {key: value for key, value in all_file_device_packets[file_key].items() if key in valid_ips}
        all_device_ips.update(all_file_device_packets[file_key].keys())

    ip_labels = get_ip_labels(ip_list_file)
    label_ips = defaultdict(set)
    for ip in all_device_ips:
        label_ips[ip_labels[ip]].add(ip)

    train_ratio = 0.8
    train_ips = []
    test_ips = []
    count = 0
    ip_number_threshold = 5
    label_set_count = 0
    for label, ip_set in label_ips.items():
        if len(ip_set) >= ip_number_threshold:
            label_set_count += 1
            ip_list = list(ip_set)  # Convert set to list for shuffling
            random.shuffle(ip_list)  # Shuffle to ensure randomness
            split_idx = int(len(ip_list) * train_ratio)  # Calculate split index
            train_ips.extend(ip_list[:split_idx])  # Training set
            test_ips.extend(ip_list[split_idx:])  # Test set
        elif len(ip_set) == 1:
            count += 1

    print(f"DM_bias = {GLOBAL_DM_BIAS}")
    print(f"DL_ratio = {GLOBAL_DL_RATIO}")
    print(f"alignment_threshold = {GLOBAL_TALI}")
    print(f"operation_match_ratio >= {GLOBAL_OPERATION_MATCH}")
    print(f"packet_match_ratio >= {GLOBAL_PACKET_MATCH}")
    print(f"train_ratio = {train_ratio}")
    print(f"ip_number_threshold = {ip_number_threshold}")

    train_all_packets = defaultdict(list)
    test_all_file_packets = defaultdict()
    for file_key, file_device_packets in all_file_device_packets.items():
        test_all_packets = defaultdict(list)
        for ip, packets in file_device_packets.items():
            if ip in train_ips:
                train_all_packets[ip].extend(packets)
            elif ip in test_ips:
                test_all_packets[ip] = packets
        test_all_file_packets[file_key] = test_all_packets
    # train device models
    train_packets(protocol, train_all_packets, stsm_type, model_file_name, excluded_operations)

    device_models = load_device_models(root_path, f"{protocol}\\{model_file_name}", stsm_type)

    """ predict and evaluate each files """
    final_predictions_all = list()
    for file_key, test_all_packets in test_all_file_packets.items():
        predict_packets(protocol, test_all_packets, stsm_type, model_file_name, test_file_suffix, excluded_operations)
        final_predictions = evaluate(protocol, model_file_name, test_file_suffix)
        final_predictions_all.extend(final_predictions)

    # Extract true labels and predicted labels
    all_true_labels = [label for _, _, label, _, _ in final_predictions_all]
    all_predicted_labels = [predict_label for _, _, _, _, predict_label in final_predictions_all]
    all_accuracy = accuracy_score(all_true_labels, all_predicted_labels)
    all_f1_score = sklearn.metrics.f1_score(all_true_labels, all_predicted_labels, average="weighted")

    ip_predictions = defaultdict(list)
    ip_true_labels = {}
    for item in final_predictions_all:
        ip_predictions[(item[0], item[1])].append(item[4])
        ip_true_labels[(item[0], item[1])] = item[2]


    multi_predictions = {}
    different_ip_count = 0
    ip_count_statistics = defaultdict(int)
    ip_different_statistics = defaultdict(int)
    for ip_port, predictions in ip_predictions.items():
        pre_count = defaultdict(int)
        for prediction in predictions:
            pre_count[prediction] += 1
        ip_count_statistics[len(predictions)] += 1
        ip_different_statistics[len(pre_count.keys())] += 1
        # if len(pre_count.keys()) > 1:
        #     different_ip_count += 1
        # print(ip)
        max_label = max(pre_count, key=lambda label: pre_count[label])
        multi_predictions[ip_port] = max_label
    true_labels = list()
    predicted_labels = list()
    for ip_port in ip_true_labels.keys():
        true_labels.append(ip_true_labels[ip_port])
        predicted_labels.append(multi_predictions[ip_port])
    # Calculate accuracy
    ip_accuracy = accuracy_score(true_labels, predicted_labels)
    ip_f1_score = sklearn.metrics.f1_score(true_labels, predicted_labels, average="weighted")
    print("multi evaluation results:")
    print(f"label_set_count: {label_set_count}")
    print(f"all instances: {len(all_predicted_labels)}, all_accuracy: {all_accuracy}, all_f1_score: {all_f1_score}")
    print(f"all devices: {len(ip_true_labels.keys())}, ip_accuracy: {ip_accuracy}, ip_f1_score: {ip_f1_score}")
    # print(f"ip_count_statistics: {ip_count_statistics}")
    # print(f"ip_different_statistics: {ip_different_statistics}")
    print()



root_path = dataset_path()
if __name__ == '__main__':
    protocol = "s7"
    stsm_type = "state"
    region = "au"
    current_time_millis = int(time.time() * 1000)
    file_number = 20
    start_file_index = 41
    model_file_name = f"device_models_{stsm_type}_semantic_ip({start_file_index}-{start_file_index+file_number-1})_{region}_open_{current_time_millis}"
    test_file_suffix = ""
    print(f"model_file_name: {model_file_name}")
    excluded_operations = []
    load_data(protocol, stsm_type, model_file_name, region, test_file_suffix, excluded_operations, file_number, start_file_index)
