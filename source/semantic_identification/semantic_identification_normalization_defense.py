# Encoding: utf-8
# Version: 1.0.0
import os
import time

import numpy as np
import sklearn
from numpy import mean
from numpy.ma.extras import average
from sklearn.metrics import accuracy_score

from source.basis.dataprocess import *
from source.basis.tsm_generation import *
from source.semantic_identification.reconnaissance_defense import *
from source.semantic_identification.semantic_device_model import SemanticDeviceModel
from source.semantic_identification.semantic_identification_train import \
    evaluate_device_models
from source.semantic_identification.semantic_temporal_state_model_state import \
    SemanticTemporalStateModelState
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


def output_device_predictions(output_path, headers, str_device_predictions, file_name):
    """
    Output device predictions from function predict().

    Parameters
    ----------
    output_path: output file path
    headers: ["device_ip", "port", "predictions"]
    str_device_predictions: list, [{"device_ip": , "port": , "predictions": }]
    file_name:

    Returns
    -------
    None
    """
    # Output CSV file name
    csv_file = analysis_file(file_name)
    # Write to CSV
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=headers)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(str_device_predictions)


def get_device_predictions(device_predictions_file):
    """
    Load device predictions from device_predictions_file

    Parameters
    ----------
    device_predictions_file

    Returns
    -------
    device_predictions: dictionary, {(device_ip, port): [(device_ip, port, match probability)]}
    """
    device_predictions = defaultdict(list)
    with open(device_predictions_file, mode="r") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            device_predictions[(row["device_ip"], row["port"])] = row["predictions"].split(", ") if row["predictions"]!="" else []
    return device_predictions


def output_device_evaluations(output_path, headers, str_device_evaluations, file_name):
    """
    Output device evaluations from function evaluate_predictions().

    Parameters
    ----------
    output_path: output file path
    headers: ["device_ip", "port", "my_label", "prediction", "pre_label", "result"]
    str_device_evaluations: list, [{"device_ip": , "port": , "my_label": , "prediction": , "pre_label": , "result": }]
    file_name:

    Returns
    -------
    None
    """
    # Output CSV file name
    csv_file = analysis_file(file_name)
    # Write to CSV
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=headers)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(str_device_evaluations)


def get_device_evaluations(device_evaluations_file):
    """
    Load device evaluations from device_evaluations_file

    Parameters
    ----------
    device_evaluations_file

    Returns
    -------
    device_evaluations: list, ["device_ip", "port", "my_label", "prediction", "pre_label", "result"]
    """
    device_evaluations = list()
    with open(device_evaluations_file, mode="r") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            device_evaluations.append(row)
    return device_evaluations


def load_device_models(model_path, file_name, stsm_type):
    """
    Load device models from device_models csv file

    Parameters
    ----------
    model_path: file path of device_models csv file
    file_name:
    stsm_type: the type of stsm model

    Returns
    -------
    device_models: device models
    """
    if stsm_type != "state":
        raise ValueError(f"Unsupported stsm_type: {stsm_type}. Only 'state' is supported.")
    device_models_file = analysis_file(file_name, create_parent=False)
    with open(device_models_file, mode="r") as file:
        csv_reader = csv.DictReader(file)
        device_models = defaultdict(list)
        for row in csv_reader:
            device_ip = row["device_ip"]
            port = int(row["port"])
            stsms = []
            for item in row.items():
                if item[0] != "device_ip" and item[0] != "port":
                    if item[1] != "":
                        # Convert string to bytes
                        operation = eval(item[0])
                        stsms.append(SemanticTemporalStateModelState.construct_str_stsm_semantic_hashes(operation, item[1]))
            device_models[(device_ip, port)] = SemanticDeviceModel(device_ip, port, stsms)
    return device_models


def predict_file(protocol, stsm_type, model_file_name, region, test_file_suffix, excluded_operations):
    """
    Predict device models from pcap file, for the data source, our global scanning list

    Parameters
    ----------
    protocol: ICS protocol
    stsm_type: the type of the identification system
    model_file_name: the file name of generated device signatures
    region: the origin of the dataset
    test_file_suffix: the suffix of test file name
    excluded_operations: the excluded operations

    Returns
    -------
    None
    """
    require_supported_protocol(protocol)
    if stsm_type != "state":
        raise ValueError(f"Unsupported stsm_type: {stsm_type}. Only 'state' is supported.")
    ip_list_file = protocol_device_info_file(protocol)
    require_existing_file(ip_list_file, f"{protocol} device information CSV")
    test_pcap_file1 = protocol_pcap_file(protocol, region, f"{protocol}_{test_file_suffix}_{region}_filtered")
    require_existing_file(test_pcap_file1, f"{protocol} test pcap file")
    test_all_packets = []
    test_all_packets.extend(get_packets_inlist(test_pcap_file1, ip_list_file))
    test_filtered_packets = filter_retransmission(test_all_packets)
    test_filtered_packets = filter_packets_train(test_filtered_packets, protocol)

    # defense methods
    test_device_packets = None
    if defense_mode == "pad":
        test_defense_packets = defense_padding_packets(test_filtered_packets, protocol)
        test_device_packets = split_packets_by_ip(test_defense_packets, protocol)
    elif defense_mode == "encry":
        test_defense_packets = defense_encryption_packets(test_filtered_packets, protocol)
        test_device_packets = split_packets_by_ip(test_defense_packets, protocol)
    elif defense_mode == "noise":
        test_defense_packets = defense_noise_packets(test_filtered_packets, protocol)
        test_device_packets = split_packets_by_ip(test_defense_packets, protocol)
    elif defense_mode == "remove":
        test_defense_packets = remove_response_packets(test_filtered_packets, protocol)
        test_device_packets = split_packets_by_ip(test_defense_packets, protocol)
    elif defense_mode == "diff":
        test_defense_packets = defense_different_encryption_packets(test_filtered_packets, protocol)
        test_device_packets = split_packets_by_ip(test_defense_packets, protocol)
    else:
        test_device_packets = split_packets_by_ip(test_filtered_packets, protocol)

    print(f"Number of test IPs: {len(test_device_packets.keys())}")
    predict_state(protocol, test_device_packets, stsm_type, model_file_name, test_file_suffix, excluded_operations)


def predict_file_others(protocol, stsm_type, model_file_name, region, test_others_file_suffix, excluded_operations, isHoneypot):
    """
    Predict device models from pcap file, for the data sources, Shodan and honeypots

    Parameters
    ----------
    protocol: ICS protocol
    stsm_type: the type of the identification system
    model_file_name: the file name of generated device signatures
    region: the origin of the dataset
    test_file_suffix: the suffix of test file name
    excluded_operations: the excluded operations
    isHoneypot: whether for honeypot detection

    Returns
    -------
    None
    """
    require_supported_protocol(protocol)
    if stsm_type != "state":
        raise ValueError(f"Unsupported stsm_type: {stsm_type}. Only 'state' is supported.")
    source_name = "honeypot" if isHoneypot else "shodan"
    ip_list_file = source_device_info_file(protocol, source_name)
    require_existing_file(ip_list_file, f"{source_name} {protocol} device information CSV")
    test_pcap_file1 = source_pcap_file(protocol, source_name, test_others_file_suffix)
    require_existing_file(test_pcap_file1, f"{source_name} {protocol} pcap file")
    test_all_packets = []
    test_all_packets.extend(get_packets_inlist(test_pcap_file1, ip_list_file))
    test_filtered_packets = filter_retransmission(test_all_packets)
    test_filtered_packets = filter_packets_train(test_filtered_packets, protocol)
    test_device_packets = split_packets_by_ip(test_filtered_packets, protocol)
    print(f"Number of test IPs: {len(test_device_packets.keys())}")
    if isHoneypot:
        predict_state_honeypot(protocol, test_device_packets, stsm_type, model_file_name, test_others_file_suffix, excluded_operations)
    else :
        predict_state(protocol, test_device_packets, stsm_type, model_file_name, test_others_file_suffix, excluded_operations)


def predict_packets(protocol, test_device_packets, stsm_type, model_file_name, test_file_suffix, excluded_operations):
    if stsm_type != "state":
        raise ValueError(f"Unsupported stsm_type: {stsm_type}. Only 'state' is supported.")
    predict_state(protocol, test_device_packets, stsm_type, model_file_name, test_file_suffix, excluded_operations)


def predict_state(protocol, test_device_packets, stsm_type, model_file_name, test_file_suffix, excluded_operations):
    """
    The identification system which generates one semantic hash for each feature packet in a sequence.
    """
    interval_time = 100  # time threshold for splitting flows of the same 5-tuple [s]
    match_score_threshold = GLOBAL_DM_Score  # match score threshold
    device_models = load_device_models(root_path, f"{protocol}\\{model_file_name}", stsm_type)
    evaluate_device_models(device_models, protocol, model_file_name)
    device_predictions = defaultdict(list)
    mean_signature_match_times = list()
    total_signature_match_times = list()
    for device_ip, d_packets in test_device_packets.items():
        port_packets = split_packets_by_port(d_packets, protocol)
        for port, p_packets in port_packets.items():
            all_flows = create_flows(p_packets, interval_time)
            operation_flows, operations = group_flows_excluded(all_flows, excluded_operations, protocol)
            operation_flow_semantic_packets = extract_flow_ts_packets_semantic_hash(operation_flows, protocol)
            if len(operation_flow_semantic_packets) == 0:  # exclude IPs without meaningful packets
                continue
            model_match_scores = defaultdict()
            time_scores = list()
            semantic_scores = list()
            start_time = time.time()
            for device_model in device_models.values():
                match_score = device_model.device_model_check(operation_flow_semantic_packets, stsm_type)
                if match_score:
                    model_match_scores[(device_model.device_ip, device_model.port)] = match_score
                    time_scores.extend([score[0] for operation, score in match_score.items()])
                    semantic_scores.extend([score[1] for operation, score in match_score.items()])
            end_time = time.time()
            mean_signature_match_times.append((end_time - start_time)/len(device_models.values()))
            total_signature_match_times.append(end_time - start_time)
            time_score_max = max(time_scores)
            time_score_min = min(time_scores)
            semantic_score_max = max(semantic_scores)
            semantic_score_min = min(semantic_scores)
            # semantic_score_max_list.append(max(semantic_scores))
            # time_score_max = 1
            # time_score_min = 0
            # semantic_score_max = max(65, max(semantic_scores))
            # semantic_score_min = 0
            model_match_scores_normalization = defaultdict()
            for ip_port, match_score in model_match_scores.items():
                match_score_normalization = defaultdict()
                for operation, score in match_score.items():
                    time_score_normalization = (score[0] - time_score_min) / (time_score_max - time_score_min) if time_score_max != time_score_min else score[0]
                    # if score[1] >= semantic_score_max:
                    #     semantic_score_normalization = 1
                    # else:
                    #     semantic_score_normalization = (score[1] - semantic_score_min) / (semantic_score_max - semantic_score_min) if semantic_score_max != semantic_score_min else score[1]
                    semantic_score_normalization = (score[1] - semantic_score_min) / (semantic_score_max - semantic_score_min) if semantic_score_max != semantic_score_min else score[1]
                    match_score_normalization[operation] = (time_score_normalization, semantic_score_normalization)
                model_match_scores_normalization[ip_port] = match_score_normalization

            predictions = list()
            for ip_port, match_score_normalization in model_match_scores_normalization.items():
                match_score_normalization_non_zero = defaultdict(int)
                for key, item in match_score_normalization.items():
                    if item[0] != 0 or item[1] != 0:
                        match_score_normalization_non_zero[key] = item
                time_scores_norm = [score[0] for score in match_score_normalization_non_zero.values()]
                time_score_mean = mean(time_scores_norm) if time_scores_norm else 0.0
                semantic_scores_norm = [score[1] for score in match_score_normalization_non_zero.values()]
                semantic_score_mean = mean(semantic_scores_norm) if semantic_scores_norm else 0.0
                match_score_bias = GLOBAL_DM_BIAS
                operation_match_ratio = len(match_score_normalization_non_zero) / max(len(match_score_normalization), len(operations))
                match_score_weight = operation_match_ratio * (1 - match_score_bias) + match_score_bias
                final_match_score = (time_score_mean + semantic_score_mean) / 2.0 * match_score_weight
                # final_match_score = time_score_mean * match_score_weight  # Disable Semantic Match
                if operation_match_ratio >= GLOBAL_OPERATION_MATCH and final_match_score > match_score_threshold:  # exclude small match scores and promote calculation speed
                    predictions.append((ip_port[0], ip_port[1], final_match_score))
            # Sort by match_score
            sorted_predictions = sorted(predictions, key=lambda x: x[2], reverse=True)
            device_predictions[(device_ip, port)] = sorted_predictions
            reset_all_models(device_models)

    print(f"Average signature matching time for one signature: {average(mean_signature_match_times)}")
    print(f"Average signature matching time for all signatures: {average(total_signature_match_times)}")
    """ Output device_predictions """
    str_device_predictions = []
    prediction_headers = ["device_ip", "port", "predictions"]
    for device_ip_port, predictions in device_predictions.items():
        str_predictions = ", ".join([f"({ip}::{port}::{score})" for ip, port, score in predictions])
        str_device_predictions.append({"device_ip": device_ip_port[0], "port": device_ip_port[1],"predictions": str_predictions})
    output_device_predictions(root_path, prediction_headers, str_device_predictions, f"{protocol}\\predictions_{model_file_name}_{test_file_suffix}")


def predict_state_honeypot(protocol, test_device_packets, stsm_type, model_file_name, test_file_suffix, excluded_operations):
    """
    The identification system for honeypots.
    """
    interval_time = 100  # time threshold for splitting flows of the same 5-tuple [s]
    match_score_threshold = GLOBAL_DM_Score  # match score threshold
    device_models = load_device_models(root_path, f"{protocol}\\{model_file_name}", stsm_type)
    evaluate_device_models(device_models, protocol, model_file_name)
    device_predictions = defaultdict(list)
    for device_ip, d_packets in test_device_packets.items():
        port_packets = split_packets_by_port(d_packets, protocol)
        for port, p_packets in port_packets.items():
            all_flows = create_flows(p_packets, interval_time)
            operation_flows, operations = group_flows_excluded(all_flows, excluded_operations, protocol)
            operation_flow_semantic_packets = extract_flow_ts_packets_semantic_hash(operation_flows, protocol)
            if len(operation_flow_semantic_packets) == 0:  # exclude IPs without meaningful packets
                device_predictions[(device_ip, port)] = []
            model_match_scores = defaultdict()
            time_scores = list()
            semantic_scores = list()
            for device_model in device_models.values():
                match_score = device_model.device_model_check(operation_flow_semantic_packets, stsm_type)
                if match_score:
                    model_match_scores[(device_model.device_ip, device_model.port)] = match_score
                    time_scores.extend([score[0] for operation, score in match_score.items()])
                    semantic_scores.extend([score[1] for operation, score in match_score.items()])

            time_score_max = max(time_scores)
            time_score_min = min(time_scores)
            semantic_score_max = max(semantic_scores)
            semantic_score_min = min(semantic_scores)
            # semantic_score_max_list.append(max(semantic_scores))
            # time_score_max = 1
            # time_score_min = 0
            # semantic_score_max = max(65, max(semantic_scores))
            # semantic_score_min = 0
            model_match_scores_normalization = defaultdict()
            for ip_port, match_score in model_match_scores.items():
                match_score_normalization = defaultdict()
                for operation, score in match_score.items():
                    time_score_normalization = (score[0] - time_score_min) / (time_score_max - time_score_min) if time_score_max != time_score_min else score[0]
                    # if score[1] >= semantic_score_max:
                    #     semantic_score_normalization = 1
                    # else:
                    #     semantic_score_normalization = (score[1] - semantic_score_min) / (semantic_score_max - semantic_score_min) if semantic_score_max != semantic_score_min else score[1]
                    semantic_score_normalization = (score[1] - semantic_score_min) / (semantic_score_max - semantic_score_min) if semantic_score_max != semantic_score_min else score[1]
                    match_score_normalization[operation] = (time_score_normalization, semantic_score_normalization)
                model_match_scores_normalization[ip_port] = match_score_normalization

            predictions = list()
            for ip_port, match_score_normalization in model_match_scores_normalization.items():
                match_score_normalization_non_zero = defaultdict(int)
                for key, item in match_score_normalization.items():
                    if item[0] != 0 or item[1] != 0:
                        match_score_normalization_non_zero[key] = item
                time_scores_norm = [score[0] for score in match_score_normalization_non_zero.values()]
                time_score_mean = mean(time_scores_norm) if time_scores_norm else 0.0
                semantic_scores_norm = [score[1] for score in match_score_normalization_non_zero.values()]
                semantic_score_mean = mean(semantic_scores_norm) if semantic_scores_norm else 0.0
                match_score_bias = GLOBAL_DM_BIAS
                operation_match_ratio = len(match_score_normalization_non_zero) / max(len(match_score_normalization), len(operations))
                match_score_weight = operation_match_ratio * (1 - match_score_bias) + match_score_bias
                final_match_score = (time_score_mean + semantic_score_mean) / 2.0 * match_score_weight
                # final_match_score = time_score_mean * match_score_weight
                if operation_match_ratio >= GLOBAL_OPERATION_MATCH and final_match_score > match_score_threshold:  # exclude small match scores and promote calculation speed
                    predictions.append((ip_port[0], ip_port[1], final_match_score))
            # Sort by match_score
            sorted_predictions = sorted(predictions, key=lambda x: x[2], reverse=True)
            device_predictions[(device_ip, port)] = sorted_predictions
            reset_all_models(device_models)

    """ Output device_predictions """
    str_device_predictions = []
    prediction_headers = ["device_ip", "port", "predictions"]
    for device_ip_port, predictions in device_predictions.items():
        str_predictions = ", ".join([f"({ip}::{port}::{score})" for ip, port, score in predictions])
        str_device_predictions.append({"device_ip": device_ip_port[0], "port": device_ip_port[1],"predictions": str_predictions})
    output_device_predictions(root_path, prediction_headers, str_device_predictions, f"{protocol}\\predictions_{model_file_name}_{test_file_suffix}")


def get_final_predictions_max(ip_labels, device_predictions):
    """
    Get the final single prediction of each IP by the maximum probability of each label

    Parameters
    ----------
    ip_labels
    device_predictions

    Returns
    -------
    final_predictions: list
    """
    final_predictions = []
    for device_ip_port, predictions in device_predictions.items():
        device_ip, port = device_ip_port
        label_scores = defaultdict(list)
        if len(predictions) > 0:
            for prediction in predictions:
                predict_ip, predict_port, score = prediction.strip("()").split("::")
                label_scores[ip_labels[predict_ip]].append((predict_ip, predict_port, score))
            # Find the key with the maximum value
            label_max_score = {}
            for label in label_scores.keys():
                # Sort the list in-place by the score (3rd element in the tuple)
                label_scores[label].sort(key=lambda x: x[2], reverse=True)  # Sort descending by score
                label_max_score[label] = label_scores[label][0]
            # Find the label with the highest maximum score
            max_label = max(label_max_score, key=lambda label: label_max_score[label][2])
            final_predictions.append((device_ip, port, ip_labels[device_ip], f"({label_max_score[max_label][0]}::{label_max_score[max_label][1]}::{label_max_score[max_label][2]})",
                                      max_label))
        else:
            final_predictions.append((device_ip, port, ip_labels[device_ip], "", ""))
    return final_predictions


def evaluate(protocol, model_file_name, test_file_suffix):
    """
    Evaluate predictions from device_predictions_file according to ip_label_file
    """
    ip_label_file = None
    if protocol == "modbus":
        ip_label_file = protocol_device_info_file("modbus")
    elif protocol == "s7":
        ip_label_file = protocol_device_info_file("s7")
    elif protocol == "enip":
        ip_label_file = protocol_device_info_file("enip")
    device_predictions_file = analysis_file(f"{protocol}\\predictions_{model_file_name}_{test_file_suffix}", create_parent=False)
    ip_labels = get_ip_labels(ip_label_file)
    device_predictions = get_device_predictions(device_predictions_file)
    final_predictions = get_final_predictions_max(ip_labels, device_predictions)

    # Extract true labels and predicted labels
    true_labels = [label for _, _, label, _, _ in final_predictions]
    predicted_labels = [predict_label for _, _, _, _, predict_label in final_predictions]
    predicted_ips = [(real, predict.strip("()").split("::")[0]) for real, _, _, predict, _ in final_predictions]
    different_pairs = 0
    for pair in predicted_ips:
        if pair[0] != pair[1]:
            different_pairs += 1

    labeled_final_predictions = [pre for pre in final_predictions if pre[4]]
    labeled_true_labels = [label for _, _, label, _, _ in labeled_final_predictions]
    labeled_predicted_labels = [predict_label for _, _, _, _, predict_label in labeled_final_predictions]

    # Calculate accuracy
    all_accuracy = accuracy_score(true_labels, predicted_labels)
    all_f1_score = sklearn.metrics.f1_score(true_labels, predicted_labels, average="weighted")
    labeled_accuracy = accuracy_score(labeled_true_labels, labeled_predicted_labels)
    print(f"all devices: {len(final_predictions)}, all accuracy: {all_accuracy}, all f1_score: {all_f1_score}")
    print(f"labeled devices: {len(labeled_final_predictions)}, labeled accuracy: {labeled_accuracy}")
    print(f"total right devices: {labeled_accuracy * len(labeled_final_predictions)}")
    # print(f"percent of different_pairs: {different_pairs / len(final_predictions)}")
    # print("")

    """ Output device_predictions """
    str_device_evaluations = []
    evaluation_headers = ["device_ip", "port", "my_label", "prediction", "pre_label", "result"]
    for prediction in final_predictions:
        str_device_evaluations.append({"device_ip": prediction[0], "port": prediction[1], "my_label": prediction[2], "prediction": prediction[3], "pre_label": prediction[4], "result": 1 if  prediction[2]== prediction[4] else 0})
    output_device_evaluations(root_path, evaluation_headers, str_device_evaluations, f"{protocol}\\evaluations_{model_file_name}_{test_file_suffix}")
    return all_accuracy, all_f1_score


def get_final_predictions_max_others(ip_labels_train, ip_labels_test, device_predictions):
    """
    Get the final single prediction of each IP by the maximum probability of each label

    Parameters
    ----------
    ip_labels
    device_predictions

    Returns
    -------
    final_predictions: list
    """
    final_predictions = []
    for device_ip_port, predictions in device_predictions.items():
        device_ip, port = device_ip_port
        label_scores = defaultdict(list)
        if len(predictions) > 0:
            for prediction in predictions:
                predict_ip, predict_port, score = prediction.strip("()").split("::")
                label_scores[ip_labels_train[predict_ip]].append((predict_ip, predict_port, score))
            # Find the key with the maximum value
            label_max_score = {}
            for label in label_scores.keys():
                # Sort the list in-place by the score (3rd element in the tuple)
                label_scores[label].sort(key=lambda x: x[2], reverse=True)  # Sort descending by score
                label_max_score[label] = label_scores[label][0]
            # Find the label with the highest maximum score
            max_label = max(label_max_score, key=lambda label: label_max_score[label][2])
            final_predictions.append((device_ip, port, ip_labels_test[device_ip], f"({label_max_score[max_label][0]}::{label_max_score[max_label][1]}::{label_max_score[max_label][2]})",
                                      max_label))
        else:
            final_predictions.append((device_ip, port, ip_labels_test[device_ip], "", "::::::"))
    return final_predictions


def evaluate_others(protocol, model_file_name, test_file_suffix, isHoneypot):
    """
    Evaluate predictions from device_predictions_file according to ip_label_file
    """
    ip_label_train_file = None
    ip_label_test_file = None
    if protocol == "modbus":
        ip_label_train_file = protocol_device_info_file("modbus")
        if isHoneypot:
            ip_label_test_file = source_device_info_file("modbus", "honeypot")
        else:
            ip_label_test_file = source_device_info_file("modbus", "shodan")
    elif protocol == "s7":
        ip_label_train_file = protocol_device_info_file("s7")
        if isHoneypot:
            ip_label_test_file = source_device_info_file("s7", "honeypot")
        else:
            ip_label_test_file = source_device_info_file("s7", "shodan")
    elif protocol == "enip":
        ip_label_train_file = protocol_device_info_file("enip")
        if isHoneypot:
            ip_label_test_file = source_device_info_file("enip", "honeypot")
        else:
            ip_label_test_file = source_device_info_file("enip", "shodan")
    device_predictions_file = analysis_file(f"{protocol}\\predictions_{model_file_name}_{test_file_suffix}", create_parent=False)
    ip_labels_train = get_ip_labels(ip_label_train_file)
    ip_labels_test = get_ip_labels(ip_label_test_file)
    device_predictions = get_device_predictions(device_predictions_file)
    final_predictions = get_final_predictions_max_others(ip_labels_train, ip_labels_test, device_predictions)

    # Extract true labels and predicted labels
    true_labels = [label for _, _, label, _, _ in final_predictions]
    predicted_labels = [predict_label for _, _, _, _, predict_label in final_predictions]
    predicted_ips = [(real, predict.strip("()").split("::")[0]) for real, _, _, predict, _ in final_predictions]
    different_pairs = 0
    for pair in predicted_ips:
        if pair[0] != pair[1]:
            different_pairs += 1

    labeled_final_predictions = [pre for pre in final_predictions if pre[4]]
    labeled_true_labels = [label for _, _, label, _, _ in labeled_final_predictions]
    labeled_predicted_labels = [predict_label for _, _, _, _, predict_label in labeled_final_predictions]

    # Calculate accuracy
    all_accuracy = accuracy_score(true_labels, predicted_labels)
    all_f1_score = sklearn.metrics.f1_score(true_labels, predicted_labels, average="weighted")
    labeled_accuracy = accuracy_score(labeled_true_labels, labeled_predicted_labels)
    print(f"all devices: {len(final_predictions)}, all accuracy: {all_accuracy}, all f1_score: {all_f1_score}")
    print(f"labeled devices: {len(labeled_final_predictions)}, labeled accuracy: {labeled_accuracy}")
    print(f"total right devices: {labeled_accuracy * len(labeled_final_predictions)}")
    # print(f"percent of different_pairs: {different_pairs / len(final_predictions)}")
    # print("")

    """ Output device_predictions """
    str_device_evaluations = []
    evaluation_headers = ["device_ip", "port", "my_label", "prediction", "pre_label", "result"]
    for prediction in final_predictions:
        str_device_evaluations.append({"device_ip": prediction[0], "port": prediction[1], "my_label": prediction[2], "prediction": prediction[3], "pre_label": prediction[4], "result": 1 if  prediction[2]== prediction[4] else 0})
    output_device_evaluations(root_path, evaluation_headers, str_device_evaluations, f"{protocol}\\evaluations_{model_file_name}_{test_file_suffix}")
    return all_accuracy, all_f1_score


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
    print(f"match_score_threshold = {GLOBAL_DM_Score}")
    print(f"operation_match_ratio >= {GLOBAL_OPERATION_MATCH}")
    print(f"packet_match_ratio >= {GLOBAL_PACKET_MATCH}")
    defense_mode = "pad"  # pad, encry, noise, remove, diff
    print(f"defense_mode = {defense_mode}")
    model_file_name = f"device_models_{stsm_type}_semantic_ip({start_file_index}-{start_file_index + file_number -1})_{region}_align_{GLOBAL_TALI}_{defense_mode}"
    print(f"model_file_name = {model_file_name}")

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
    #     b'c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ]# ,
        # b'o\x00\x16\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x06\x00\x01\x02 \x01$\x01',
        # b'd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        # b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00']  # for ENIP
    excluded_operations = []
    accuracy_scores = []
    f1_scores = []

    """ For the data source, our global scanning list """
    for round in range(66, 70):
        test_file_suffix = f"more_round{round}"
        predict_file(protocol, stsm_type, model_file_name, region, test_file_suffix, excluded_operations)
        all_accuracy, all_f1_score = evaluate(protocol, model_file_name, test_file_suffix)
        accuracy_scores.append(all_accuracy)
        f1_scores.append(all_f1_score)
    print(f"Mean Accuracy: {np.mean(accuracy_scores)}, Mean F1-Score: {np.mean(f1_scores)}")

    """ For the data sources, Shodan and honeypots
    isHoneypot = False
    prefix = "shodan"
    if isHoneypot:
        prefix = "honeypot"
    for r in range(0, 1):
        test_others_file_suffix = f"{prefix}_{protocol}_{region}_round{r + 1}"
        predict_file_others(protocol, stsm_type, model_file_name, region, test_others_file_suffix, excluded_operations, isHoneypot)
        all_accuracy, all_f1_score = evaluate_others(protocol, model_file_name, test_others_file_suffix, isHoneypot)
        accuracy_scores.append(all_accuracy)
        f1_scores.append(all_f1_score)
    print(f"Mean Accuracy: {np.mean(accuracy_scores)}, Mean F1-Score: {np.mean(f1_scores)}") """
