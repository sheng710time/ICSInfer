# Encoding: utf-8
# Version: 1.0.0
import os

from sklearn.metrics import accuracy_score

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


def output_device_predictions(output_path, headers, str_device_predictions):
    """
    Output device predictions from function predict().

    Parameters
    ----------
    output_path: output file path
    headers: ["device_ip", "port", "predictions"]
    str_device_predictions: list, [{"device_ip": , "port": , "predictions": }]

    Returns
    -------
    None
    """
    # Output CSV file name
    csv_file = analysis_file("device_predictions")
    # Write to CSV
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=headers)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(str_device_predictions)


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


def output_device_evaluations(output_path, headers, str_device_evaluations):
    """
    Output device evaluations from function evaluate().

    Parameters
    ----------
    output_path: output file path
    headers: ["device_ip", "port", "my_label", "prediction", "pre_label", "result"]
    str_device_evaluations: list, [{"device_ip": , "port": , "my_label": , "prediction": , "pre_label": , "result": }]

    Returns
    -------
    None
    """
    # Output CSV file name
    csv_file = analysis_file("device_evaluations")
    # Write to CSV
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=headers)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(str_device_evaluations)


def output_device_multi_evaluations(output_path, headers, str_device_evaluations):
    """
    Output device evaluations from function multi_evaluate_probability().

    Parameters
    ----------
    output_path: output file path
    headers: ["device_ip", "port", "my_label", "pre_label", "probability", "result"]
    str_device_evaluations: list, [{"device_ip": , "port": , "my_label": , "pre_label": , "probability": , "result": }]

    Returns
    -------
    None
    """
    # Output CSV file name
    csv_file = analysis_file("device_multi_evaluations")
    # Write to CSV
    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=headers)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(str_device_evaluations)


def train():
    round_number = 3
    common_threshold = round_number * 1/3
    interval_time = 100  # time threshold for splitting flows of the same 5-tuple [s]
    ip_list_file = protocol_device_info_file("modbus")
    train_pcap_files = [
        protocol_pcap_file("modbus", "au", f"modbus_more_round{round_id}_au")
        for round_id in range(18, 21)
    ]
    train_all_packets = []
    for train_pcap_file in train_pcap_files:
        train_all_packets.extend(get_packets_inlist(train_pcap_file, ip_list_file))
    train_filtered_packets = filter_retransmission(train_all_packets)  # Call filter_retransmission() before filter_packets_train(), because filter_retransmission() is unrelated to other factors, but filter_packets_train() can be impacted by retransmission packets
    train_filtered_packets = filter_packets_train(train_filtered_packets)
    train_device_packets = split_packets_by_ip(train_filtered_packets)
    device_models = defaultdict(list)
    for device_ip, d_packets in train_device_packets.items():
        port_packets = split_packets_by_port(d_packets)
        for port, p_packets in port_packets.items():
            all_flows = create_flows(p_packets, interval_time)
            operation_flows, operations = group_flows(all_flows)
            operation_flow_ts_packets = extract_flow_ts_packets(operation_flows)
            device_tsms = []
            for operation, flow_ts_packets in operation_flow_ts_packets.items():
                init_clusters = cluster_ts_packets(5, round_number, flow_ts_packets)
                if len(init_clusters) == 0:
                    # print(f"init_clusters: {device_ip}, {port}, {operation}")
                    continue
                split_clusters = split_init_clusters(len(flow_ts_packets), round_number, init_clusters)
                if len(split_clusters) == 0:
                    # print(f"split_clusters: {device_ip}, {port}, {operation}")
                    continue
                flow_ts_packets = aggregate_ts_packets(split_clusters)
                flow_ts_packets = align_flows(common_threshold, flow_ts_packets)
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
    output_device_models(root_path, model_headers, str_device_models)


def predict(file_name):
    ip_list_file = protocol_device_info_file("modbus")
    file_stem = os.path.splitext(os.path.basename(file_name))[0]
    test_pcap_file = protocol_pcap_file("modbus", "au", file_stem)
    interval_time = 100  # time threshold for splitting flows of the same 5-tuple [s]
    match_score_threshold = 0.5  # match score threshold
    test_all_packets = []
    test_all_packets.extend(get_packets_inlist(test_pcap_file, ip_list_file))
    test_filtered_packets = filter_retransmission(test_all_packets)
    test_filtered_packets = filter_packets_train(test_filtered_packets)
    test_device_packets = split_packets_by_ip(test_filtered_packets)
    device_predictions = defaultdict(list)
    device_models = load_device_models(root_path)
    # evaluate_device_models(device_models)
    for device_ip, d_packets in test_device_packets.items():
        port_packets = split_packets_by_port(d_packets)
        for port, p_packets in port_packets.items():
            predictions = []
            all_flows = create_flows(p_packets, interval_time)
            operation_flows, operations = group_flows(all_flows)
            operation_flow_ts_packets = extract_flow_ts_packets(operation_flows)
            if len(operation_flow_ts_packets) == 0:  # exclude IPs without meaningful packets
                continue
            for device_model in device_models.values():
                match_score = device_model.check_auto(operation_flow_ts_packets)
                if match_score > match_score_threshold:
                    predictions.append((device_model.device_ip, device_model.port, match_score))
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
    output_device_predictions(root_path, prediction_headers, str_device_predictions)

    print()


def evaluate():
    """
    Evaluate predictions from function predict()
    """
    ip_label_file = protocol_device_info_file("modbus")
    device_predictions_file = analysis_file("device_predictions", create_parent=False)
    ip_labels = get_ip_labels(ip_label_file)
    device_predictions = get_device_predictions(device_predictions_file)
    final_predictions = []
    final_predictions_all_labels = {}
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
            final_predictions.append((device_ip, port, ip_labels[device_ip], f"({label_max_score[max_label][0]}::{label_max_score[max_label][1]}::{label_max_score[max_label][2]})", max_label))
            final_predictions_all_labels[device_ip_port] = label_max_score
        else:
            final_predictions.append((device_ip, port, ip_labels[device_ip], "", ""))
            final_predictions_all_labels[device_ip_port] = None

    # Extract true labels and predicted labels
    true_labels = [label for _, _, label, _, _ in final_predictions]
    predicted_labels = [predict_label for _, _, _, _, predict_label in final_predictions]

    # Filter predictions of which predicted labels are not NULL
    labeled_final_predictions = [pre for pre in final_predictions if pre[4]]
    labeled_true_labels = [label for _, _, label, _, _ in labeled_final_predictions]
    labeled_predicted_labels = [predict_label for _, _, _, _, predict_label in labeled_final_predictions]

    # Calculate accuracy
    accuracy = accuracy_score(true_labels, predicted_labels)
    labeled_accuracy = accuracy_score(labeled_true_labels, labeled_predicted_labels)
    print(f"all devices: {len(final_predictions)}, all accuracy: {accuracy}")
    print(f"labeled devices: {len(labeled_final_predictions)}, labeled accuracy: {labeled_accuracy}")
    print(f"total right devices: {labeled_accuracy * len(labeled_final_predictions)}")
    print()

    """ Output device_predictions """
    str_device_evaluations = []
    evaluation_headers = ["device_ip", "port", "my_label", "prediction", "pre_label", "result"]
    for prediction in final_predictions:
        str_device_evaluations.append({"device_ip": prediction[0], "port": prediction[1], "my_label": prediction[2], "prediction": prediction[3], "pre_label": prediction[4], "result": 1 if  prediction[2]== prediction[4] else 0})
    output_device_evaluations(root_path, evaluation_headers, str_device_evaluations)
    return final_predictions, final_predictions_all_labels


def multi_evaluate_vote():
    """
    Combine evaluation results from multiple rounds by the majority vote

    Returns
    -------
    None
    """
    final_predictions_all = list()
    pre_file_name1 = "modbus_more_round27_au"
    predict(pre_file_name1)
    final_predictions, _ = evaluate()
    final_predictions_all.extend(final_predictions)
    pre_file_name2 = "modbus_more_round28_au"
    predict(pre_file_name2)
    final_predictions, _ = evaluate()
    final_predictions_all.extend(final_predictions)
    pre_file_name3 = "modbus_more_round29_au"
    predict(pre_file_name3)
    final_predictions, _ = evaluate()
    final_predictions_all.extend(final_predictions)
    # pre_file_name4 = "modbus_more_round30_au"
    # predict(pre_file_name4)
    # final_predictions, _ = evaluate()
    # final_predictions_all.extend(final_predictions)
    # pre_file_name5 = "modbus_more_round31_au"
    # predict(pre_file_name5)
    # final_predictions, _ = evaluate()
    # final_predictions_all.extend(final_predictions)
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
    accuracy = accuracy_score(true_labels, predicted_labels)
    print("multi evaluation results:")
    print(f"all devices: {len(ip_true_labels.keys())}, all accuracy: {accuracy}")
    print(f"ip_count_statistics: {ip_count_statistics}")
    print(f"ip_different_statistics: {ip_different_statistics}")
    print()


def multi_evaluate_probability():
    """
    Combine evaluation results from multiple rounds by the maximum probability

    Returns
    -------
    None
    """
    final_predictions_all = list()
    pre_file_name1 = "modbus_more_round27_au"
    predict(pre_file_name1)
    final_predictions, _ = evaluate()
    final_predictions_all.extend(final_predictions)
    pre_file_name2 = "modbus_more_round28_au"
    predict(pre_file_name2)
    final_predictions, _ = evaluate()
    final_predictions_all.extend(final_predictions)
    pre_file_name3 = "modbus_more_round29_au"
    predict(pre_file_name3)
    final_predictions, _ = evaluate()
    final_predictions_all.extend(final_predictions)
    # pre_file_name4 = "modbus_more_round30_au"
    # predict(pre_file_name4)
    # final_predictions, _ = evaluate()
    # final_predictions_all.extend(final_predictions)
    # pre_file_name5 = "modbus_more_round31_au"
    # predict(pre_file_name5)
    # final_predictions, _ = evaluate()
    # final_predictions_all.extend(final_predictions)
    ip_predictions = defaultdict(list)
    ip_true_labels = {}
    for item in final_predictions_all:
        pro = None
        if item[3]:
            pro = float(item[3].strip("()").split("::")[2])
        ip_predictions[(item[0], item[1])].append((item[4], pro))
        ip_true_labels[(item[0], item[1])] = item[2]

    multi_predictions = {}
    ip_count_statistics = defaultdict(int)
    ip_different_statistics = defaultdict(int)
    for ip_port, predictions in ip_predictions.items():
        pre_probability = defaultdict(float)
        for prediction in predictions:
            pre_probability[prediction[0]] += prediction[1] if prediction[1] else 0
        ip_count_statistics[len(predictions)] += 1
        ip_different_statistics[len(pre_probability.keys())] += 1
        max_label = max(pre_probability, key=lambda label: pre_probability[label])
        multi_predictions[ip_port] = (max_label, pre_probability[max_label])
    true_labels = list()
    predicted_labels = list()
    multi_evaluations = []
    for ip_port in ip_true_labels.keys():
        true_labels.append(ip_true_labels[ip_port])
        predicted_labels.append(multi_predictions[ip_port][0])
        multi_evaluations.append((ip_port[0], ip_port[1], ip_true_labels[ip_port], multi_predictions[ip_port][0], multi_predictions[ip_port][1]))
    # Calculate accuracy
    accuracy = accuracy_score(true_labels, predicted_labels)
    print("multi evaluation results:")
    print(f"all devices: {len(ip_true_labels.keys())}, all accuracy: {accuracy}")
    print(f"ip_count_statistics: {ip_count_statistics}")
    print(f"ip_different_statistics: {ip_different_statistics}")

    """ Output device_predictions """
    str_device_evaluations = []
    evaluation_headers = ["device_ip", "port", "my_label", "pre_label", "probability", "result"]
    for prediction in multi_evaluations:
        str_device_evaluations.append(
            {"device_ip": prediction[0], "port": prediction[1], "my_label": prediction[2], "pre_label": prediction[3],
             "probability": prediction[4], "result": 1 if prediction[2] == prediction[3] else 0})
    output_device_multi_evaluations(root_path, evaluation_headers, str_device_evaluations)
    print()


def multi_evaluate_all_label():
    """
    Combine evaluation results from multiple rounds by the maximum probability of all labels

    Returns
    -------
    None
    """
    # Define a nested defaultdict
    final_predictions_all = defaultdict(lambda: defaultdict(float))
    pre_file_name1 = "modbus_more_round27_au"
    predict(pre_file_name1)
    _, final_predictions_all_labels = evaluate()
    for ip_port, label_max_score in final_predictions_all_labels.items():
        if label_max_score is None:
            if ip_port not in final_predictions_all:
                final_predictions_all[ip_port] = defaultdict(float)
        else:
            for label, score in label_max_score.items():
                final_predictions_all[ip_port][label] += float(score[2])
    pre_file_name2 = "modbus_more_round28_au"
    predict(pre_file_name2)
    _, final_predictions_all_labels = evaluate()
    for ip_port, label_max_score in final_predictions_all_labels.items():
        if label_max_score is None:
            if ip_port not in final_predictions_all:
                final_predictions_all[ip_port] = defaultdict(float)
        else:
            for label, score in label_max_score.items():
                final_predictions_all[ip_port][label] += float(score[2])
    pre_file_name3 = "modbus_more_round29_au"
    predict(pre_file_name3)
    _, final_predictions_all_labels = evaluate()
    for ip_port, label_max_score in final_predictions_all_labels.items():
        if label_max_score is None:
            if ip_port not in final_predictions_all:
                final_predictions_all[ip_port] = defaultdict(float)
        else:
            for label, score in label_max_score.items():
                final_predictions_all[ip_port][label] += float(score[2])
    pre_file_name4 = "modbus_more_round30_au"
    predict(pre_file_name4)
    _, final_predictions_all_labels = evaluate()
    for ip_port, label_max_score in final_predictions_all_labels.items():
        if label_max_score is None:
            if ip_port not in final_predictions_all:
                final_predictions_all[ip_port] = defaultdict(float)
        else:
            for label, score in label_max_score.items():
                final_predictions_all[ip_port][label] += float(score[2])
    pre_file_name5 = "modbus_more_round31_au"
    predict(pre_file_name5)
    _, final_predictions_all_labels = evaluate()
    for ip_port, label_max_score in final_predictions_all_labels.items():
        if label_max_score is None:
            if ip_port not in final_predictions_all:
                final_predictions_all[ip_port] = defaultdict(float)
        else:
            for label, score in label_max_score.items():
                final_predictions_all[ip_port][label] += float(score[2])

    ip_predicted_labels = {}
    ip_true_labels = {}
    ip_label_file = protocol_device_info_file("modbus")
    ip_labels = get_ip_labels(ip_label_file)
    for ip_port, label_max_score in final_predictions_all.items():
        if len(label_max_score) == 0:
            ip_predicted_labels[ip_port] = ""
        else:
            max_label = max(label_max_score, key=lambda label: label_max_score[label])
            ip_predicted_labels[ip_port] = max_label
        ip_true_labels[ip_port] = ip_labels[ip_port[0]]

    true_labels = list()
    predicted_labels = list()
    for ip_port in ip_true_labels.keys():
        true_labels.append(ip_true_labels[ip_port])
        predicted_labels.append(ip_predicted_labels[ip_port])
    # Calculate accuracy
    accuracy = accuracy_score(true_labels, predicted_labels)
    print("multi evaluation results:")
    print(f"all devices: {len(ip_true_labels.keys())}, all accuracy: {accuracy}")
    print()


root_path = dataset_path()
if __name__ == '__main__':
    # train()
    # pre_file_name1 = "modbus_more_round29_au"
    # predict(pre_file_name1)
    # evaluate()
    # device_models = load_device_models(root_path)
    # evaluate_device_models(device_models)
    # multi_evaluate_vote()
    multi_evaluate_probability()
    # multi_evaluate_all_label()
