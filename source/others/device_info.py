"""
Encoding: UTF-8
Description:
"""
import csv
import os
from source.basis.dataprocess import *
from source.label_utils import build_device_label
from source.config.config import *


def get_device_information(device_information_file):
    """
    Modify device information file

    Parameters
    ----------
    device_information_file: filepath of device information csv file

    Returns
    -------
    None
    """
    devices = []
    with open(device_information_file, mode="r") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            row["model_name"] = row["product_code"][:10]
            row["product_code"] = row["product_code"][15:]
            devices.append(row)

    # Output CSV file name
    # Write to CSV

    with open(device_information_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=csv_reader.fieldnames)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(devices)


def filter_shodan_ips(right_list_file, modbus_shodan_file, output_file):
    right_ips = set()
    with open(right_list_file, mode="r") as file:
        csv_reader_right = csv.DictReader(file)
        for row in csv_reader_right:
            right_ips.add(row["device_ip"])

    valid_items = []
    valid_ips = set()
    with open(modbus_shodan_file, mode="r") as file:
        csv_reader_shodan = csv.DictReader(file)
        for row in csv_reader_shodan:
            if row["ip"] in right_ips and row["ip"] not in valid_ips:
                valid_ips.add(row["ip"])
                valid_items.append(row)

    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        # Use the first dictionary's keys as the headers
        writer = csv.DictWriter(file, fieldnames=csv_reader_shodan.fieldnames)
        # Write header
        writer.writeheader()
        # Write rows
        writer.writerows(valid_items)
    print("")

def filter_honeypot_ips(protocol):
    ip_label_train_file = None
    ip_label_test_file = None
    if protocol == "modbus":
        ip_label_train_file = source_device_info_file("modbus", "honeypot")
        ip_label_test_file = source_device_info_file("modbus", "honeypot")
    elif protocol == "s7":
        ip_label_train_file = source_device_info_file("s7", "honeypot")
        ip_label_test_file = source_device_info_file("s7", "honeypot")
    ip_labels_train = get_ip_labels(ip_label_train_file)
    ip_labels_test = get_ip_labels(ip_label_test_file)
    for ip in ip_labels_test.keys():
        if ip in ip_labels_train.keys():
            print(ip)
    print()


def find_labels(protocol):
    ip_label_file = None
    if protocol == "modbus":
        ip_label_file = source_device_info_file("modbus", "honeypot")
    elif protocol == "s7":
        ip_label_file = source_device_info_file("s7", "honeypot")
    ip_labels = get_ip_labels(ip_label_file)
    labels = set()
    for ip, label in ip_labels.items():
        labels.add(label)
    print()


def extract_model_labels(ip_label_file):
    label_set = set()
    with open(ip_label_file, mode="r") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            label_set.add(build_device_label(row))
    return label_set


root_path = dataset_path()
if __name__ == '__main__':
    # device_information_file = protocol_device_info_file("s7")
    # get_device_information(device_information_file)

    # right_list_file = results_path("s7_shodan_right.csv")
    # modbus_shodan_file = source_device_info_file("s7", "shodan")
    # output_file = results_path("s7_valid.csv", create_parent=True)
    # filter_shodan_ips(right_list_file, modbus_shodan_file, output_file)

    # filter_honeypot_ips("s7")
    # find_labels("modbus")
    ip_label_file_modbus = protocol_device_info_file("modbus")
    labels_modbus = extract_model_labels(ip_label_file_modbus)
    ips_modbus = set(get_ip_labels(ip_label_file_modbus).keys())

    ip_label_file_s7 = protocol_device_info_file("s7")
    labels_s7 = extract_model_labels(ip_label_file_s7)
    ips_s7 = set(get_ip_labels(ip_label_file_s7).keys())

    ip_label_file_enip = protocol_device_info_file("enip")
    labels_enip = extract_model_labels(ip_label_file_enip)
    ips_enip = set(get_ip_labels(ip_label_file_enip).keys())

    total_labels = labels_modbus.union(labels_s7, labels_enip)
    total_ips = ips_modbus.union(ips_s7, ips_enip)
    print()




