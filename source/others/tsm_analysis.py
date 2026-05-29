# Encoding: utf-8
# Version: 1.0.0
import os

from source.basis.dataprocess import *
from source.identification.device_model import DeviceModel
from source.basis.feature_packet_extraction import *
from source.basis.tsm_generation import *
from source.config.config import *


def generate_tsm():
    # root_path = dataset_path()
    root_path = results_path(ANALYSIS_DIR_NAME)
    train_pcap_file1 = os.path.join(root_path, "193.192.222.50.pcap")
    # train_pcap_file2 = os.path.join(root_path, "193.192.222.50.pcap")
    # train_pcap_file3 = os.path.join(root_path, "193.192.222.50.pcap")
    train_all_packets = []
    train_all_packets.extend(get_packets(train_pcap_file1))
    # train_all_packets.extend(get_packets(train_pcap_file2))
    # train_all_packets.extend(get_packets(train_pcap_file3))
    train_filtered_packets = filter_retransmission(train_all_packets)  # Call filter_retransmission() before filter_packets_train(), because filter_retransmission() is unrelated to other factors, but filter_packets_train() can be impacted by retransmission packets
    train_filtered_packets = filter_packets_train(train_filtered_packets)
    train_device_packets = split_packets_by_ip(train_filtered_packets)
    device_models = defaultdict(list)
    for device_ip, d_packets in train_device_packets.items():
        port_packets = split_packets_by_port(d_packets)
        for port, p_packets in port_packets.items():
            all_flows = create_flows(p_packets)
            operation_flows, operations = group_flows(all_flows)
            operation_flow_ts_packets = extract_flow_ts_packets(operation_flows)
            device_tsms = []
            for operation, flow_ts_packets in operation_flow_ts_packets.items():
                init_clusters = cluster_ts_packets(10, flow_ts_packets)
                split_clusters = split_init_clusters(len(flow_ts_packets), init_clusters)
                flow_ts_packets = aggregate_ts_packets(split_clusters)
                flow_ts_packets = align_flows(flow_ts_packets)
                device_tsms.append(TemporalStateModel.construct_flows(operation, flow_ts_packets))
            if len(device_tsms) > 0:  # filter out empty list
                device_models[(device_ip, port)] = DeviceModel(device_ip, device_tsms)

        print()


def main():
    generate_tsm()

    print()


if __name__ == '__main__':
    main()
