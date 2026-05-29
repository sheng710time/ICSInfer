# Encoding: utf-8
# Version: 1.0.0
import sys
from collections import defaultdict

import numpy as np
from sklearn.cluster import DBSCAN


def my_custom_distance(packet1, packet2):
    """
    Calculate the distance between two directional lengths.

    Parameters
    ----------
    packet1: directional_length 1
    packet2: directional_length 2

    Returns
    -------
    distance: distance between two directional lengths
    """
    # Compare directions; if different, return max float distance
    if packet1[0] != packet2[0]:
        return sys.float_info.max

    # Compute absolute distance based on packet lengths
    distance = abs(int(packet1[2:]) - int(packet2[2:]))
    return distance


def process_flows(flow_ts_packets):
    """
    Convert flow_ts_packets into a list of tuples (flow_key, ts_packet).

    Parameters
    ----------
    flow_ts_packets: flows of ts_packets

    Returns
    -------
    all_ts_packets: list of tuples (flow_key, ts_packet)
    """
    all_ts_packets = []
    for flow_key, ts_packets in flow_ts_packets.items():
        for ts_packet in ts_packets:
            all_ts_packets.append((flow_key, ) + ts_packet)
    return all_ts_packets


def process_ts_packets(ts_packets):
    """
    Convert ts_packets to the numeric format

    Parameters
    ----------
    ts_packets: raw ts_packets

    Returns
    -------
    lengths: list, directional length of each ts_packet
    """
    lengths = []
    for ts_packet in ts_packets:
        lengths.append(ts_packet[3])
    return lengths


def cluster_ts_packets(eps, round_number, flow_ts_packets):
    """
    Cluster ts_packets by DBSCAN with the custom distance function.

    Parameters
    ----------
    eps: DBSCAN parameter
    round_number: the number of rounds
    flow_ts_packets: flows of ts_packets

    Returns
    -------
    clustered_ts_packets: dictionary, {cluster_label: list of ts_packets}
    """
    all_ts_packets = process_flows(flow_ts_packets)
    processed_ts_packets = process_ts_packets(all_ts_packets)

    # Calculate ts_packets distance matrix as the precomputed matrix
    distance_matrix = np.zeros((len(processed_ts_packets), len(processed_ts_packets)))
    for i in range(len(processed_ts_packets)):
        for j in range(len(processed_ts_packets)):
            if i != j:
                distance_matrix[i, j] = my_custom_distance(processed_ts_packets[i], processed_ts_packets[j])

    # Cluster ts_packets by DBSCAN with the precomputed matrix.
    min_samples = 0
    if round_number <= 2:
        min_samples = round_number
    elif 3 <= round_number <= 9:  # allow 1 miss, more robust to network interference
        min_samples = round_number - 1
    else:
        min_samples = int(round_number * 0.9)

    dbscan = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed")
    labels = dbscan.fit_predict(distance_matrix)

    # Group ts_packets by labels
    clustered_ts_packets = defaultdict(list)
    for label, ts_packet in zip(labels, all_ts_packets):
        clustered_ts_packets[label].append(ts_packet)
    if -1 in clustered_ts_packets:  # remove non-clustered items
        del clustered_ts_packets[-1]
    return clustered_ts_packets


def calculate_min_samples(flow_number):
    """
    Calculate the minimum number of samples required for the common pattern.

    Parameters
    ----------
    flow_number

    Returns
    -------
    min_samples:
    """
    min_samples = 0
    if flow_number <= 2:
        min_samples = flow_number
    elif 3 <= flow_number <= 9:  # allow 1 miss, more robust to network interference
        min_samples = flow_number - 1
    else:
        min_samples = int(flow_number * 0.9)
    return min_samples


def cluster_ts_packets_strict(flow_number, flow_ts_packets):
    """
    Cluster ts_packets by directional lengths of packets strictly.

    Parameters
    ----------
    flow_number: number of flows
    flow_ts_packets: all flows of ts_packets of the same operation

    Returns
    -------
    clustered_ts_packets: dictionary, {cluster_label: list of ts_packets}
    """
    all_ts_packets = process_flows(flow_ts_packets)
    directional_lengths = defaultdict(list)
    for ts_packet in all_ts_packets:
        directional_lengths[ts_packet[3]].append(ts_packet)

    min_samples = calculate_min_samples(flow_number)

    keys_to_delete = [dl for dl, ts_packets in directional_lengths.items() if len(ts_packets) < min_samples]  # Disable Cluster Component
    for key in keys_to_delete:
        del directional_lengths[key]

    return directional_lengths


def split_init_clusters(flow_number, round_number, clustered_ts_packets):
    """
    Split clusters by the relative position of each ts_packet.

    Parameters
    ----------
    flow_number: the number of flows that is consistent with the number of operations
    round_number: the number of rounds
    clustered_ts_packets: from function cluster_ts_packets()

    Returns
    -------
    split_clusters: dictionary, split clusters from clustered_ts_packets
    """
    split_clusters = defaultdict(list)
    for label, cluster in clustered_ts_packets.items():
        flows = defaultdict(list)
        max_size = 0
        for ts_packet in cluster:
            flows[ts_packet[0]].append(ts_packet)
        for flow in flows.values():
            flow.sort(key=lambda x: x[2])  # x[2]: the relative position
            max_size = max(max_size, len(flow))

        for i in range(0,max_size):
            new_cluster = []
            for flow in flows.values():
                if len(flow) > i:
                    new_cluster.append(flow[i])
            split_clusters[f"{label}_{i}"] = new_cluster

    # Remove clusters without predefined numbers of members, which can align the lengths of flows of the same operation
    min_samples = 0
    if round_number <= 2:
        min_samples = round_number
    elif 3 <= round_number <= 9:  # allow 1 miss, more robust to network interference
        min_samples = round_number - 1
    else:
        min_samples = int(round_number * 0.9)

    # keys_to_delete = [key for key, cluster in split_clusters.items() if len(cluster) <= flow_number * 1 or len(cluster) >= flow_number * 1]
    keys_to_delete_soft = [key for key, cluster in split_clusters.items() if len(cluster) < min_samples]
    # keys_to_delete_strict = [key for key, cluster in split_clusters.items() if len(cluster) != flow_number]
    # Delete the keys
    for key in keys_to_delete_soft:
        del split_clusters[key]
    return split_clusters


def split_init_clusters_strict(flow_number, clustered_ts_packets):
    """
    Split clusters by the relative position of each ts_packet.

    Parameters
    ----------
    flow_number: the number of flows of the same operation
    clustered_ts_packets: from function cluster_ts_packets()

    Returns
    -------
    split_clusters: dictionary, split clusters from clustered_ts_packets
    """
    split_clusters = defaultdict(list)
    for label, cluster in clustered_ts_packets.items():
        flows = defaultdict(list)
        max_size = 0
        for ts_packet in cluster:
            flows[ts_packet[0]].append(ts_packet)
        for flow in flows.values():
            flow.sort(key=lambda x: x[2])  # x[2]: the relative position
            max_size = max(max_size, len(flow))

        for i in range(0,max_size):
            new_cluster = []
            for flow in flows.values():
                if len(flow) > i:
                    new_cluster.append(flow[i])
            split_clusters[f"{label}_{i}"] = new_cluster

    # Remove clusters without predefined numbers of members, which can align the lengths of flows of the same operation
    min_samples = calculate_min_samples(flow_number)

    keys_to_delete_soft = []
    # keys_to_delete_soft = [key for key, cluster in split_clusters.items() if len(cluster) < min_samples]
    # Delete the keys
    for key in keys_to_delete_soft:
        del split_clusters[key]
    return split_clusters










