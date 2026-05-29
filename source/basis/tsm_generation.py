# Encoding: utf-8
# Version: 1.0.0
import copy
import hashlib
from collections import defaultdict, Counter

from minineedle import smith, core, needle
from minineedle.core import Gap
from numpy import mean
from sympy import sequence
from source.config.config import *


def aggregate_ts_packets(split_clusters):
    """
    Aggregate clustered ts_packets into flows.

    Parameters
    ----------
    split_clusters: from function split_clusters()

    Returns
    -------
    aggregated_ts_packets: dictionary, {flow_key: [ts_packets]}
    """
    aggregated_ts_packets = defaultdict(list)
    for label, cluster in split_clusters.items():
        for item in cluster:
            aggregated_ts_packets[item[0]].append(item[1:])
    # Sort each flow by the relative position in each ts_packet
    for key, flow in aggregated_ts_packets.items():
        aggregated_ts_packets[key] = sorted(flow, key=lambda x: x[1])  # x[1]: the relative position

    return aggregated_ts_packets


def flow_length_hash(ts_packets):
    """
    Create a hash based on ts_packets in a flow.

    Parameters
    ----------
    ts_packets:

    Returns
    -------
    : hash value of ts_packets in a flow
    """
    result_string = ", ".join(ts_packet[2] for ts_packet in ts_packets)
    return hashlib.md5(result_string.encode()).hexdigest()


def flow_sequence_hash(sequence):
    """
    Create a hash based on ts_packets in a flow.

    Parameters
    ----------
    sequence:

    Returns
    -------
    : hash value of ts_packets in a flow
    """
    result_string = ", ".join(sequence)
    return hashlib.md5(result_string.encode()).hexdigest()


def align_flows(common_threshold, flow_ts_packets):
    """
    Align flows by flow lengths and hash values of ts_packets.

    Parameters
    ----------
    flow_number: the number of flows of the same operation
    flow_ts_packets: dictionary, flows of ts_packets

    Returns
    -------
    flow_ts_packets: dictionary, aligned version of flow_ts_packets, whose members may be less than the members of the input flow_ts_packets.
    """
    length_mean = mean([len(ts_packets) for ts_packets in flow_ts_packets.values()])
    flow_ts_packets = align_flow_ts_packets(flow_ts_packets, length_mean)
    if len(flow_ts_packets) < common_threshold:
        print("len(flow_ts_packets) < common_threshold")
        return  []

    """First align by flow lengths
    # Calculate the most common flow length
    length_counts = Counter(len(ts_packets) for ts_packets in flow_ts_packets.values())
    most_common_length = max(length_counts, key=length_counts.get)
    if length_counts[most_common_length] < common_threshold:
        return []
    # Filter the flows by flow lengths
    flow_ts_packets = {key: ts_packets for key, ts_packets in flow_ts_packets.items() if len(ts_packets) == most_common_length} """

    """ Second align by hash values of ts_packets
    hash_counts = Counter(flow_length_hash(ts_packets) for ts_packets in flow_ts_packets.values())
    most_common_hash = max(hash_counts, key=hash_counts.get)
    # if hash_counts[most_common_hash] < common_threshold:
    if hash_counts[most_common_hash] < len(flow_ts_packets)/2:
        return []
    # Filter the flows by hash values of ts_packets
    flow_ts_packets = {key: ts_packets for key, ts_packets in flow_ts_packets.items() if flow_length_hash(ts_packets) == most_common_hash} """

    return flow_ts_packets


def align_flow_ts_packets(flow_ts_packets, length_mean):
    """
    Align ts_packets by the largest common subsequences of flow_ts_packets.
    Parameters
    ----------
    flow_ts_packets
    length_mean

    Returns
    -------
    flow_ts_packets_aligned: aligned flow_ts_packets
    """
    # Convert flow_ts_packets to sequence_list
    sequence_list = []
    for flow_key, ts_packets in flow_ts_packets.items():
        sequence_list.append((flow_key, [ts_packet[2] for ts_packet in ts_packets]))

    aligned_seq_max = None
    sequence_list_copy = copy.deepcopy(sequence_list)
    while True:
        # Determine the maximum length of the lists
        max_length = max(len(seq[1]) for seq in sequence_list_copy)
        sequences_max = [seq[1] for seq in sequence_list_copy if len(seq[1]) == max_length]
        hash_counts = Counter(flow_sequence_hash(seq_max) for seq_max in sequences_max)
        most_common_hash = max(hash_counts, key=hash_counts.get)
        if hash_counts[most_common_hash] < len(sequences_max)/2:
            sequence_list_copy = [seq for seq in sequence_list_copy if len(seq[-1]) < max_length]
            print(f"max_length [{max_length}] is not representative")
            sequences_max_str = "\n".join(["\t".join(map(str, row)) for row in sequences_max])
            print(f"sequences_max: \n{sequences_max_str}")
            # exit()
            if len(sequence_list_copy) == 0:
                return []
            # Filter the flows by hash values of ts_packets
        else:
            # Filter the flows by hash values of ts_packets
            sequences_max_hash = [seq_hash for seq_hash in sequences_max if flow_sequence_hash(seq_hash) == most_common_hash]
            aligned_seq_max = sequences_max_hash[0]
            break

    if len(aligned_seq_max) < length_mean/2:  # Limit the total length of LCS
        return []

    # Align all remaining sequences by aligned_seq_max
    sequence_list_aligned_map = defaultdict(list)
    sequence_list_aligned = []
    align_gap = Gap("-")
    if aligned_seq_max:
        for seq in sequence_list_copy:
            al1, al2, alignment = align_pairwise(aligned_seq_max, seq[1])
            if len(al1) == len(aligned_seq_max):
                gap_number = al2.count(align_gap)
                my_tuple = (seq[0], al2, gap_number)
                sequence_list_aligned_map[gap_number].append(my_tuple)
                sequence_list_aligned.append(my_tuple)

    # Calculate Gap positions, and corresponding sequences
    sequence_list_aligned_gap = defaultdict(list)
    for seq_aligned in sequence_list_aligned:
        positions = sorted([i for i, val in enumerate(seq_aligned[1]) if val == align_gap])
        # Create the key (len(positions), tuple of positions) to make it hashable
        position_key = (len(positions), tuple(positions))  # Convert positions to a tuple
        sequence_list_aligned_gap[position_key].append(seq_aligned)
    sequence_list_aligned_gap_count = defaultdict(int)
    for position_key, seq_aligned_list in sequence_list_aligned_gap.items():
        position_count_key = (position_key[0], len(seq_aligned_list), position_key[1])
        sequence_list_aligned_gap_count[position_count_key] = seq_aligned_list

    # Sort the keys first by position_count_key[0] (ascending), then by position_count_key[1] (descending)
    sorted_keys = sorted(sequence_list_aligned_gap_count.keys(), key=lambda x: (x[0], -x[1]))
    sequence_list_aligned_gap_count_sorted = {key: sequence_list_aligned_gap_count[key] for key in sorted_keys}
    positions_remained = []
    sequence_list_aligned_gap_count_sorted_remained = []
    alignment_threshold = GLOBAL_TALI
    for key, value in sequence_list_aligned_gap_count_sorted.items():
        sequence_list_aligned_gap_count_sorted_remained.extend(value)
        positions_remained.append(key[-1])
        if len(sequence_list_aligned_gap_count_sorted_remained) > len(sequence_list_aligned) * alignment_threshold:
            break

    positions_remained_set = set([item for sublist in positions_remained for item in sublist])
    flow_ts_packets_aligned = {}
    for seq_aligned_remained in sequence_list_aligned_gap_count_sorted_remained:
        flow_key = seq_aligned_remained[0]
        seq_aligned_remained_sequence = seq_aligned_remained[1]
        match_index = 0
        ts_packets_aligned = []
        for i in range(len(seq_aligned_remained_sequence)):
            if seq_aligned_remained_sequence[i] == align_gap:  # Remove gaps
                continue
            elif i in positions_remained_set:  # Remove non-aligned elements that are not shared by other sequences
                match_index += 1
                continue
            else:
                ts_packets_aligned.append(flow_ts_packets[flow_key][match_index])
                match_index += 1
        flow_ts_packets_aligned[flow_key] = ts_packets_aligned
    return flow_ts_packets_aligned


def align_multiple_lists(sequences: list[list]) -> list:
    """
    Align multiple strings using pairwise Smith-Waterman.
    """
    if sequences is None or len(sequences) == 0:
        return None
    elif len(sequences) == 1:
        return sequences[0]

    # Start with the first sequence
    aligned_seq = sequences[0]
    # Iteratively align with the rest of the sequences
    for seq in sequences[1:]:
        aligned_seq = align_pairwise_no_gap(aligned_seq, seq)
        # print(f"aligned seq: {aligned_seq}")
    return aligned_seq


def align_multiple_lists_with_reference(reference, sequences):
    """
    Align multiple strings using pairwise Smith-Waterman.
    """
    if reference is None or len(sequences) == 0:
        return None

    # Start with the first sequence
    aligned_seq = sequences[0]
    # Iteratively align with the rest of the sequences
    for seq in sequences[1:]:
        aligned_seq = align_pairwise_no_gap(aligned_seq, seq)
        # print(f"aligned seq: {aligned_seq}")
    return aligned_seq


def align_pairwise_no_gap(seq1: list, seq2: list) -> list:
    """
    Perform pairwise Smith-Waterman alignment between two sequences.
    """
    # Get the sequences aligned as lists
    al1, al2, alignment = align_pairwise(seq1, seq2)
    lcs = []
    for i in range(len(al1)):
        if al1[i] == al2[i] and al1[i] != alignment.gap_character:
            lcs.append(al1[i])
    return lcs


def align_pairwise(seq1: list, seq2: list) -> list:
    """
    Perform pairwise Smith-Waterman alignment between two sequences.
    """
    # Create the instance
    alignment: needle.NeedlemanWunsch[list] = needle.NeedlemanWunsch(seq1, seq2)
    # Make the alignment
    alignment.align()
    # Get the sequences aligned as lists
    al1, al2 = alignment.get_aligned_sequences(core.AlignmentFormat.list)
    return al1, al2, alignment
