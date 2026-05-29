# Encoding: utf-8
# Version: 1.0.0
from collections import defaultdict


class SemanticDeviceModel:
    def __init__(self, device_ip, port, models):
        self.device_ip = device_ip
        self.port = port
        self.device_model, self.operations = self.extract_model(models)


    def extract_model(self, models):
        """
        Extract pairs of operation and STSM

        Parameters
        ----------
        models: list, STSM list

        Returns
        -------
        device_model: dictionary, {operation: STSM}
        operations: set, operation set
        """
        operations = set()
        device_model = defaultdict()
        for stsm in models:
            operations.add(stsm.operation)
            device_model[stsm.operation] = stsm
        return device_model, operations


    def check_auto(self, operation_flow_semantic_packets):
        """
        Check whether operation_flow_semantic_packets matches with the device model.

        Parameters
        ----------
        operation_flow_semantic_packets: dictionary, {operation: flow_semantic_packets}

        Returns
        -------
        match probability
        """
        my_operations = set(operation_flow_semantic_packets.keys())
        if not my_operations.issubset(self.operations): # if my_operations <= self.operations, continue; otherwise return 0 (absolutely unmatched)
            return 0
        # print(f"device_ip: {self.device_ip}, port: {self.port}")
        match_scores = defaultdict(int)
        for operation, flow_semantic_packets in operation_flow_semantic_packets.items():
            my_flow = next(iter(flow_semantic_packets.items()))  # Get the only key-value pair as a tuple
            my_score = self.device_model[operation].check_auto_semantic(my_flow[1])
            if my_score == 0:  # unmatched operation
                # return 0  # Force all matches
                match_scores[operation] = my_score
            else:
                match_scores[operation] = my_score
        return self.calculate_match_probability(match_scores)


    def check_auto_normalization(self, operation_flow_semantic_packets, stsm_type):
        """
        Check whether operation_flow_semantic_packets matches with the device model.

        Parameters
        ----------
        operation_flow_semantic_packets: dictionary, {operation: flow_semantic_packets}
        stsm_type: the type of stsm to check

        Returns
        -------
        match_scores
        """
        my_operations = set(operation_flow_semantic_packets.keys())
        if not my_operations.issubset(self.operations): # if my_operations <= self.operations, continue; otherwise return 0 (absolutely unmatched)
            return None
        # print(f"device_ip: {self.device_ip}, port: {self.port}")
        match_scores = defaultdict(int)
        for operation, flow_semantic_packets in operation_flow_semantic_packets.items():
            my_flow = next(iter(flow_semantic_packets.items()))  # Get the only key-value pair as a tuple
            if stsm_type == "operation":
                time_similarity_score, semantic_similarity_score = self.device_model[operation].stsm_operation_check(my_flow[1])
                match_scores[operation] = (time_similarity_score, semantic_similarity_score)
            elif stsm_type == "state":
                time_similarity_score, semantic_similarity_score = self.device_model[operation].stsm_state_check(my_flow[1])
                match_scores[operation] = (time_similarity_score, semantic_similarity_score)
            elif stsm_type == "double":
                time_score_uni, semantic_score_uni, semantic_total_score = self.device_model[operation].stsm_double_check(my_flow[1])
                match_scores[operation] = (time_score_uni, semantic_score_uni, semantic_total_score)
        return match_scores


    def check_auto_normalization_by_model(self, operation_flow_semantic_packets, stsm_type):
        """
        Check whether operation_flow_semantic_packets matches with the device model.

        Parameters
        ----------
        operation_flow_semantic_packets: dictionary, {operation: flow_semantic_packets}
        stsm_type: the type of stsm to check

        Returns
        -------
        match_scores
        """
        match_scores = defaultdict(int)
        for operation in self.operations:
            # if operation == b'\x03\x00\x00\x1d\x02\xf0\x802\x07\x00\x008\x00\x00\x08\x00\x04\x00\x01\x12\x04\x11G\x01\x00\n\x00\x00\x00':
            #     print()
            flow_semantic_packets = operation_flow_semantic_packets[operation]
            if flow_semantic_packets is None or len(flow_semantic_packets) == 0:
                if stsm_type == "double":
                    match_scores[operation] = (0, 0, 0)
                else:
                    match_scores[operation] = (0, 0)
                continue
            my_flow = next(iter(flow_semantic_packets.items()))  # Get the only key-value pair as a tuple
            if stsm_type == "operation":
                time_similarity_score, semantic_similarity_score = self.device_model[operation].stsm_operation_check(my_flow[1])
                match_scores[operation] = (time_similarity_score, semantic_similarity_score)
            elif stsm_type == "state":
                time_similarity_score, semantic_similarity_score = self.device_model[operation].stsm_state_check(my_flow[1])
                match_scores[operation] = (time_similarity_score, semantic_similarity_score)
            elif stsm_type == "double":
                time_score_uni, semantic_score_uni, semantic_total_score = self.device_model[operation].stsm_double_check(my_flow[1])
                match_scores[operation] = (time_score_uni, semantic_score_uni, semantic_total_score)
        return match_scores


    def device_model_check(self, operation_flow_semantic_packets, stsm_type):
        """
        The main interface of SemanticDeviceModel for checking input data

        Parameters
        ----------
        operation_flow_semantic_packets
        stsm_type: the type of stsm to check

        Returns
        -------

        """
        return self.check_auto_normalization_by_model(operation_flow_semantic_packets, stsm_type)


    def calculate_match_probability(self, match_scores):
        """
        Calculate the match probability based on the sequence of match scores

        Returns
        -------
        match probability
        """
        n_flows = len(match_scores)
        n_model = len(self.operations)
        n_matched = 0
        sum_score = 0
        for score in match_scores.values():
            if score != 0: n_matched += 1
            sum_score += float(score)
        # return (sum_score / n_flows) * (n_matched / n_model)
        return sum_score / n_model


    def reset(self):
        for stsm in self.device_model.values():
            stsm.reset()


    def to_string(self, stsm_type):
        model_dict = defaultdict()
        model_dict["device_ip"] = self.device_ip
        model_dict["port"] = self.port
        for operation, stsm in self.device_model.items():
            if stsm_type == "operation":
                model_dict[operation] = stsm.to_string_semantic_total_hashes()
            elif stsm_type == "state":
                model_dict[operation] = stsm.to_string_semantic_hashes()
            elif stsm_type == "double":
                model_dict[operation] = stsm.to_string_semantic_double()
        return model_dict


    def to_string_statistical(self):
        model_dict = defaultdict()
        model_dict["device_ip"] = self.device_ip
        model_dict["port"] = self.port
        for operation, stsm in self.device_model.items():
            model_dict[operation] = len(stsm.length_sequence)
        return model_dict