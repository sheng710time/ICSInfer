# Encoding: utf-8
# Version: 1.0.0
from collections import defaultdict

from numpy import mean


class DeviceModel:
    def __init__(self, device_ip, port, models):
        self.device_ip = device_ip
        self.port = port
        self.device_model, self.operations = self.extract_model(models)


    def extract_model(self, models):
        """
        Extract pairs of operation and TSM

        Parameters
        ----------
        models: list, TSM list

        Returns
        -------
        device_model: dictionary, {operation: TSM}
        operations: set, operation set
        """
        operations = set()
        device_model = defaultdict()
        for tsm in models:
            operations.add(tsm.operation)
            device_model[tsm.operation] = tsm
        return device_model, operations


    def check(self, operation_flow_ts_packets, n_sigma):
        """
        Check whether operation_flow_ts_packets matches with the device model given n_sigma.

        Parameters
        ----------
        operation_flow_ts_packets: dictionary, {operation: flow_ts_packets}

        Returns
        -------
        True: match, False: otherwise
        """
        my_operations = set(operation_flow_ts_packets.keys())
        if not my_operations.issubset(self.operations): # if my_operations <= self.operations, continue; otherwise return 0 (absolutely unmatched)
            return 0


        for operation, flow_ts_packets in operation_flow_ts_packets.items():
            my_flow = next(iter(flow_ts_packets.items()))  # Get the only key-value pair as a tuple
            if self.device_model[operation].check(my_flow[1], n_sigma):
                continue
            else:
                return False
        return True


    def check_auto(self, operation_flow_ts_packets):
        """
        Check whether operation_flow_ts_packets matches with the device model.

        Parameters
        ----------
        operation_flow_ts_packets: dictionary, {operation: flow_ts_packets}

        Returns
        -------
        match probability
        """
        my_operations = set(operation_flow_ts_packets.keys())
        if not my_operations.issubset(self.operations): # if my_operations <= self.operations, continue; otherwise return 0 (absolutely unmatched)
            return 0

        match_scores = defaultdict(int)
        for operation, flow_ts_packets in operation_flow_ts_packets.items():
            my_flow = next(iter(flow_ts_packets.items()))  # Get the only key-value pair as a tuple
            my_score = self.device_model[operation].check_auto(my_flow[1])
            if my_score == 0:  # unmatched operation
                # return 0  # Force all matches
                match_scores[operation] = my_score
            else:
                match_scores[operation] = my_score

        return self.calculate_match_probability(match_scores)


    def check_auto_any(self, operation_flow_ts_packets):
        """
        Check whether operation_flow_ts_packets matches with the device model.

        Parameters
        ----------
        operation_flow_ts_packets: dictionary, {operation: flow_ts_packets}

        Returns
        -------
        match probability
        """
        match_scores = defaultdict(int)
        for operation, tsm in self.device_model.items():
            if operation in operation_flow_ts_packets:
                my_flow = next(iter(operation_flow_ts_packets[operation].items()))
                my_score = self.device_model[operation].check_auto(my_flow[1])
                match_scores[operation] = my_score
        return self.calculate_match_probability(match_scores)


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
        return sum_score / 5
        # return sum_score / n_model


    def reset(self):
        for tsm in self.device_model.values():
            tsm.reset()


    def to_string(self):
        model_dict = defaultdict()
        model_dict["device_ip"] = self.device_ip
        model_dict["port"] = self.port
        for operation, tsm in self.device_model.items():
            model_dict[operation] = tsm.to_string()
        return model_dict
