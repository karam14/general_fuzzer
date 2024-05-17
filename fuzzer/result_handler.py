from collections import defaultdict
import logging
from fuzzer.config import Config

class ResultHandler:
    @staticmethod
    def save_results(results, anomalies):
        with open(Config.RESULTS_FILE, "a", encoding='utf-8') as file:
            file.write("All Results\n" + "="*60 + "\n")
            for test_input, stdout, stderr in results:
                file.write(f"Input: {test_input}\nOutput: {stdout}\nErrors: {stderr}\n{'-'*60}\n")
            file.write("\nAnomalies\n" + "="*60 + "\n")
            for test_input, stdout, stderr in anomalies:
                file.write(f"Input: {test_input}\nOutput: {stdout}\nErrors: {stderr}\n{'-'*60}\n")

    @staticmethod
    def analyze_anomalies(anomalies):
        input_lengths = defaultdict(int)
        unique_chars = defaultdict(int)

        for test_input, stdout, stderr in anomalies:
            input_lengths[len(test_input)] += 1
            for char in set(test_input):
                unique_chars[char] += 1

        most_common_length = max(input_lengths, key=input_lengths.get)
        most_common_chars = sorted(unique_chars, key=unique_chars.get, reverse=True)[:5]

        logging.info(f"Most common input length causing anomalies: {most_common_length}")
        logging.info(f"Most common characters in anomalous inputs: {most_common_chars}")

        return most_common_length, most_common_chars
