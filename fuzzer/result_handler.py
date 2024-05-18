import os
import logging
from fuzzer.config import Config

class ResultHandler:
    @staticmethod
    def save_results(results, anomalies):
        results_dir = 'results'
        os.makedirs(results_dir, exist_ok=True)

        all_results_file = os.path.join(results_dir, "all_results.txt")
        anomalies_file = os.path.join(results_dir, "anomalies.txt")

        with open(all_results_file, "w", encoding='utf-8') as file:
            file.write("All Results\n" + "="*60 + "\n")
            for test_input, stdout, stderr in results:
                file.write(f"Input: {test_input}\nOutput: {stdout}\nErrors: {stderr}\n{'-'*60}\n")

        with open(anomalies_file, "w", encoding='utf-8') as file:
            file.write("Anomalies\n" + "="*60 + "\n")
            for test_input, stdout, stderr in anomalies:
                file.write(f"Input: {test_input}\nOutput: {stdout}\nErrors: {stderr}\n{'-'*60}\n")

    @staticmethod
    def save_report(report, filename):
        results_dir = 'results'
        os.makedirs(results_dir, exist_ok=True)

        report_file = os.path.join(results_dir, filename)
        with open(report_file, "w", encoding='utf-8') as file:
            file.write(report)

