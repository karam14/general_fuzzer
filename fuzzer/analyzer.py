import logging
from collections import defaultdict, Counter
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from fuzzer.input_generator import InputGenerator
from fuzzer.utils import run_process
from fuzzer.validator import Validator

logger = logging.getLogger(__name__)

class AnomalyAnalyzer:
    def __init__(self, anomalies):
        self.anomalies = anomalies
        self.input_lengths = defaultdict(int)
        self.unique_chars = defaultdict(int)
        self.common_patterns = Counter()
        self.character_positions = defaultdict(lambda: defaultdict(int))
        self.max_length = 0

    def analyze(self):
        inputs = []
        for test_input, stdout, stderr in self.anomalies:
            inputs.append(test_input)
            self.input_lengths[len(test_input)] += 1
            for char in set(test_input):
                self.unique_chars[char] += 1
            self.common_patterns[test_input] += 1
            for index, char in enumerate(test_input):
                self.character_positions[index][char] += 1

            # Update max_length to the longest input observed
            self.max_length = max(self.max_length, len(test_input))

        most_common_length = max(self.input_lengths, key=self.input_lengths.get)
        most_common_chars = sorted(self.unique_chars, key=self.unique_chars.get, reverse=True)[:5]
        common_pattern = self.common_patterns.most_common(1)[0][0]
        common_char_positions = {index: max(chars, key=chars.get) for index, chars in self.character_positions.items()}

        # Analyze impact of specific characters in specific positions
        impactful_positions = self.analyze_impactful_positions()

        logger.info(f"Most common input length causing anomalies: {most_common_length}")
        logger.info(f"Most common characters in anomalous inputs: {most_common_chars}")
        logger.info(f"Most common input pattern: {common_pattern}")
        logger.info(f"Most common character positions: {common_char_positions}")
        logger.info(f"Impactful positions: {impactful_positions}")

        return {
            "most_common_length": most_common_length,
            "most_common_chars": most_common_chars,
            "common_pattern": common_pattern,
            "common_char_positions": common_char_positions,
            "impactful_positions": impactful_positions,
            "inputs": inputs  # Adding inputs for further analysis
        }

    def analyze_impactful_positions(self):
        position_impact = {}
        for index in self.character_positions:
            for char in self.character_positions[index]:
                count = self.character_positions[index][char]
                if count > 1:  # Only consider characters that appear more than once
                    position_impact[(index, char)] = count
        
        # Sort by impact (frequency)
        impactful_positions = sorted(position_impact.items(), key=lambda item: item[1], reverse=True)
        return impactful_positions

    def build_feature_matrix(self, inputs):
        feature_matrix = np.zeros((len(inputs), self.max_length))

        for i, input_str in enumerate(inputs):
            for j, char in enumerate(input_str):
                feature_matrix[i, j] = ord(char)  # Use ASCII value of character as feature

        return feature_matrix

    def pad_input(self, input_str):
        # Pad the input string to the max_length with a special padding character (e.g., space)
        return input_str.ljust(self.max_length)

    def further_testing(self, executable, buffer_size, mutation_rate, num_tests, validate_output, initial_output, attack_keywords, marker, analysis_results):
        educated_guesses = []

        inputs = analysis_results["inputs"]
        feature_matrix = self.build_feature_matrix(inputs)
        labels = np.ones(len(inputs))  # All inputs in anomalies are labeled as 1 (anomalous)

        clf = DecisionTreeClassifier()
        clf.fit(feature_matrix, labels)

        impactful_positions = analysis_results["impactful_positions"]

        # Hypothesis testing based on impactful positions
        hypotheses = self.generate_hypotheses(impactful_positions)
        educated_guesses.extend(self.test_hypotheses(hypotheses, executable, validate_output, initial_output, attack_keywords, marker))

        # Random input testing as a control
        for _ in range(num_tests):
            random_input = InputGenerator.generate_random_input("".join(self.unique_chars.keys()), buffer_size)
            padded_input = self.pad_input(random_input)
            input_features = np.array([ord(char) for char in padded_input]).reshape(1, -1)
            prediction = clf.predict(input_features)

            if prediction == 1:
                stdout, stderr = run_process(executable, random_input)
                anomaly_detected = validate_output(initial_output, stdout, stderr, random_input, attack_keywords, marker)
                educated_guesses.append((None, None, random_input, stdout, stderr, anomaly_detected))

        # Further testing for format string vulnerabilities
        format_string_positions = [index for index, char, _, _, _, _ in educated_guesses if char == '%']
        if format_string_positions:
            further_results = self.test_format_specifiers(format_string_positions, executable, validate_output, initial_output, attack_keywords, marker)
            educated_guesses.extend(further_results)

        return educated_guesses

    def generate_hypotheses(self, impactful_positions):
        hypotheses = []
        for (index, char), _ in impactful_positions:
            hypotheses.append((index, char))
        return hypotheses

    def test_hypotheses(self, hypotheses, executable, validate_output, initial_output, attack_keywords, marker):
        results = []
        for index, char in hypotheses:
            # Calculate effective position considering the marker length
            effective_index = (index - len(marker)) if marker else index
            effective_length = self.max_length  # The input length without marker considered
            test_input = ['a'] * effective_length  # Use a default character to fill the buffer
            test_input[effective_index] = char  # Place the character from the hypothesis
            test_input = marker + "".join(test_input) if marker else "".join(test_input)
            stdout, stderr = run_process(executable, test_input)
            anomaly_detected = validate_output(initial_output, stdout, stderr, test_input, attack_keywords, marker)
            results.append((index, char, test_input, stdout, stderr, anomaly_detected))

        return results

    def test_format_specifiers(self, format_string_positions, executable, validate_output, initial_output, attack_keywords, marker):
        results = []
        format_specifiers = ['%s', '%d', '%x', '%f', '%p', '%n']
        
        for index in format_string_positions:
            for specifier in format_specifiers:
                # Calculate effective position considering the marker length
                effective_index = index - len(marker) if marker else index
                effective_length = self.max_length  # The input length without marker considered
                test_input = ['a'] * effective_length
                test_input[effective_index] = specifier
                test_input = marker + "".join(test_input) if marker else "".join(test_input)
                stdout, stderr = run_process(executable, test_input)
                anomaly_detected = validate_output(initial_output, stdout, stderr, test_input, attack_keywords, marker)
                results.append((index, specifier, test_input, stdout, stderr, anomaly_detected))

        return results

    def report_results(self, analysis_results, hypothesis_results):
        report = []
        confirmed_hypotheses = []

        report.append(f"Most common length: {analysis_results['most_common_length']}")
        report.append(f"Most common characters: {analysis_results['most_common_chars']}")
        report.append(f"Common pattern: {analysis_results['common_pattern']}")
        report.append(f"Common character positions: {analysis_results['common_char_positions']}")
        report.append(f"Impactful positions: {analysis_results['impactful_positions']}")
        report.append(f"Inputs: {analysis_results['inputs']}")
        
        report.append("\nExtended Analytics (Further testing results):")
        for i, (index, char, test_input, stdout, stderr, anomaly_detected) in enumerate(hypothesis_results):
            if index is not None and char is not None:
                report.append(f"Hypothesis {i+1}: Character '{char}' at position {index + 1} with test input '{test_input}'")
            else:
                report.append(f"Hypothesis {i+1}: Random input '{test_input}'")
            report.append(f"Testing result: STDOUT: {stdout} STDERR: {stderr}")
            report.append(f"Anomaly Cause Guess: {'Confirmed' if anomaly_detected else 'Not Confirmed'}")
            if anomaly_detected and index is not None and char is not None:
                confirmed_hypotheses.append((index, char, test_input))

        report.append("\nFinal Result with Confirmed Hypotheses:")
        if confirmed_hypotheses:
            for index, char, test_input in confirmed_hypotheses:
                report.append(f"Confirmed Hypothesis: Character '{char}' at position {index + 1} with test input '{test_input}'")
            if any(char in ['%s', '%d', '%x', '%f', '%p', '%n'] for _, char, test_input in confirmed_hypotheses):
                report.append("Format string vulnerability detected")
        else:
            report.append("No confirmed hypotheses")

        report_str = "\n".join(report)
        logger.info(report_str)
        return report_str
