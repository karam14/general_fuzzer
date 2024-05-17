import difflib
import logging

logger = logging.getLogger(__name__)

class Validator:
    @staticmethod
    def validate_output_with_variation(initial_output, stdout, stderr, test_input, attack_keywords, marker):
        # Check if the exact marker and payload appear in the output
        output_substr = ""
        if marker in stdout:
            index = stdout.find(marker)
            # logger.info(f"Marker found at index {index}")
            # logger.info(f"Test input: {test_input}")
            # logger.info(f"Output: {stdout}")

            end_index = index + len(test_input)
            output_substr = stdout[index:end_index]
            # logger.info(f"Extracted output substring: {output_substr}")

            if output_substr != test_input:
                return True
            else:
                return False
        #Check for attack feasibility keywords in the output
        if any(keyword in stdout.lower() or keyword in stderr.lower() for keyword in attack_keywords):
            return False

        # Check for significant deviations in the output
        if difflib.SequenceMatcher(None, initial_output, stdout).ratio() < 0.9:
            return True

        # # Check if the output length is different from the initial output
        if len(stdout) != len(initial_output):
            return True


        return False
