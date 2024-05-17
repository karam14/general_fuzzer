import logging
from multiprocessing import Pool, Manager, cpu_count
from tqdm import tqdm
from queue import Empty
from fuzzer.input_generator import InputGenerator
from fuzzer.validator import Validator
from fuzzer.result_handler import ResultHandler
from fuzzer.analyzer import AnomalyAnalyzer
from fuzzer.config import Config
from fuzzer.utils import run_process
from fuzzer.exploiter import Exploiter

logger = logging.getLogger(__name__)

class FuzzRunner:
    def __init__(self, executable, buffer_size, mutation_rate, num_tests_per_worker, vulnerability_type):
        self.executable = executable
        self.buffer_size = buffer_size
        self.mutation_rate = mutation_rate
        self.num_tests_per_worker = num_tests_per_worker
        self.vulnerability_type = vulnerability_type
        self.num_workers = cpu_count()
        self.characters = Config.CHAR_SETS[vulnerability_type]
        self.attack_keywords = Config.ATTACK_KEYWORDS[vulnerability_type]
        self.marker = Config.MARKER if vulnerability_type == "format_string" else "<m>"
        self.initial_output = self.get_initial_output()

    def get_initial_output(self):
        initial_output, _ = run_process(self.executable, InputGenerator.generate_random_input(self.characters, self.buffer_size))
        logger.info(f"Initial output: {initial_output}")
        return initial_output

    def test_combinations(self, args):
        results = []
        anomalies = []
        for _ in range(self.num_tests_per_worker):
            base_input = InputGenerator.generate_random_input(self.characters, self.buffer_size)
            test_input = self.marker + InputGenerator.mutate_input(base_input, self.characters, self.mutation_rate)
            stdout, stderr = run_process(self.executable, test_input)
            args['queue'].put(1)  # Update progress
            results.append((test_input, stdout, stderr))
            if Validator.validate_output_with_variation(self.initial_output, stdout, stderr, test_input, self.attack_keywords, self.marker):
                logger.info(f"Potential vulnerability detected for input '{test_input}':\nSTDOUT: {stdout}\nSTDERR: {stderr}")
                anomalies.append((test_input, stdout, stderr))
        return results, anomalies

    def run(self):
        manager = Manager()
        queue = manager.Queue(maxsize=self.num_tests_per_worker * self.num_workers)

        with Pool(self.num_workers) as pool:
            args = [
                {
                    'executable': self.executable,
                    'initial_output': self.initial_output,
                    'queue': queue,
                    'characters': self.characters,
                    'mutation_rate': self.mutation_rate,
                    'num_tests': self.num_tests_per_worker,
                    'buffer_size': self.buffer_size,
                    'validate_output': Validator.validate_output_with_variation,
                    'attack_keywords': self.attack_keywords,
                    'marker': self.marker,
                } for _ in range(self.num_workers)
            ]

            with tqdm(total=self.num_tests_per_worker * self.num_workers, desc="Testing combinations") as pbar:
                results = pool.map_async(self.test_combinations, args)

                processed = 0
                while not results.ready():
                    try:
                        while True:
                            queue.get_nowait()
                            processed += 1
                            pbar.update(1)
                    except Empty:
                        pass

                while not queue.empty():
                    queue.get()
                    processed += 1
                    pbar.update(1)

                pbar.n = processed
                pbar.refresh()
                pbar.close()

            all_results = []
            all_anomalies = []
            for partial_results, partial_anomalies in results.get():
                all_results.extend(partial_results)
                all_anomalies.extend(partial_anomalies)

            ResultHandler.save_results(all_results, all_anomalies)

            if all_anomalies:
                analyzer = AnomalyAnalyzer(all_anomalies)
                analysis_results = analyzer.analyze()
                hypothesis_results = analyzer.further_testing(
                    self.executable, self.buffer_size, self.mutation_rate,
                    self.num_tests_per_worker, Validator.validate_output_with_variation,
                    self.initial_output, self.attack_keywords, self.marker,
                    analysis_results
                )
                report = analyzer.report_results(analysis_results, hypothesis_results)

                # Save the final report
                with open(Config.RESULTS_FILE, "a", encoding='utf-8') as file:
                    file.write("\n" + "="*60 + "\n")
                    file.write(report)

                # Exploit confirmed hypotheses
                exploiter = Exploiter(self.executable, Validator.validate_output_with_variation, self.initial_output, self.attack_keywords, self.marker)

                # Check for format string vulnerabilities and exploit if found
                if "Format string vulnerability detected" in report:
                    format_string_positions = [index for index, char, _, _, _, _ in hypothesis_results if char == '%']
                    if format_string_positions:
                        flag = exploiter.exploit_format_string(format_string_positions)
                        if flag:
                            logger.info(f"Flag found during format string exploitation: {flag}")
                        else:
                            logger.info("No flag found during format string exploitation.")

                # Check for flags in other vulnerabilities
                flag = exploiter.check_for_flag(hypothesis_results)
                if flag:
                    logger.info(f"Flag found in hypothesis results: {flag}")
                else:
                    logger.info("No flag found in hypothesis results.")
