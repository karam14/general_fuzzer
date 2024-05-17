import logging
from fuzzer.fuzz_runner import FuzzRunner
from fuzzer.constants import RESULTS_FILE

def main():
    # Configure the root logger
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    executable = input("Enter the executable and its arguments (e.g., ./app): ").split()
    buffer_size = int(input("Enter the buffer size: "))
    mutation_rate = float(input("Enter the mutation rate (0.0 - 1.0): "))
    num_tests_per_worker = int(input("Enter the number of tests per worker: "))
    
    print("Choose the type of vulnerability to test for:")
    print("1. Automated Fuzzing")
    print("2. Format String")
    vulnerability_choice = int(input("Enter your choice (1-2): "))
    
    vulnerability_map = {
        1: "Auotmated_Fuzzing",
        2: "format_string"
    }
    
    if vulnerability_choice not in vulnerability_map:
        print("Invalid choice")
        return

    vulnerability_type = vulnerability_map[vulnerability_choice]

    fuzz_runner = FuzzRunner(
        executable,
        buffer_size,
        mutation_rate,
        num_tests_per_worker,
        vulnerability_type
    )
    
    logging.info("Starting the fuzzing process.")
    with open(RESULTS_FILE, "w", encoding='utf-8') as file:
        file.write("Fuzzing Results\n" + "="*60 + "\n")

    fuzz_runner.run()
    logging.info("Fuzzing process completed.")

if __name__ == "__main__":
    main()
