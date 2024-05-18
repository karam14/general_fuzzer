
# Fuzzer for Vulnerability Detection

## Overview

This project is a fuzzer designed to automatically find vulnerabilities in `modern2.exe` and `modern3.exe`. The fuzzer uses various fuzzing techniques to generate inputs, execute the target binaries, and analyze the outputs to identify potential security vulnerabilities. In the future, this fuzzer will also include capabilities to automatically exploit the identified vulnerabilities.

## Features

- **Automated Input Generation**: Generates random and mutated inputs to test the target binaries.
- **Anomalies Detection**: Identifies anomalies that may be a cause for a potential vulnerability such as format string and other anomalies.
- **Advanced Analysis**: Uses machine learning techniques to refine hypotheses and improve the detection of anomalies.
- **Format String Vulnerability Testing**: Specifically tests format string specifiers to detect vulnerabilities.
- **Detailed Reporting**: Provides comprehensive reports on detected vulnerabilities and their characteristics.

## Requirements

- Python 3.6+
- Required Python packages:
  - `tqdm`
  - `numpy`
  - `scikit-learn`

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/karam14/general_fuzzer.git
   cd general_fuzzer
   ```

2. Set up a virtual environment:

   ```sh
   python -m venv venv
   ```

3. Activate the virtual environment:

   - On Windows:

     ```sh
     venv\Scripts\activate
     ```



4. Install the required packages:

   ```sh
   pip install -r requirements.txt 
   ```

## Usage

1. Activate the virtual environment if not already activated:

   - On Windows:

     ```sh
     venv\Scripts\activate
     ```


2. Run the fuzzer:

   ```sh
   python main.py
   ```

3. Follow the on-screen instructions to specify the target executable (`modern2.exe` or `modern3.exe`), buffer size, mutation rate, number of tests per worker, and type of vulnerability to test for.

## Configuration

The fuzzer can be configured by modifying the following parameters in the `main.py` script:

- **Executable**: The path to the target binary (`modern2.exe` or `modern3.exe`).
- **Buffer Size**: The size of the input buffer for the target binary.
- **Mutation Rate**: The rate at which the input is mutated.
- **Number of Tests per Worker**: The number of tests each worker performs.
- **Vulnerability Types**: The type of vulnerability to test for (Buffer Overflow, SQL Injection, Command Injection, Format String).

## Project Structure

### `main.py`

This is the entry point of the fuzzer. It initializes the fuzzing process, handles user inputs for configuration, and coordinates the execution of the fuzzing tasks.

### `fuzzer/`

This directory contains the core components of the fuzzer.

- **`__init__.py`**: Marks the directory as a Python package.
- **`fuzz_runner.py`**: Manages the fuzzing process, including generating inputs, running the target binaries, and collecting results.
- **`analyzer.py`**: Contains the `AnomalyAnalyzer` class, which analyzes the results of the fuzzing to identify patterns and potential vulnerabilities.
- **`input_generator.py`**: Handles the generation and mutation of inputs for the fuzzing process.
- **`utils.py`**: Contains utility functions such as `run_process` for executing the target binaries.
- **`validator.py`**: Provides validation functions to determine if the outputs of the target binaries indicate a vulnerability.

### Example

Here is an example of how to run the fuzzer:

```sh
python main.py
```

Follow the prompts:

- Enter the executable and its arguments (e.g., `./modern3.exe`).
- Enter the buffer size (e.g., `40`).
- Enter the mutation rate (0.0 - 1.0, e.g., `0.1`).
- Enter the number of tests per worker (e.g., `40`). It's worth mentioning that the more tests you run, the more accurate the results will be. Running fewer than 40 tests might not guarantee a finding.
- Choose the type of vulnerability to test for:
  1. Automated random mutation fuzzing
  2. Format String based mutation fuzzing

## Output

The fuzzer generates detailed logs and reports that include:

- Most common length of inputs causing anomalies.
- Most common characters in anomalous inputs.
- Common patterns and character positions.
- Confirmed hypotheses about vulnerabilities.
- Specific format string vulnerabilities if detected.

## Future Plans

- **Automatic Exploitation**: Develop functionality to automatically exploit identified vulnerabilities.
- **Extended Support**: Add support for more types of vulnerabilities and more target binaries.
- **Improved Analysis**: Enhance machine learning models to improve the accuracy and efficiency of vulnerability detection.
- **GUI Interaction**: Implement a GUI for easier configuration and reporting.

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests.
