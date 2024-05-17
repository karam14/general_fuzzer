import subprocess
import logging

def run_process(executable, input_str):
    try:
        process = subprocess.Popen(
            executable,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        stdout, stderr = process.communicate(input=input_str, timeout=5)
        return stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired:
        logging.error(f"Process timed out for input '{input_str}'")
        return "", "Timeout"
    except subprocess.CalledProcessError as e:
        logging.error(f"CalledProcessError: {e}")
        return "", f"Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected error running process with input '{input_str}': {e}")
        return "", str(e)
