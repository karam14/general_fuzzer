import string

class Config:
    RESULTS_FILE = "fuzzing_results.txt"
    MARKER = "<MARKER>"
    ATTACK_KEYWORDS = {
        "Auotmated_Fuzzing": ["not allowed", "forbidden", "error", "denied"],
        "format_string": ["not allowed", "forbidden", "error", "denied"],
    }
    CHAR_SETS = {
        "Auotmated_Fuzzing": string.ascii_letters + string.digits + string.punctuation + string.whitespace,
        "format_string": string.ascii_letters + string.digits + string.punctuation + " %",
    }
