import logging
import os

def setup_logging():
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    logging.basicConfig(level=logging.DEBUG,
                        format=log_format,
                        handlers=[
                            logging.FileHandler(os.path.join(log_dir, 'debug.log')),
                            logging.FileHandler(os.path.join(log_dir, 'info.log')),
                            logging.FileHandler(os.path.join(log_dir, 'error.log')),
                            logging.StreamHandler()
                        ])

    # Setting up log levels for individual files
    logging.getLogger().handlers[0].setLevel(logging.DEBUG)
    logging.getLogger().handlers[1].setLevel(logging.INFO)
    logging.getLogger().handlers[2].setLevel(logging.ERROR)
    logging.getLogger().handlers[3].setLevel(logging.WARNING)

    # Reduce the verbosity of console output
    console_handler = logging.getLogger().handlers[3]
    console_handler.setLevel(logging.WARNING)

    # Custom format for the console
    console_format = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_format)
