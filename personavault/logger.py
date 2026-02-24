import logging
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "vault.log")

# Ensure logs directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Configure logger
logger = logging.getLogger("personavault")
logger.setLevel(logging.INFO)
logger.handlers = []  # Remove any existing handlers

# Console output
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# File output
file_handler = logging.FileHandler(LOG_FILE, mode="a")
file_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)
