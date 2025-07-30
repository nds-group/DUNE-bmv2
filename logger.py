import logging
import os
import threading
import traceback

# === CONFIGURATION ===
LOG_DIR = "logs"
GLOBAL_LOG_NAME = "p4runtime_client"
GLOBAL_LOG_PATH = os.path.join(LOG_DIR, f"{GLOBAL_LOG_NAME}.log")

# === INIT ===
os.makedirs(LOG_DIR, exist_ok=True)

# Global logger
global_logger = logging.getLogger(GLOBAL_LOG_NAME)
global_logger.setLevel(logging.DEBUG)

# Formatter
formatter = logging.Formatter(
    "%(asctime)s [%(threadName)s] [%(levelname)s] %(message)s"
)

# File handler
file_handler = logging.FileHandler(GLOBAL_LOG_PATH, mode='w')
file_handler.setFormatter(formatter)
global_logger.addHandler(file_handler)

# Console handler (optional)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
global_logger.addHandler(console_handler)

def get_global_logger():
    return global_logger

def setup_thread_logger(thread_name):
    """
    Returns a logger for the given thread that logs to both:
    - logs/<thread_name>.log
    - logs/p4runtime_client.log (global)
    """
    logger = logging.getLogger(thread_name)
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        # File-only handler for thread-specific log
        thread_log_path = os.path.join(LOG_DIR, f"{thread_name}.log")
        fh = logging.FileHandler(thread_log_path, mode='w')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        # Reuse global handlers (e.g., to also log to global file/console)
        for h in global_logger.handlers:
            logger.addHandler(h)

    return logger

def thread_entry(target, thread_name, *args, **kwargs):
    """
    Wraps a thread's target function:
    - Assigns thread name
    - Attaches logger
    - Catches unhandled exceptions and logs them
    """
    logger = setup_thread_logger(thread_name)
    threading.current_thread().name = thread_name
    try:
        target(*args, logger=logger, **kwargs)
    except Exception:
        logger.error("Unhandled exception in thread %s:\n%s",
                     thread_name, traceback.format_exc())

