import logging
import os.path

def initialize_logger(name, output_dir='.'):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    handler = logging.FileHandler(os.path.join(output_dir, "log"),"w")
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)-15s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
