import logging


def setup_custom_logger(name):
    format_string = '%(asctime)s - %(levelname)s - %(module)s - %(message)s'
    formatter = logging.Formatter(fmt=format_string)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger


def setup_console_logger(name):
    handler = logging.StreamHandler()

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger
