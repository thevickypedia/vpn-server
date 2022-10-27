import importlib
import logging
import os
from datetime import datetime
from typing import Optional, Tuple

DATETIME_FORMAT = '%b-%d-%Y %I:%M:%S %p'


def time_converter(seconds: float) -> str:
    """Modifies seconds to appropriate days/hours/minutes/seconds.

    Args:
        seconds: Takes number of seconds as argument.

    Returns:
        str:
        Seconds converted to days or hours or minutes or seconds.
    """
    days = round(seconds // 86400)
    seconds = round(seconds % (24 * 3600))
    hours = round(seconds // 3600)
    seconds %= 3600
    minutes = round(seconds // 60)
    seconds %= 60
    if days:
        return f'{days} days, {hours} hours, {minutes} minutes, and {seconds} seconds'
    elif hours:
        return f'{hours} hours, {minutes} minutes, and {seconds} seconds'
    elif minutes:
        return f'{minutes} minutes, and {seconds} seconds'
    elif seconds:
        return f'{seconds} seconds'


def logging_wrapper(file: Optional[bool] = False) -> Tuple[Optional[logging.Logger], logging.Logger,
                                                           Optional[logging.Logger], Optional[str]]:
    """Wraps logging module to create multiple handlers for different purposes.

    Args:
        file: Takes a boolean flag to determine if a file logger should be created.

    See Also:
        - fileLogger: Writes the log information only to the log file.
        - consoleLogger: Writes the log information only in stdout.

    Returns:
        tuple:
        A tuple of classes ``logging.Logger`` for file and console logging.
    """
    importlib.reload(logging)  # since the gmail-connector module uses logging, it is better to reload logging module
    log_formatter = logging.Formatter(
        fmt='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
        datefmt=DATETIME_FORMAT
    )

    console_logger = logging.getLogger('CONSOLE')
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt=log_formatter)
    console_logger.setLevel(level=logging.INFO)
    console_logger.addHandler(hdlr=console_handler)

    if file:
        logs_dir = os.path.join(os.getcwd(), 'logs')
        os.makedirs(logs_dir) if not os.path.isdir(logs_dir) else None
        file_logger = logging.getLogger('FILE')
        log_file = datetime.now().strftime(os.path.join(os.getcwd(), 'logs', 'vpn_server_%d_%m_%Y_%H_%M.log'))
        file_handler = logging.FileHandler(filename=log_file)
        file_handler.setFormatter(fmt=log_formatter)
        file_logger.setLevel(level=logging.INFO)
        file_logger.addHandler(hdlr=file_handler)
        hybrid_logger = logging.getLogger('HYBRID')
        hybrid_logger.addHandler(hdlr=console_handler)
        hybrid_logger.setLevel(level=logging.INFO)
        hybrid_logger.addHandler(hdlr=file_handler)
    else:
        file_logger, hybrid_logger, log_file = None, None, None

    return file_logger, console_logger, hybrid_logger, log_file
