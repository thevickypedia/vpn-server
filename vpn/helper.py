import logging
import socket
import sys
from datetime import datetime
from importlib import reload
from os import devnull, getcwd, makedirs, path

from paramiko import (AuthenticationException, AutoAddPolicy,
                      BadHostKeyException, RSAKey, SSHClient)
from paramiko.ssh_exception import SSHException
from paramiko_expect import SSHClientInteraction

DATETIME_FORMAT = '%b-%d-%Y %I:%M:%S %p'
CURRENT_DIR = getcwd() + path.sep


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


def logging_wrapper(file: bool = False) -> tuple:
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
    reload(logging)  # since the gmail-connector module uses logging, it is better to reload logging module before start
    makedirs(f'{CURRENT_DIR}logs') if not path.isdir(f'{CURRENT_DIR}logs') else None  # create logs dir if not found
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
        file_logger = logging.getLogger('FILE')
        log_file = datetime.now().strftime(f'{CURRENT_DIR}logs{path.sep}vpn_server_%d_%m_%Y_%H_%M.log')
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


def interactive_ssh(hostname: str, username: str, pem_file: str, logger: logging.Logger,
                    prompts_and_response: dict = None, display: bool = True, timeout: int = 30) -> bool:
    """Runs interactive ssh commands to configure the VPN server.

    Args:
        hostname: Hostname of the server.
        username: Username to log in to the server.
        pem_file: PEM filename to authenticate the login.
        prompts_and_response: Prompts and their responses.
        logger: Logging module.
        display: Boolean flag whether to display interaction data on screen.
        timeout: Default session timeout.

    Returns:
        bool:
        Flag to indicate whether the interactive session has completed successfully.
    """
    pem_key = RSAKey.from_private_key_file(filename=pem_file)
    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh_client.connect(hostname=hostname, username=username, pkey=pem_key)
    except (ConnectionResetError, BadHostKeyException, AuthenticationException, SSHException, socket.error) as error:
        logger.error(error)
        return False
    interact = SSHClientInteraction(client=ssh_client, timeout=timeout, display=display)
    if not prompts_and_response:
        ssh_client.close()
        return True

    sys.stdout = open(devnull, 'w')
    n = 0
    for prompt, response in prompts_and_response.items():
        n += 1
        prompt = prompt.lstrip(f'{n}|')
        replace_this = '\\'
        logger.info(f"Expecting {prompt.replace(replace_this, '')}")
        interact.expect(re_strings=prompt, timeout=response[1])
        if isinstance(response, list):
            logger.info(f"Sending {''.join(['*' for _ in range(len(response[0]))])}")
        elif isinstance(response, tuple):
            logger.info(f"Sending {response[0]}")
        interact.send(send_string=response[0])
    if 'FILE' in str(logger):
        interact.expect(timeout=timeout)
        sys.stdout = sys.__stdout__
        ssh_client.close()
    else:
        sys.stdout = sys.__stdout__
        interact.expect(timeout=timeout)
        ssh_client.close()
    return True
