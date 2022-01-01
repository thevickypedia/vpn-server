import logging
import socket
import sys
from datetime import datetime
from importlib import reload
from os import devnull, path, system

from paramiko import (AuthenticationException, AutoAddPolicy,
                      BadHostKeyException, RSAKey, SSHClient)
from paramiko.ssh_exception import SSHException
from paramiko_expect import SSHClientInteraction

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


def logging_wrapper() -> tuple:
    """Wraps logging module to create multiple handlers for different purposes.

    See Also:
        - fileLogger: Writes the log information only to the log file.
        - consoleLogger: Writes the log information only in stdout.

    Returns:
        tuple:
        A tuple of classes ``logging.Logger`` for file and console logging.
    """
    reload(logging)  # since the gmail-connector module uses logging, it is better to reload logging module before start
    system('mkdir logs') if not path.isdir('logs') else None  # create logs directory if not found
    log_formatter = logging.Formatter(
        fmt='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
        datefmt=DATETIME_FORMAT
    )

    directory = path.dirname(__file__)
    log_file = datetime.now().strftime(path.join(directory, 'logs/vpn_server_%d_%m_%Y_%H_%M.log'))

    file_logger = logging.getLogger('FILE')
    console_logger = logging.getLogger('CONSOLE')

    file_handler = logging.FileHandler(filename=log_file)
    file_handler.setFormatter(fmt=log_formatter)
    file_logger.setLevel(level=logging.INFO)
    file_logger.addHandler(hdlr=file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt=log_formatter)
    console_logger.setLevel(level=logging.INFO)
    console_logger.addHandler(hdlr=console_handler)

    return file_logger, console_logger


def interactive_ssh(hostname: str, username: str, pem_file: str, logger: logging.Logger,
                    prompts_and_response: dict = None, display: bool = False) -> bool:
    """Runs interactive ssh commands to configure the VPN server.

    Args:
        hostname: Hostname of the server.
        username: Username to log in to the server.
        pem_file: PEM filename to authenticate the login.
        prompts_and_response: Prompts and their responses.
        logger: Logging module.
        display: Boolean flag whether to display interaction data on screen.
    """
    pem_key = RSAKey.from_private_key_file(filename=pem_file)
    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh_client.connect(hostname=hostname, username=username, pkey=pem_key)
    except (BadHostKeyException, AuthenticationException, SSHException, socket.error) as conn_error:
        logger.error(conn_error)
        return False
    if display:
        interact = SSHClientInteraction(client=ssh_client, timeout=5)
        sys.stdout = open(devnull, 'w')
    else:
        interact = SSHClientInteraction(client=ssh_client, timeout=30, display=True)
    if prompts_and_response:
        for prompt, response in prompts_and_response.items():
            logger.info(f"Expecting {prompt}")
            interact.expect(re_strings=prompt, timeout=2)
            logger.info(f"Sending {response}")
            interact.send(send_string=response)
    else:
        interact.send(send_string='logout')
    if display:
        interact.expect(timeout=1)
        sys.stdout = sys.__stdout__
    else:
        interact.expect()
    ssh_client.close()
    return True
