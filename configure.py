import socket
import sys
from logging import Logger
from os import devnull

from paramiko import (AuthenticationException, AutoAddPolicy,
                      BadHostKeyException, RSAKey, SSHClient)
from paramiko.ssh_exception import SSHException
from paramiko_expect import SSHClientInteraction

DATETIME_FORMAT = '%b-%d-%Y %I:%M:%S %p'


def interactive_ssh(hostname: str, username: str, pem_file: str, logger: Logger,
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
        interact = SSHClientInteraction(client=ssh_client, timeout=20, display=True)
    if prompts_and_response:
        interact.send(send_string='yes')
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
