import logging
import os
import sys
from typing import Dict, Optional

from paramiko import AutoAddPolicy, RSAKey, SSHClient
from paramiko_expect import SSHClientInteraction


class Server:
    """Initiates ``Server`` object to create an SSH session to configure the server.

    >>> Server

    """

    def __init__(self, hostname: str, pem_file: str, username: str):
        """Instantiates the session using RSAKey generated from a ``***.pem`` file.

        Args:
            hostname: Hostname of the server.
            username: Username to log in to the server.
            pem_file: PEM filename to authenticate the login.
        """
        pem_key = RSAKey.from_private_key_file(filename=pem_file)
        self.ssh_client = SSHClient()
        self.ssh_client.load_system_host_keys()
        self.ssh_client.set_missing_host_key_policy(policy=AutoAddPolicy())
        self.ssh_client.connect(hostname=hostname, username=username, pkey=pem_key)

    def run_interactive_ssh(self, logger: logging.Logger, log_file: Optional[str] = None,
                            prompts_and_response: Optional[Dict] = None,
                            display: Optional[bool] = True, timeout: Optional[int] = 30) -> bool:
        """Runs interactive ssh commands to configure the VPN server.

        Args:
            prompts_and_response: Prompts and their responses.
            logger: Logging module.
            display: Boolean flag whether to display interaction data on screen.
            timeout: Default session timeout.
            log_file: To write clean console output to the log file.

        Returns:
            bool:
            Flag to indicate whether the interactive session has completed successfully.
        """
        interact = SSHClientInteraction(client=self.ssh_client, timeout=timeout, display=display)
        if not prompts_and_response:
            self.ssh_client.close()
            return True

        sys.stdout = open(log_file, 'a') if log_file else open(os.devnull, 'w')
        n = 0
        for prompt, response in prompts_and_response.items():
            n += 1
            prompt = prompt.lstrip(f'{n}|')
            replace_this = '\\'
            None if log_file else logger.info(f"Expecting {prompt.replace(replace_this, '')}")
            interact.expect(re_strings=prompt, timeout=response[1])
            if not log_file:  # Log 'prompt and response' only if it is console
                if isinstance(response, list):  # Secure information that shouldn't be on the logs
                    logger.info(f"Sending {''.join(['*' for _ in range(len(response[0]))])}")
                elif isinstance(response, tuple):
                    logger.info(f"Sending {response[0]}")
            interact.send(send_string=response[0])
        if log_file:
            interact.expect(timeout=timeout)
            sys.stdout.close()
            sys.stdout = sys.__stdout__
            self.ssh_client.close()
        else:
            sys.stdout.close()
            sys.stdout = sys.__stdout__
            interact.expect(timeout=timeout)
            self.ssh_client.close()
        return True
