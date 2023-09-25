import logging
import os
import sys
import time

from paramiko import AutoAddPolicy, RSAKey, SSHClient
from paramiko.ssh_exception import AuthenticationException
from paramiko_expect import SSHClientInteraction

from vpn.models.config import env, settings


class Server:
    """Initiates ``Server`` object to create an SSH session to configure the server.

    >>> Server

    """

    def __init__(self, hostname: str, username: str, logger: logging.Logger):
        """Instantiates the session using RSAKey generated from a ``***.pem`` file.

        Args:
            hostname: Hostname of the server.
        """
        self.logger = logger
        pem_key = RSAKey.from_private_key_file(filename=settings.key_pair_file)
        self.ssh_client = SSHClient()
        self.ssh_client.load_system_host_keys()
        self.ssh_client.set_missing_host_key_policy(policy=AutoAddPolicy())
        if username == env.vpn_username:
            try:
                # todo: Manual config accepts username and password, but unable to get authentication pass via paramiko
                self.ssh_client.connect(hostname=hostname, username=username, pkey=pem_key, password=env.vpn_password)
            except AuthenticationException as error:
                self.logger.warning(error)
                self.ssh_client.connect(hostname=hostname, username='openvpnas', pkey=pem_key)
        else:
            self.ssh_client.connect(hostname=hostname, username=username, pkey=pem_key)
        self.logger.info("Connected to %s as %s", hostname, username)
        # Backup before modifying logger to compatible version
        self._formatter = []
        self._level = self.logger.level

    def remove_formatter(self) -> None:
        """Remove any logging formatters to allow room for OpenVPN configuration interaction."""
        for handler in self.logger.handlers:
            self._formatter.append(handler.formatter)
            handler.formatter = None
        self.logger.setLevel(level=logging.INFO)
        sys.stdout = open(os.devnull, 'w')

    def add_formatter(self) -> None:
        """Re-add any formatters that were removed during instantiation."""
        for handler in self.logger.handlers:
            assert len(self._formatter) == 1
            handler.formatter = self._formatter[0]
        self.logger.setLevel(level=self._level)
        sys.stdout.close()
        sys.stdout = sys.__stdout__

    def restart_service(self) -> None:
        """Restarts the openvpn service."""
        self.ssh_client.exec_command("sudo service openvpnas stop")
        self.ssh_client.exec_command("sudo service openvpnas start")
        time.sleep(3)

    def test_service(self, timeout: int, display: bool) -> bool:
        """Check status of the service running on remote server.

        Args:
            timeout: Default interaction session timeout.
            display: Boolean flag whether to display interaction data on screen.

        Returns:
            bool:
            Returns a boolean flag if test was successful.
        """
        with SSHClientInteraction(client=self.ssh_client,
                                  timeout=timeout,
                                  display=display,
                                  output_callback=lambda msg: self.logger.info(msg)) as interact:
            self.remove_formatter()
            interact.send("systemctl status openvpnas", '\n')
            interact.expect(r".*Started OpenVPN Access Server\..*", timeout)
            self.add_formatter()
            return True

    def run_interactive_ssh(self,
                            display: bool = True,
                            timeout: int = 30) -> None:
        """Runs interactive ssh commands to configure the VPN server.

        Args:
            display: Boolean flag whether to display interaction data on screen.
            timeout: Default interaction session timeout.

        Returns:
            bool:
            Flag to indicate whether the interactive session has completed successfully.
        """
        self.remove_formatter()
        with SSHClientInteraction(client=self.ssh_client,
                                  timeout=timeout,
                                  display=display,
                                  output_callback=lambda msg: self.logger.info(msg)) as interact:
            for setting in settings.openvpn_config_commands:
                interact.expect(re_strings=setting.request, timeout=setting.timeout)
                interact.send(send_string=str(setting.response))
            # Blank to await final steps of configuration
            interact.expect(timeout=timeout)
            self.restart_service()
            interact.send("systemctl status openvpnas")
            interact.expect(r".*Started OpenVPN Access Server\..*", timeout=5)
            self.logger.info(interact.output_callback)
        self.ssh_client.close()
        self.add_formatter()
