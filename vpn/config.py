from typing import AnyStr, Dict, List, Tuple, Union


class SSHConfig:
    """Initiates ``SSHConfig`` object to isolate the configuration dictionary.

    >>> SSHConfig

    """

    def __init__(self, port, vpn_username, vpn_password):
        """Instantiates object and stores port, username and password as members.

        Args:
            port: Port number to spin up VPN server on.
            vpn_username: Username for authentication.
            vpn_password: Password for authentication.
        """
        self.port = port
        self.vpn_username = vpn_username
        self.vpn_password = vpn_password

    def get_config(self) -> Dict[AnyStr, Union[Tuple, List]]:
        """Returns the dictionary for ssh config."""
        return {
            "1|Please enter 'yes' to indicate your agreement \\[no\\]: ": ("yes", 10),
            "2|> Press ENTER for default \\[yes\\]: ": ("yes", 2),
            "3|> Press Enter for default \\[1\\]: ": ("1", 2),
            "4|> Press ENTER for default \\[943\\]: ": [str(self.port), 2],
            "5|> Press ENTER for default \\[443\\]: ": ("443", 2),
            "6|> Press ENTER for default \\[no\\]: ": ("yes", 2),
            "7|> Press ENTER for default \\[no\\]: ": ("yes", 2),
            "8|> Press ENTER for default \\[yes\\]: ": ("yes", 2),
            "9|> Press ENTER for EC2 default \\[yes\\]: ": ("yes", 2),
            "10|> Press ENTER for default \\[yes\\]: ": ("no", 2),
            "11|> Specify the username for an existing user or for the new user account: ": [self.vpn_username, 2],
            f"12|Type the password for the '{self.vpn_username}' account:": [self.vpn_password, 2],
            f"13|Confirm the password for the '{self.vpn_username}' account:": [self.vpn_password, 2],
            "14|> Please specify your Activation key \\(or leave blank to specify later\\): ": ("\n", 2)
        }
