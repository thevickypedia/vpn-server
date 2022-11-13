import os


class Settings:
    """Initiate ``Settings`` object to access env vars acros modules.

    >>> Settings

    """

    def __init__(self):
        """Instantiate the class and load all env variables."""
        self.aws_access_key: str = os.environ.get('AWS_ACCESS_KEY', os.environ.get('aws_access_key'))
        self.aws_secret_key: str = os.environ.get('AWS_SECRET_KEY', os.environ.get('aws_secret_key'))
        self.aws_region_name: str = os.environ.get('AWS_REGION_NAME', os.environ.get('aws_region_name'))
        self.image_id: str = os.environ.get('IMAGE_ID', os.environ.get('image_id'))
        self.vpn_port: int = os.environ.get('VPN_PORT', os.environ.get('vpn_port', 943))
        self.domain: str = os.environ.get('DOMAIN', os.environ.get('domain'))
        self.record_name: str = os.environ.get('RECORD_NAME', os.environ.get('record_name'))
        self.vpn_username: str = os.environ.get('VPN_USERNAME', os.environ.get('vpn_username',
                                                                               os.environ.get('USER', 'openvpn')))
        self.vpn_password: str = os.environ.get('VPN_PASSWORD', os.environ.get('vpn_password', 'awsVPN2021'))
        self.gmail_user: str = os.environ.get('GMAIL_USER', os.environ.get('gmail_user'))
        self.gmail_pass: str = os.environ.get('GMAIL_PASS', os.environ.get('gmail_pass'))
        self.phone: str = os.environ.get('PHONE', os.environ.get('phone'))
        self.recipient: str = os.environ.get('RECIPIENT', os.environ.get('recipient'))

        if not isinstance(self.vpn_port, int):
            if str(self.vpn_port).isdigit():
                self.vpn_port = int(self.vpn_port)
            else:
                raise ValueError(
                    "Port number should be an integer."
                )
