import os
import sys
from typing import Any

import boto3


def ec2_instance_types(region_name: str):
    """Yield all available EC2 instance types in a particular region."""
    ec2 = boto3.client('ec2', region_name=region_name)
    describe_args = {}
    while True:
        describe_result = ec2.describe_instance_types(**describe_args)
        yield from [i['InstanceType'] for i in describe_result['InstanceTypes']]
        if 'NextToken' not in describe_result:
            break
        describe_args['NextToken'] = describe_result['NextToken']


class Settings:
    """Initiate ``Settings`` object to access env vars acros modules.

    >>> Settings

    """

    def __init__(self):
        """Instantiate the class, load all env variables and perform custom validations."""
        self.aws_access_key: str = os.environ.get('AWS_ACCESS_KEY', os.environ.get('aws_access_key'))
        self.aws_secret_key: str = os.environ.get('AWS_SECRET_KEY', os.environ.get('aws_secret_key'))
        self.aws_region_name: str = os.environ.get('AWS_REGION_NAME', os.environ.get('aws_region_name'))
        self.image_id: str = os.environ.get('IMAGE_ID', os.environ.get('image_id'))
        self.domain: str = os.environ.get('DOMAIN', os.environ.get('domain'))
        self.record_name: str = os.environ.get('RECORD_NAME', os.environ.get('record_name'))
        self.vpn_username: str = os.environ.get('VPN_USERNAME', os.environ.get('vpn_username',
                                                                               os.environ.get('USER', 'openvpn')))
        self.vpn_password: str = os.environ.get('VPN_PASSWORD', os.environ.get('vpn_password', 'awsVPN2021'))
        self.gmail_user: str = os.environ.get('GMAIL_USER', os.environ.get('gmail_user'))
        self.gmail_pass: str = os.environ.get('GMAIL_PASS', os.environ.get('gmail_pass'))
        self.phone: str = os.environ.get('PHONE', os.environ.get('phone'))
        self.recipient: str = os.environ.get('RECIPIENT', os.environ.get('recipient'))
        self.instance_type: str = os.environ.get('INSTANCE_TYPE', os.environ.get('instance_type'))

        test_client = boto3.client('ec2')
        self.available_regions = [region['RegionName'] for region in test_client.describe_regions()['Regions']]
        if self.aws_region_name and self.aws_region_name.lower() in self.available_regions:
            self.aws_region_name = self.aws_region_name.lower()
        elif self.aws_region_name:
            raise ValueError(
                f'Incorrect region name. {self.aws_region_name!r} does not exist.'
            )
        else:
            self.aws_region_name = test_client.meta.region_name

        if self.instance_type and self.instance_type in list(ec2_instance_types(region_name=self.aws_region_name)):
            self.instance_type = self.instance_type
        elif self.instance_type:
            raise ValueError(
                f'Incorrect instance type. {self.instance_type!r} does not exist.'
            )
        else:
            self.instance_type = "t2.nano"


def write_screen(text: Any) -> None:
    """Write text on screen that can be cleared later.

    Args:
        text: Text to be written.
    """
    sys.stdout.write(f"\r{text}")


def flush_screen() -> None:
    """Flushes the screen output.

    See Also:
        Writes new set of empty strings for the size of the terminal if ran using one.
    """
    if sys.stdin.isatty():
        sys.stdout.write(f"\r{' '.join(['' for _ in range(os.get_terminal_size().columns)])}")
    else:
        sys.stdout.write("\r")
