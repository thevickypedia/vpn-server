import json
import os
import sys
import time
from datetime import datetime
from ipaddress import IPv4Address
from threading import Thread
from typing import Dict, NoReturn, Optional, Tuple, Union

import boto3
import dotenv
import requests
import urllib3
from botocore.exceptions import ClientError
from gmailconnector.responder import Response
from gmailconnector.send_email import SendEmail
from gmailconnector.send_sms import Messenger
from urllib3.exceptions import InsecureRequestWarning

from .defaults import AWSDefaults
from .helper import logging_wrapper, time_converter
from .models import Settings
from .server import Server

urllib3.disable_warnings(InsecureRequestWarning)  # Disable warnings for self-signed certificates

if os.path.isfile('.env'):
    dotenv.load_dotenv(dotenv_path='.env', verbose=True, override=True)
settings = Settings()

PEM_FILE = os.path.join(os.getcwd(), 'OpenVPN.pem')
INFO_FILE = os.path.join(os.getcwd(), 'vpn_info.json')


class VPNServer:
    """Initiates ``VPNServer`` object to spin up an EC2 instance with a pre-configured AMI which serves as a VPN server.

    >>> VPNServer

    """

    def __init__(self, aws_access_key: str = settings.aws_access_key,
                 aws_secret_key: str = settings.aws_secret_key, image_id: str = settings.image_id,
                 aws_region_name: str = settings.aws_region_name, vpn_port: int = settings.vpn_port,
                 domain: str = settings.domain, record_name: str = settings.record_name,
                 vpn_username: str = settings.vpn_username, vpn_password: str = settings.vpn_password,
                 gmail_user: str = settings.gmail_user, gmail_pass: str = settings.gmail_pass,
                 phone: str = settings.phone, recipient: str = settings.recipient,
                 log: str = 'CONSOLE'):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module.

        Args:
            aws_access_key: Access token for AWS account.
            aws_secret_key: Secret ID for AWS account.
            aws_region_name: Region where the instance should live. Defaults to AWS profile default.
            image_id: AMI ID using which the instance should be created.
            vpn_port: Port number using which VPN traffic should be forwarded.
            domain: Domain name for the hosted zone.
            record_name: Record using which the VPN server has to be accessed.
            vpn_username: Username to access VPN client.
            vpn_password: Password to access VPN client.
            gmail_user: Gmail username or email address.
            gmail_pass: Gmail password.
            phone: Phone number to which an SMS notification has to be sent.
            recipient: Email address to which an email notification has to be sent.
            log: Determines whether to print the log in a console or send it to a file.

        See Also:
            - If no values (for aws authentication) are passed during object initialization, script checks for env vars.
            - If the environment variables are ``null``, gets the default credentials from ``~/.aws/credentials``.
        """
        # Check is custom directory exists, raise an error otherwise
        if os.path.isdir(os.path.dirname(PEM_FILE)):
            self.PEM_FILE = PEM_FILE
            self.PEM_IDENTIFIER = os.path.basename(PEM_FILE).rstrip('.pem')
        else:
            raise NotADirectoryError(f"{os.path.dirname(PEM_FILE)!r} does not exist!")
        if os.path.isdir(os.path.dirname(INFO_FILE)):
            self.INFO_FILE = INFO_FILE
            self.INFO_IDENTIFIER = os.path.basename(INFO_FILE)
        else:
            raise NotADirectoryError(f"{os.path.dirname(INFO_FILE)!r} does not exist!")

        # AWS region setup
        test_client = boto3.client('ec2')
        default_region = test_client.meta.region_name
        self.AVAILABLE_REGIONS = [region['RegionName'] for region in test_client.describe_regions()['Regions']]
        if aws_region_name and aws_region_name.lower() in self.AVAILABLE_REGIONS:
            self.region = aws_region_name.lower()
        elif aws_region_name:
            raise ValueError(
                f'Incorrect region name. {aws_region_name!r} does not exist.'
            )
        else:
            self.region = default_region

        self.SESSION = boto3.session.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key,
                                             region_name=self.region)

        # AWS user inputs
        self.image_id = image_id
        self.port = vpn_port
        self.domain = domain
        self.record_name = record_name

        # Load boto3 clients
        self.ec2_client = self.SESSION.client(service_name='ec2')
        self.ec2_resource = self.SESSION.resource(service_name='ec2')
        self.route53_client = self.SESSION.client(service_name='route53')

        # Login credentials setup
        self.vpn_username = vpn_username
        self.vpn_password = vpn_password

        # Logger setup
        if log.upper() == 'CONSOLE':
            file_logger, console_logger, hybrid_logger, log_file = logging_wrapper()
            self.logger = console_logger
        elif log.upper() == 'FILE':
            file_logger, console_logger, hybrid_logger, log_file = logging_wrapper(file=True)
            self.logger = file_logger
        else:
            file_logger, console_logger, hybrid_logger, log_file = logging_wrapper(file=True)
            self.logger = hybrid_logger
        self.log_file = log_file

        # Notification information
        self.gmail_user = gmail_user
        self.gmail_pass = gmail_pass
        self.recipient = recipient
        self.phone = phone

    def __del__(self):
        """Destructor to print the run time at the end."""
        if time and hasattr(self, 'logger'):  # Hit or miss, since this is not the actual purpose of a destructor
            self.logger.info(f'Total runtime: {time_converter(time.perf_counter())}')

    def _get_image_id(self) -> str:
        """Looks for AMI ID in the default image map. Fetches AMI ID from public images if not present.

        Returns:
            str:
            AMI ID.
        """
        if self.region.startswith('us'):
            return AWSDefaults.IMAGE_MAP[self.region]

        try:
            images = self.ec2_client.describe_images(Filters=[
                {
                    'Name': 'name',
                    'Values': [AWSDefaults.AMI_NAME]
                },
            ])
        except ClientError as error:
            self.logger.error(f'API call to retrieve AMI ID has failed.\n{error}')
            raise

        if not (retrieved := (images.get('Images') or [{}])[0].get('ImageId')):
            raise LookupError(
                f'Failed to retrieve AMI ID. Get AMI ID from {AWSDefaults.AMI_SOURCE} and set one manually for '
                f'{self.region!r}.'
            )
        return retrieved

    def _sleeper(self, sleep_time: int) -> NoReturn:
        """Sleeps for a particular duration.

        Args:
            sleep_time: Takes the time script has to sleep, as an argument.
        """
        if self.logger.name == 'FILE':
            self.logger.info(f'Waiting for {sleep_time} seconds.')
            time.sleep(sleep_time)
        else:
            time.sleep(1)
            for i in range(sleep_time):
                sys.stdout.write(f'\rRemaining: {sleep_time - i:0{len(str(sleep_time))}}s')
                time.sleep(1)
            sys.stdout.flush()
            sys.stdout.write('\r')

    def _create_key_pair(self) -> bool:
        """Creates a ``KeyPair`` of type ``RSA`` stored as a ``PEM`` file to use with ``OpenSSH``.

        Returns:
            bool:
            Flag to indicate the calling function whether a ``KeyPair`` was created.
        """
        try:
            response = self.ec2_client.create_key_pair(
                KeyName=self.PEM_IDENTIFIER,
                KeyType='rsa'
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidKeyPair.Duplicate)' in error and self.PEM_IDENTIFIER in error:
                self.logger.warning(f'Found an existing KeyPair named: {self.PEM_IDENTIFIER!r}. Re-creating it.')
                self._delete_key_pair()
                self._create_key_pair()
                return True
            self.logger.error(f'API call to create key pair has failed.\n{error!r}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            with open(self.PEM_FILE, 'w') as file:
                file.write(response.get('KeyMaterial'))
            self.logger.info(f'Created a key pair named: {self.PEM_IDENTIFIER!r} and stored as {self.PEM_FILE}')
            return True
        else:
            self.logger.error(f'Unable to create a key pair: {self.PEM_IDENTIFIER!r}')

    def _get_vpc_id(self) -> Union[str, None]:
        """Gets the default VPC id.

        Returns:
            str or None:
            Default VPC id.
        """
        try:
            response = self.ec2_client.describe_vpcs()
        except ClientError as error:
            self.logger.error(f'API call to get VPC id has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            if vpc_id := response.get('Vpcs', [{}])[0].get('VpcId', ''):
                self.logger.info(f'Got the default VPC: {vpc_id}')
                return vpc_id
        self.logger.error('Unable to get VPC ID')

    def _authorize_security_group(self, security_group_id: str) -> bool:
        """Authorizes the security group for certain ingress list.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        See Also:
            `Firewall configuration ports to be open: <https://tinyurl.com/ycxam2sr>`__

            - TCP 22 — SSH access.
            - TCP 443 — Web interface access and OpenVPN TCP connections.
            - TCP 943 — Web interface access (This can be dynamic, but the same should be used to configure the VPN.)
            - TCP 945 — Cluster control channel.
            - UDP 1194 — OpenVPN UDP connections.

        Returns:
            bool:
            Flag to indicate the calling function whether the security group was authorized.
        """
        try:
            response = self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 22,
                     'ToPort': 22,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': 443,
                     'ToPort': 443,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': self.port,
                     'ToPort': self.port,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': 945,
                     'ToPort': 945,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'udp',
                     'FromPort': 1194,
                     'ToPort': 1194,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ])
        except ClientError as error:
            error = str(error)
            if '(InvalidPermission.Duplicate)' in error:
                self.logger.warning(f'Identified same permissions in an existing SecurityGroup: {security_group_id}')
                return True
            self.logger.error(f'API call to authorize the security group {security_group_id} has failed.\n{error}')
            return False
        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'Ingress Successfully Set for SecurityGroup {security_group_id}')
            for sg_rule in response['SecurityGroupRules']:
                log = 'Allowed protocol: ' + sg_rule['IpProtocol'] + ' '
                if sg_rule['FromPort'] == sg_rule['ToPort']:
                    log += 'on port: ' + str(sg_rule['ToPort']) + ' '
                else:
                    log += 'from port:  ' f"{sg_rule['FromPort']} to port: {sg_rule['ToPort']}" + ' '
                self.logger.info(log + 'with CIDR ' + sg_rule['CidrIpv4'])
            return True
        else:
            self.logger.info(f'Failed to set Ingress: {response}')

    def _create_security_group(self) -> Union[str, None]:
        """Calls the class method ``_get_vpc_id`` and uses the VPC ID to create a ``SecurityGroup`` for the instance.

        Returns:
            str or None:
            SecurityGroup ID
        """
        if not (vpc_id := self._get_vpc_id()):
            return

        try:
            response = self.ec2_client.create_security_group(
                GroupName='OpenVPN Access Server',
                Description='Security Group to allow certain port ranges for VPN server.',
                VpcId=vpc_id
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidGroup.Duplicate)' in error and 'OpenVPN Access Server' in error:
                self.logger.warning('Found an existing SecurityGroup named: OpenVPN Access Server. Reusing it.')
                response = self.ec2_client.describe_security_groups(
                    Filters=[
                        dict(Name='group-name', Values=['OpenVPN Access Server'])
                    ]
                )
                group_id = response['SecurityGroups'][0]['GroupId']
                return group_id
            self.logger.error(f'API call to create security group has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            security_group_id = response['GroupId']
            self.logger.info(f'Security Group Created {security_group_id} in VPC {vpc_id}')
            return security_group_id
        else:
            self.logger.error('Failed to created the SecurityGroup')

    def _create_ec2_instance(self) -> Union[Tuple[str, str], None]:
        """Creates an EC2 instance of type ``t2.nano`` with the pre-configured AMI id.

        Returns:
            tuple:
            A tuple of Instance ID and Security Group ID.
        """
        self.image_id = self.image_id or self._get_image_id()
        if not self.image_id:
            return

        if not self._create_key_pair():
            return

        if not (security_group_id := self._create_security_group()):
            self._delete_key_pair()
            return

        if not self._authorize_security_group(security_group_id=security_group_id):
            self._delete_key_pair()
            self._delete_security_group(security_group_id=security_group_id)
            return

        try:
            response = self.ec2_client.run_instances(
                InstanceType="t2.nano",
                MaxCount=1,
                MinCount=1,
                ImageId=self.image_id,
                KeyName=self.PEM_IDENTIFIER,
                SecurityGroupIds=[security_group_id]
            )
        except ClientError as error:
            self._delete_key_pair()
            self._delete_security_group(security_group_id=security_group_id)
            self.logger.error(f'API call to create instance has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            instance_id = response.get('Instances')[0].get('InstanceId')
            self.logger.info(f'Created the EC2 instance: {instance_id}')
            return instance_id, security_group_id
        else:
            self._delete_key_pair()
            self._delete_security_group(security_group_id=security_group_id)
            self.logger.error('Failed to create an EC2 instance.')

    def _delete_key_pair(self) -> bool:
        """Deletes the ``KeyPair``.

        Returns:
            bool:
            Flag to indicate the calling function whether the KeyPair was deleted.
        """
        try:
            response = self.ec2_client.delete_key_pair(
                KeyName=self.PEM_IDENTIFIER
            )
        except ClientError as error:
            self.logger.error(f'API call to delete the key {self.PEM_IDENTIFIER!r} has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            if os.path.exists(self.PEM_FILE):
                self.logger.info(f'{self.PEM_IDENTIFIER!r} has been deleted from KeyPairs.')
                os.chmod(self.PEM_FILE, int('700', base=8) or 0o700)
                os.remove(self.PEM_FILE)
            return True
        else:
            self.logger.error(f'Failed to delete the key: {self.PEM_IDENTIFIER!r}')

    def _delete_security_group(self, security_group_id: str) -> bool:
        """Deletes the security group.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        Returns:
            bool:
            Flag to indicate the calling function whether the SecurityGroup was deleted.
        """
        try:
            response = self.ec2_client.delete_security_group(
                GroupId=security_group_id
            )
        except ClientError as error:
            self.logger.error(f'API call to delete the Security Group {security_group_id} has failed.\n{error}')
            if '(InvalidGroup.NotFound)' in str(error):
                return True
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'{security_group_id} has been deleted from Security Groups.')
            return True
        else:
            self.logger.error(f'Failed to delete the SecurityGroup: {security_group_id}')

    def _terminate_ec2_instance(self, instance_id: str) -> bool:
        """Terminates the requested instance.

        Args:
            instance_id: Takes instance ID as an argument. Defaults to the instance that was created previously.

        Returns:
            bool:
            Flag to indicate the calling function whether the instance was terminated.
        """
        try:
            response = self.ec2_client.terminate_instances(
                InstanceIds=[instance_id]
            )
        except ClientError as error:
            self.logger.error(f'API call to terminate the instance has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'InstanceId {instance_id} has been set to terminate.')
            return True
        else:
            self.logger.error(f'Failed to terminate the InstanceId: {instance_id}')

    def _instance_info(self, instance_id: str) -> Union[Tuple[str, str, str], None]:
        """Makes a ``describe_instance_status`` API call to get the status of the instance that was created.

        Args:
            instance_id: Takes the instance ID as an argument.

        Returns:
            tuple or None:
            A tuple object of Public DNS Name and Public IP Address.
        """
        self.logger.info('Waiting for the instance to go live.')
        self._sleeper(sleep_time=25)
        while True:
            self._sleeper(sleep_time=3)
            try:
                response = self.ec2_client.describe_instance_status(
                    InstanceIds=[instance_id]
                )
            except ClientError as error:
                self.logger.error(f'API call to describe instance has failed.\n{error}')
                return

            if response.get('ResponseMetadata').get('HTTPStatusCode') != 200:
                continue
            if status := response.get('InstanceStatuses'):
                if status[0].get('InstanceState').get('Name') == 'running':
                    instance_info = self.ec2_resource.Instance(instance_id)
                    return (instance_info.public_dns_name,
                            instance_info.public_ip_address,
                            instance_info.private_ip_address)

    def _tester(self, data: Dict) -> bool:
        """Tests ``GET`` and ``SSH`` connections on the existing server.

        Args:
            data: Takes the instance information in a dictionary format as an argument.

        See Also:
            - Called when a startup request is made but info file and pem file are present already.
            - Called when a manual test request is made.
            - Testing SSH connection will also run updates on the VM.

        Returns:
            bool:
            - ``True`` if the existing connection is reachable and ``ssh`` to the origin succeeds.
            - ``False`` if the connection fails or unable to ``ssh`` to the origin.
        """
        self.logger.info(f"Testing GET connection to https://{data.get('public_ip')}:{self.port}")
        try:
            url_check = requests.get(url=f"https://{data.get('public_ip')}:{self.port}", verify=False)
        except requests.ConnectionError:
            self.logger.error('Unable to connect the VPN server. Please check the logs for more information.')
            return False

        test_ssh = Server(username='openvpnas', hostname=data.get('public_dns'), pem_file=self.PEM_FILE)
        self.logger.info(f"Testing SSH connection to {data.get('public_dns')}")
        if url_check.ok and test_ssh.run_interactive_ssh(logger=self.logger, display=False,
                                                         timeout=5, log_file=self.log_file):
            self.logger.info(f"Connection to https://{data.get('public_ip')}:{self.port} and "
                             f"SSH to {data.get('public_dns')} was successful.")
            return True
        else:
            self.logger.error('Unable to establish SSH connection with the VPN server. '
                              'Please check the logs for more information.')
            return False

    def reconfigure_vpn(self) -> NoReturn:
        """Runs the configuration on an existing VPN server."""
        if os.path.isfile(self.INFO_FILE) and os.path.isfile(self.PEM_FILE):
            with open(self.INFO_FILE) as file:
                data_exist = json.load(file)
            self._configure_vpn(data=data_exist)
            self._tester(data=data_exist)
        else:
            self.logger.error(f'Input file: {self.INFO_IDENTIFIER} is missing. CANNOT proceed.')

    def test_vpn(self) -> NoReturn:
        """Tests the ``GET`` and ``SSH`` connections to an existing VPN server."""
        if os.path.isfile(self.INFO_FILE) and os.path.isfile(self.PEM_FILE):
            with open(self.INFO_FILE) as file:
                data_exist = json.load(file)
            self._tester(data=data_exist)
        else:
            self.logger.error(f'Input file: {self.INFO_IDENTIFIER} is missing. CANNOT proceed.')

    def _get_hosted_zone_id_by_name(self, domain: str) -> Union[str, None]:
        """Get hosted zone id using the domain name.

        Args:
            domain: Domain name to add the A record.

        Returns:
            str:
            Hosted zone ID.
        """
        try:
            zones = self.route53_client.list_hosted_zones_by_name(DNSName=domain)
        except ClientError as error:
            self.logger.error(f"API call to get hosted zone has failed.\n{error}")
            return

        if not zones or len(zones['HostedZones']) == 0:
            self.logger.info(f"Could not find hosted zone for the domain: {domain!r}")
            return

        zone_id = zones['HostedZones'][0]['Id']
        return zone_id.split('/')[-1]

    def _hosted_zone_record(self, instance_ip: Union[IPv4Address, str], action: str, record_name: Optional[str] = None,
                            domain: Optional[str] = None) -> Union[bool, None]:
        """Add or remove A record in hosted zone.

        Args:
            instance_ip: Public IP of the ec2 instance.
            action: Argument to ADD|DELETE|UPSERT dns record.
            record_name: Name of the DNS record.
            domain: Domain of the hosted zone where an alias record has been made.

        Returns:
            bool:
            Boolean flag to indicate whether the A name record was added.
        """
        domain = domain or self.domain
        record_name = record_name or self.record_name
        if not domain or not record_name:
            self.logger.warning('ENV vars are not configured for hosted zone.')
            return

        if not (hosted_zone_id := self._get_hosted_zone_id_by_name(domain=domain)):
            return

        try:
            response = self.route53_client.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    'Comment': 'OpenVPN server',
                    'Changes': [
                        {
                            'Action': action,
                            'ResourceRecordSet': {
                                'Name': record_name,
                                'Type': 'A',
                                'TTL': 300,
                                'ResourceRecords': [
                                    {
                                        'Value': instance_ip
                                    },
                                ],
                            }
                        },
                    ]
                }
            )
        except ClientError as error:
            self.logger.error(f"API call to add A record has failed.\n{error}")
            return

        if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
            self.logger.info(f"{action.lower()}'ed {record_name} → {instance_ip} in the hosted zone: "
                             f"{'.'.join(record_name.split('.')[-2:])}")
            return True
        else:
            self.logger.error(f"Failed to add A record: {record_name!r}")

    def create_vpn_server(self) -> None:
        """Calls the class methods ``_create_ec2_instance`` and ``_instance_info`` to configure the VPN server.

        See Also:
            - Checks if info and pem files are present, before spinning up a new instance.
            - If present, checks the connection to the existing origin and tears down the instance if connection fails.
            - If connects, notifies user with details and adds key-value pair ``Retry: True`` to info file.
            - If another request is sent to start the vpn, creates a new instance regardless of existing info.
        """
        if os.path.isfile(self.INFO_FILE) and os.path.isfile(self.PEM_FILE):
            with open(self.INFO_FILE) as file:
                data_exist = json.load(file)

            self.logger.warning(f"Found an existing VPN Server running at {data_exist.get('SERVER')}")
            if self._tester(data=data_exist):
                if data_exist.get('RETRY'):
                    self.logger.warning('Received a second request to spin up a new VPN Server. Proceeding this time.')
                else:
                    data_exist.update({'RETRY': True})
                    self._notify(message=f"CURRENTLY SERVING: {data_exist.get('SERVER').lstrip('https://')}\n\n"
                                         f"Username: {data_exist.get('USERNAME')}\n"
                                         f"Password: {data_exist.get('PASSWORD')}")
                    with open(self.INFO_FILE, 'w') as file:
                        json.dump(data_exist, file, indent=2)
                    return
            else:
                self.logger.error('Existing server is not responding. Creating a new one.')
                self.delete_vpn_server(partial=True)  # Keeps the security group for re-use

        if not (instance_basic := self._create_ec2_instance()):
            return
        instance_id, security_group_id = instance_basic

        if not (instance := self._instance_info(instance_id=instance_id)):
            return
        public_dns, public_ip, private_ip = instance

        instance_info = {
            'instance_id': instance_id,
            'public_dns': public_dns,
            'public_ip': public_ip,
            'private_ip': private_ip,
            'security_group_id': security_group_id
        }

        with open(self.INFO_FILE, 'w') as file:
            json.dump(instance_info, file, indent=2)

        self.logger.info(f'Restricting wide open permissions to {self.PEM_FILE!r}')
        os.chmod(self.PEM_FILE, int('400', base=8) or 0o400)

        self.logger.info('Waiting for SSH origin to be active.')
        self._sleeper(sleep_time=15)

        if not self._configure_vpn(data=instance_info):
            self.logger.warning('Unknown error occurred during configuration. Testing connecting to server.')

        if not self._tester(data=instance_info):
            if self.logger.name == 'FILE':
                self._notify(message='Failed to configure VPN server. Please check the logs for more information.',
                             attachment=self.log_file)
            return

        if self._hosted_zone_record(instance_ip=public_ip, action='UPSERT'):
            instance_info['domain'] = self.domain
            instance_info['record_name'] = self.record_name

        self.logger.info('VPN server has been configured successfully. '
                         f'Details have been stored in {self.INFO_IDENTIFIER}.')
        url = f"https://{instance_info.get('public_ip')}"
        instance_info.update({'SERVER': f"{url}:{self.port}",
                              'USERNAME': self.vpn_username,
                              'PASSWORD': self.vpn_password})
        with open(self.INFO_FILE, 'w') as file:
            json.dump(instance_info, file, indent=2)

        self._notify(message=f"SERVER: {public_ip}:{self.port}\n\n"
                             f"Username: {self.vpn_username}\n"
                             f"Password: {self.vpn_password}")

    def _configure_vpn(self, data: dict) -> bool:
        """Frames a dictionary of anticipated prompts and responses to initiate interactive SSH commands.

        Args:
            data: A dictionary with key, value pairs with instance information in it.

        Returns:
            bool:
            A boolean flag to indicate whether the interactive ssh session succeeded.
        """
        self.logger.info('Configuring VPN server.')

        configuration = {
            "1|Please enter 'yes' to indicate your agreement \\[no\\]: ": ("yes", 10),
            "2|> Press ENTER for default \\[yes\\]: ": ("yes", 2),
            "3|> Press Enter for default \\[1\\]: ": ("1", 2),
            "4|> Press ENTER for default \\[943\\]: ": [str(self.port), 2],
            "5|> Press ENTER for default \\[443\\]: ": ("443", 2),
            "6|> Press ENTER for default \\[no\\]: ": ("yes", 2),
            "7|> Press ENTER for default \\[no\\]: ": ("no", 2),
            "8|> Press ENTER for default \\[yes\\]: ": ("yes", 2),
            "9|> Press ENTER for EC2 default \\[yes\\]: ": ("yes", 2),
            "10|> Press ENTER for default \\[yes\\]: ": ("no", 2),
            "11|> Specify the username for an existing user or for the new user account: ": [self.vpn_username, 2],
            f"12|Type the password for the '{self.vpn_username}' account:": [self.vpn_password, 2],
            f"13|Confirm the password for the '{self.vpn_username}' account:": [self.vpn_password, 2],
            "14|> Please specify your Activation key \\(or leave blank to specify later\\): ": ("\n", 2)
        }

        ssh_configuration = Server(hostname=data.get('public_dns'),
                                   username='root',
                                   pem_file=self.PEM_FILE)
        return ssh_configuration.run_interactive_ssh(logger=self.logger, log_file=self.log_file,
                                                     prompts_and_response=configuration)

    def _notify(self, message: str, attachment: Optional[str] = None) -> None:
        """Send login details via SMS and Email if the following env vars are present.

        ``gmail_user``, ``gmail_pass`` and ``phone [or] recipient``

        Args:
            message: Login information that has to be sent as a message/email.
            attachment: Name of the log file in case of a failure.
        """
        subject = f"VPN Server::{datetime.now().strftime('%B %d, %Y %I:%M %p')}"
        if self.recipient:
            email_response = SendEmail(gmail_user=self.gmail_user,
                                       gmail_pass=self.gmail_pass).send_email(recipient=self.recipient,
                                                                              subject=subject, body=message,
                                                                              sender='VPNServer', attachment=attachment)
            self._notification_response(response=email_response)
        else:
            self.logger.warning('ENV vars are not configured for an email notification.')

        if self.phone:
            sms_response = Messenger(gmail_user=self.gmail_user,
                                     gmail_pass=self.gmail_pass).send_sms(phone=self.phone, subject=subject,
                                                                          message=message)
            self._notification_response(response=sms_response)
        else:
            self.logger.warning('ENV vars are not configured for an SMS notification.')

    def _notification_response(self, response: Response) -> NoReturn:
        """Logs the response after sending notifications.

        Args:
            response: Takes the response dictionary to log the success/failure message.
        """
        if response.ok:
            self.logger.info(response.body)
        else:
            self.logger.error(response.json())

    def delete_vpn_server(self, partial: Optional[bool] = False, instance_id: Optional[str] = None,
                          security_group_id: Optional[str] = None,
                          domain: Optional[str] = None, record_name: Optional[str] = None,
                          instance_ip: Optional[Union[IPv4Address, str]] = None) -> None:
        """Disables VPN server by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created.

        Args:
            partial: Flag to indicate whether the ``SecurityGroup`` has to be removed.
            instance_id: Instance that has to be terminated.
            security_group_id: Security group that has to be removed.
            domain: Domain of the hosted zone where an alias record has been made.
            record_name: Record name for the alias.
            instance_ip: Value of the record.
        """
        if not os.path.exists(self.INFO_FILE) and (not instance_id or not security_group_id):
            self.logger.error("CANNOT proceed without input file or 'instance_id' and 'security_group_id' as params.")
            return

        if os.path.isfile(self.INFO_FILE):
            with open(self.INFO_FILE, 'r') as file:
                data = json.load(file)
        else:
            data = {}

        if self._delete_key_pair() and self._terminate_ec2_instance(instance_id=instance_id or data.get('instance_id')):
            Thread(target=self._hosted_zone_record,
                   kwargs={'record_name': record_name or data.get('record_name'),
                           'domain': domain or data.get('domain'),
                           'instance_ip': instance_ip or data.get('public_ip'), 'action': 'DELETE'}).start()
            if partial:
                os.remove(self.INFO_FILE)
                return
            self.logger.info('Waiting for dependents to release before deleting SecurityGroup.')
            self._sleeper(sleep_time=90)
            while True:
                if self._delete_security_group(security_group_id=security_group_id or data.get('security_group_id')):
                    break
                else:
                    self._sleeper(sleep_time=20)
            os.remove(self.INFO_FILE) if os.path.isfile(self.INFO_FILE) else None
