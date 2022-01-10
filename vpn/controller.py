from datetime import datetime
from json import dump, load
from os import chmod, environ, path, remove
from sys import stdout
from time import perf_counter, sleep

import requests
from boto3 import client, resource
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from gmailconnector.responder import Response
from gmailconnector.send_email import SendEmail
from gmailconnector.send_sms import Messenger
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from vpn.defaults import AWSDefaults
from vpn.helper import (CURRENT_DIR, interactive_ssh, logging_wrapper,
                        time_converter)

disable_warnings(InsecureRequestWarning)  # Disable warnings for self-signed certificates

if path.isfile('.env'):
    load_dotenv(dotenv_path='.env', verbose=True, override=True)


class VPNServer:
    """Initiates ``VPNServer`` object to spin up an EC2 instance with a pre-configured AMI which serves as a VPN server.

    >>> VPNServer

    """

    def __init__(self, aws_access_key: str = environ.get('ACCESS_KEY'), aws_secret_key: str = environ.get('SECRET_KEY'),
                 aws_region_name: str = environ.get('REGION_NAME', 'us-west-2'), log: str = 'CONSOLE'):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module.

        Args:
            aws_access_key: Access token for AWS account.
            aws_secret_key: Secret ID for AWS account.
            aws_region_name: Region where the instance should live. Defaults to ``us-west-2``
            log: Determines whether to print the log in a console or send it to a file.

        See Also:
            - If no values (for aws authentication) are passed during object initialization, script checks for env vars.
            - If the environment variables are ``null``, gets the default credentials from ``~/.aws/credentials``.
        """
        # Logger setup
        file_logger, console_logger, hybrid_logger = logging_wrapper()
        if log.upper() == 'CONSOLE':
            self.logger = console_logger
        elif log.upper() == 'FILE':
            self.logger = file_logger
        else:
            self.logger = hybrid_logger

        # Notification information
        self.gmail_user = environ.get('gmail_user')
        self.gmail_pass = environ.get('gmail_pass')
        self.recipient = environ.get('recipient')
        self.phone = environ.get('phone')

        # AWS client and resource setup
        self.region = aws_region_name.lower()
        if not AWSDefaults.REGIONS.get(self.region):
            raise ValueError(f'Incorrect region name. {aws_region_name} does not exist.')
        self.ec2_client = client(service_name='ec2', region_name=self.region,
                                 aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
        self.ec2_resource = resource(service_name='ec2', region_name=self.region,
                                     aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
        self.port = int(environ.get('VPN_PORT', 943))

    def __del__(self):
        """Destructor to print the run time at the end."""
        self.logger.info(f'Total runtime: {time_converter(perf_counter())}')

    def _get_image_id(self) -> None:
        """Fetches AMI ID from public images."""
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
            self.logger.error(f'API call to retrieve AMI ID for {self.region} has failed.\n{error}')
            raise

        if not (retrieved := images.get('Images', [{}])[0].get('ImageId')):
            raise LookupError(f'Failed to retrieve AMI ID for {self.region}. Set one manually.')
        return retrieved

    def _sleeper(self, sleep_time: int) -> None:
        """Sleeps for a particular duration.

        Args:
            sleep_time: Takes the time script has to sleep, as an argument.
        """
        if str(self.logger) == '<Logger FILE (INFO)>':
            self.logger.info(f'Waiting for {sleep_time} seconds.')
            sleep(sleep_time)
            return

        sleep(1)
        for i in range(sleep_time):
            stdout.write(f'\rRemaining: {sleep_time - i:0{len(str(sleep_time))}}s')
            sleep(1)
        stdout.write('\r')

    def _create_key_pair(self) -> bool:
        """Creates a ``KeyPair`` of type ``RSA`` stored as a ``PEM`` file to use with ``OpenSSH``.

        Returns:
            bool:
            Flag to indicate the calling function whether a ``KeyPair`` was created.
        """
        try:
            response = self.ec2_client.create_key_pair(
                KeyName='OpenVPN',
                KeyType='rsa'
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidKeyPair.Duplicate)' in error and 'OpenVPN' in error:
                self.logger.warning('Found an existing KeyPair named: OpenVPN. Re-creating it.')
                self._delete_key_pair()
                self._create_key_pair()
                return True
            self.logger.error(f'API call to create key pair has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            with open(f'{CURRENT_DIR}OpenVPN.pem', 'w') as file:
                file.write(response.get('KeyMaterial'))
            self.logger.info('Created a key pair named: OpenVPN and stored as OpenVPN.pem')
            return True
        else:
            self.logger.error('Unable to create a key pair: OpenVPN')

    def _get_vpc_id(self) -> str or None:
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
            vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')
            self.logger.info(f'Got the default VPC: {vpc_id}')
            return vpc_id
        else:
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

    def _create_security_group(self) -> str or None:
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

    def _create_ec2_instance(self, image_id: str = environ.get(f"AMI_ID_{environ.get('REGION_NAME', 'us-west-2')}")) \
            -> str or None:
        """Creates an EC2 instance of type ``t2.nano`` with the pre-configured AMI id.

        Args:
            image_id: Takes image ID as an argument. Defaults to ``ami_id`` in environment variable. Exits if `null`.

        Returns:
            str or None:
            Instance ID.
        """
        if not image_id and not (image_id := self._get_image_id()):
            self.logger.warning(f"AMI ID was not set. "
                                f"Using the default AMI ID {image_id} for the region {self.region}")
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
                ImageId=image_id,
                KeyName='OpenVPN',
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
                KeyName='OpenVPN'
            )
        except ClientError as error:
            self.logger.error(f'API call to delete the key OpenVPN has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info('OpenVPN has been deleted from KeyPairs.')
            if path.exists('OpenVPN.pem'):
                chmod('OpenVPN.pem', int('700', base=8) or 0o700)  # reset file permissions before deleting
                remove('OpenVPN.pem')
            return True
        else:
            self.logger.error('Failed to delete the key: OpenVPN')

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

    def _instance_info(self, instance_id: str) -> tuple or None:
        """Makes a ``describe_instance_status`` API call to get the status of the instance that was created.

        Args:
            instance_id: Takes the instance ID as an argument.

        Returns:
            tuple or None:
            A tuple object of Public DNS Name and Public IP Address.
        """
        self.logger.info('Waiting for the instance to go live.')
        self._sleeper(sleep_time=15)
        while True:
            sleep(3)
            try:
                response = self.ec2_client.describe_instance_status(
                    InstanceIds=[instance_id]
                )
            except ClientError as error:
                self.logger.error(f'API call to describe instance has failed.{error}')
                return

            if response.get('ResponseMetadata').get('HTTPStatusCode') != 200:
                continue
            if status := response.get('InstanceStatuses'):
                if status[0].get('InstanceState').get('Name') == 'running':
                    instance_info = self.ec2_resource.Instance(instance_id)
                    return (instance_info.public_dns_name,
                            instance_info.public_ip_address,
                            instance_info.private_ip_address)

    def _notification_response(self, response: Response) -> None:
        """Logs the response after sending notifications.

        Args:
            response: Takes the response dictionary to log the success/failure message.
        """
        if response.ok:
            self.logger.info(response.body)
        else:
            self.logger.error(response.json())

    def _tester(self, data: dict) -> bool:
        """Tests ``GET`` and ``SSH`` connections on the existing server.

        Args:
            data: Takes the instance information in a dictionary format as an argument.

        See Also:
            - Called when a startup request is made but ``vpn_info.json`` and ``OpenVPN.pem`` are present already.
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
            return False

        self.logger.info(f"Testing SSH connection to {data.get('public_dns')}")
        if url_check.ok and interactive_ssh(hostname=data.get('public_dns'), username='openvpnas',
                                            pem_file='OpenVPN.pem', logger=self.logger,
                                            display=False, timeout=5):
            self.logger.info(f"Connection to https://{data.get('public_ip')}:{self.port} and "
                             f"SSH to {data.get('public_dns')} was successful.")
            return True

    def reconfigure_vpn(self):
        """Runs the configuration on an existing VPN server."""
        if path.isfile(f'{CURRENT_DIR}vpn_info.json') and path.isfile(f'{CURRENT_DIR}OpenVPN.pem'):
            with open(f'{CURRENT_DIR}vpn_info.json') as file:
                data_exist = load(file)
            self._configure_vpn(data=data_exist)
            if not self._tester(data=data_exist):
                self.logger.error('Unable to connect VPN server. Please check the logs for more information.')
        else:
            self.logger.error('Input file: vpn_info.json is missing. CANNOT proceed.')

    def test_vpn(self):
        """Tests the ``GET`` and ``SSH`` connections to an existing VPN server."""
        if path.isfile(f'{CURRENT_DIR}vpn_info.json') and path.isfile(f'{CURRENT_DIR}OpenVPN.pem'):
            with open(f'{CURRENT_DIR}vpn_info.json') as file:
                data_exist = load(file)
            self._tester(data=data_exist)
        else:
            self.logger.error('Input file: vpn_info.json is missing. CANNOT proceed.')

    def create_vpn_server(self) -> None:
        """Calls the class methods ``_create_ec2_instance`` and ``_instance_info`` to configure the VPN server.

        See Also:
            - Checks if ``vpn_info.json`` and ``OpenVPN.pem`` files are present, before spinning up a new instance.
            - If present, checks the connection to the existing origin and tears down the instance if connection fails.
            - If connects, notifies user with details and adds key-value pair ``Retry: True`` to ``vpn_info.json``
            - If another request is sent to start the vpn, creates a new instance regardless of existing info.
        """
        if path.isfile(f'{CURRENT_DIR}vpn_info.json') and path.isfile(f'{CURRENT_DIR}OpenVPN.pem'):
            with open(f'{CURRENT_DIR}vpn_info.json') as file:
                data_exist = load(file)

            self.logger.warning(f"Found an existing VPN Server running at {data_exist.get('SERVER')}")
            if self._tester(data=data_exist):
                if data_exist.get('RETRY'):
                    self.logger.warning('Received a second request to spin up a new VPN Server. Proceeding this time.')
                else:
                    data_exist.update({'RETRY': True})
                    self._notify(login_details=f"CURRENTLY SERVING: {data_exist.get('SERVER').lstrip('https://')}\n\n"
                                               f"Username: {data_exist.get('USERNAME')}\n"
                                               f"Password: {data_exist.get('PASSWORD')}")
                    with open(f'{CURRENT_DIR}vpn_info.json', 'w') as file:
                        dump(data_exist, file, indent=2)
                    return
            else:
                self.logger.error('Existing server is not responding. Creating a new one.')
                self.delete_vpn_server(partial=True)

        if not all([self.gmail_user, self.gmail_pass, self.phone, self.recipient]):
            self.logger.warning('Env vars for notifications are missing! '
                                'Credentials will be stored in vpn_info.json file.')

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

        with open(f'{CURRENT_DIR}vpn_info.json', 'w') as file:
            dump(instance_info, file, indent=2)

        self.logger.info('Restricting wide open permissions to OpenVPN.pem')
        chmod('OpenVPN.pem', int('400', base=8) or 0o400)

        self.logger.info('Waiting for SSH origin to be active.')
        self._sleeper(sleep_time=15)

        vpn_username, vpn_password = self._configure_vpn(data=instance_info)

        if not self._tester(data=instance_info):
            self.logger.error('Unable to connect VPN server. Please check the logs for more information.')
            return

        self.logger.info('VPN server has been configured successfully. Details have been stored in vpn_info.json.')
        url = f"https://{instance_info.get('public_ip')}"
        instance_info.update({'SERVER': f"{url}:{self.port}", 'USERNAME': vpn_username, 'PASSWORD': vpn_password})
        with open(f'{CURRENT_DIR}vpn_info.json', 'w') as file:
            dump(instance_info, file, indent=2)

        self._notify(login_details=f"SERVER: {public_ip}:{self.port}\n\n"
                                   f"Username: {vpn_username}\n"
                                   f"Password: {vpn_password}")

    def _configure_vpn(self, data: dict) -> tuple:
        """Frames a dictionary of anticipated prompts and responses to initiate interactive SSH commands.

        Args:
            data: A dictionary with key, value pairs with instance information in it.

        Returns:
            tuple:
            A tuple of ``vpn_username`` and ``vpn_password`` to trigger the notification.
        """
        self.logger.info('Configuring VPN server.')
        if not (vpn_username := environ.get('VPN_USERNAME')):
            vpn_username = environ.get('USER', 'openvpn')
        vpn_password = environ.get('VPN_PASSWORD', 'awsVPN2021')

        configuration = {
            "> Please enter 'yes' to indicate your agreement [no]: ": "yes",
            "> Press ENTER for default [yes]: ": "yes",
            "> Press Enter for default [1]: ": "1",
            "Please specify the port number for the Admin Web UI.": [str(self.port)],
            "Please specify the TCP port number for the OpenVPN Daemon.": "443",
            "Should client traffic be routed by default through the VPN?": "yes",
            "Should client DNS traffic be routed by default through the VPN?": "no",
            "Use local authentication via internal DB?": "yes",
            "Should private subnets be accessible to clients by default?": "yes",
            "Do you wish to login to the Admin UI as 'openvpn'?": "no",
            "Specify the username for an existing user or for the new user account:": [vpn_username],
            f"Type the password for the '{vpn_username}' account:": [vpn_password],
            f"Confirm the password for the '{vpn_username}' account:": [vpn_password],
            "Please specify your Activation key (or leave blank to specify later):": "\n"
        }

        interactive_ssh(hostname=data.get('public_dns'),
                        username='root',
                        pem_file='OpenVPN.pem',
                        logger=self.logger,
                        prompts_and_response=configuration)

        return vpn_username, vpn_password

    def _notify(self, login_details: str) -> None:
        """Send login details via SMS and Email if the following env vars are present.

        ``gmail_user``, ``gmail_pass`` and ``phone [or] recipient``

        Args:
            login_details: Login information that has to be sent as a message/email.
        """
        subject = f"VPN Server::{datetime.now().strftime('%B %d, %Y %I:%M %p')}"
        if self.phone:
            sms_response = Messenger(gmail_user=self.gmail_user, gmail_pass=self.gmail_pass, phone=self.phone,
                                     subject=subject, message=login_details).send_sms()

            self._notification_response(response=sms_response)
        else:
            self.logger.warning('ENV vars are not configured for an SMS notification.')

        if self.recipient:
            email_response = SendEmail(gmail_user=self.gmail_user, gmail_pass=self.gmail_pass, recipient=self.recipient,
                                       subject=subject, body=login_details).send_email()
            self._notification_response(response=email_response)
        else:
            self.logger.warning('ENV vars are not configured for an email notification.')

    def delete_vpn_server(self, partial: bool = False) -> None:
        """Disables VPN server by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created.

        Args:
            partial: Flag to indicate whether the ``SecurityGroup`` has to be removed.

        See Also:
            There is a wait time (60 seconds) for the instance to terminate.
        """
        if not path.exists('vpn_info.json'):
            self.logger.error('Input file: vpn_info.json is missing. CANNOT proceed.')
            return

        with open(f'{CURRENT_DIR}vpn_info.json', 'r') as file:
            data = load(file)

        if self._delete_key_pair() and self._terminate_ec2_instance(instance_id=data.get('instance_id')):
            if partial:
                remove('vpn_info.json')
                return
            self.logger.info('Waiting for dependents to release before deleting SecurityGroup.')
            self._sleeper(sleep_time=90)
            while True:
                if self._delete_security_group(security_group_id=data.get('security_group_id')):
                    break
                else:
                    self._sleeper(sleep_time=20)
            remove('vpn_info.json')
