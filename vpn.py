from datetime import datetime
from json import dump, load
from os import environ, getpid, path, system
from sys import argv, stdout
from time import perf_counter, sleep

import requests
from boto3 import client, resource
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from gmailconnector.responder import Response
from gmailconnector.send_email import SendEmail
from gmailconnector.send_sms import Messenger
from psutil import Process
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from helper import interactive_ssh, logging_wrapper, time_converter

disable_warnings(InsecureRequestWarning)  # Disable warnings for self-signed certificates

if path.isfile('.env'):
    load_dotenv(dotenv_path='.env', verbose=True, override=True)


class VPNServer:
    """Initiates ``VPNServer`` object to spin up an EC2 instance with a pre-configured AMI which serves as a VPN server.

    >>> VPNServer

    """

    def __init__(self, aws_access_key: str = environ.get('ACCESS_KEY'), aws_secret_key: str = environ.get('SECRET_KEY'),
                 aws_region_name: str = environ.get('REGION_NAME', 'us-west-2')):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module.

        Args:
            aws_access_key: Access token for AWS account.
            aws_secret_key: Secret ID for AWS account.
            aws_region_name: Region where the instance should live. Defaults to ``us-west-2``

        See Also:
            - If no values (for aws authentication) are passed during object initialization, script checks for env vars.
            - If the environment variables are ``null``, gets the default credentials from ``~/.aws/credentials``.
        """
        # Hard-coded certificate file name, server information file name, security group name
        self.key_name = 'OpenVPN'
        self.server_file = 'server_info.json'
        self.security_group_name = 'OpenVPN Access Server'

        # Logger setup
        file_logger, console_logger = logging_wrapper()
        if environ.get('ENV') == 'Jarvis':
            self.logger = file_logger
        else:
            self.logger = console_logger

        # Notification information
        self.gmail_user = environ.get('gmail_user')
        self.gmail_pass = environ.get('gmail_pass')
        self.recipient = environ.get('recipient')
        self.phone = environ.get('phone')

        # AWS client and resource setup
        self.region = aws_region_name
        self.ec2_client = client(service_name='ec2', region_name=aws_region_name,
                                 aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
        self.ec2_resource = resource(service_name='ec2', region_name=aws_region_name,
                                     aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
        self.port = int(environ.get('PORT', 943))

    def __del__(self):
        """Destructor to print the run time at the end."""
        self.logger.info(f'Total runtime: {time_converter(perf_counter())}')

    def _sleeper(self, sleep_time: int) -> None:
        """Sleeps for a particular duration.

        See Also:
            - If triggered by ``Jarvis``, logs and waits else writes the remaining time in ``stdout``.

        Args:
            sleep_time: Takes the time script has to sleep, as an argument.
        """
        if environ.get('ENV') == 'Jarvis':
            self.logger.info(f'Waiting for {sleep_time} seconds.')
            sleep(sleep_time + 2)
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
                KeyName=self.key_name,
                KeyType='rsa'
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidKeyPair.Duplicate)' in error and self.key_name in error:
                self.logger.warning(f'Found an existing KeyPair named: {self.key_name}. Re-creating it.')
                self._delete_key_pair()
                self._create_key_pair()
                return True
            self.logger.error(f'API call to create key pair has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            with open(f'{self.key_name}.pem', 'w') as file:
                file.write(response.get('KeyMaterial'))
            self.logger.info(f'Created a key pair named: {self.key_name} and stored as {self.key_name}.pem')
            return True
        else:
            self.logger.error(f'Unable to create a key pair: {self.key_name}')

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
                     'FromPort': self.port,
                     'ToPort': self.port,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': 945,
                     'ToPort': 945,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': 443,
                     'ToPort': 443,
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
                GroupName=self.security_group_name,
                Description='Security Group to allow certain port ranges for VPN server.',
                VpcId=vpc_id
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidGroup.Duplicate)' in error and self.security_group_name in error:
                self.logger.warning(f'Found an existing SecurityGroup named: {self.security_group_name}. Reusing it.')
                response = self.ec2_client.describe_security_groups(
                    Filters=[
                        dict(Name='group-name', Values=[self.security_group_name])
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
        """Creates an EC2 instance of type ``t2.micro`` with the pre-configured AMI id.

        Args:
            image_id: Takes image ID as an argument. Defaults to ``ami_id`` in environment variable. Exits if `null`.

        Returns:
            str or None:
            Instance ID.
        """
        if not image_id:
            self.logger.error('AMI is mandatory to spin up an EC2 instance. Received `null`')
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
                InstanceType="t2.micro",
                MaxCount=1,
                MinCount=1,
                ImageId=image_id,
                KeyName=self.key_name,
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
                KeyName=self.key_name
            )
        except ClientError as error:
            self.logger.error(f'API call to delete the key {self.key_name} has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'{self.key_name} has been deleted from KeyPairs.')
            if path.exists(f'{self.key_name}.pem'):
                system(f'chmod 700 {self.key_name}.pem')  # reset file permissions before deleting
                system(f'rm {self.key_name}.pem')
            return True
        else:
            self.logger.error(f'Failed to delete the key: {self.key_name}')

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
        """Tests whether the existing server is connectable.

        This is called when a startup request is made but ``server_info.json`` and ``OpenVPN.pem`` are present already.

        Args:
            data: Takes the instance information in a dictionary format as an argument.

        Returns:
            bool:
            - ``True`` if the existing connection is reachable and ``ssh`` to the origin succeeds.
            - ``False`` is the connection fails or unable to ``ssh`` to the origin.
        """
        self.logger.info(f"Testing GET connection to https://{data.get('public_ip')}:{self.port}")
        try:
            url_check = requests.get(url=f"https://{data.get('public_ip')}:{self.port}", verify=False)
        except requests.ConnectionError:
            return False
        self.logger.info(f"Testing SSH connection to {data.get('public_dns')}")
        if url_check.ok and interactive_ssh(hostname=data.get('public_dns'), username='openvpnas',
                                            pem_file=f'{self.key_name}.pem', logger=self.logger,
                                            display=True):
            return True

    def startup_vpn(self, reconfig: bool = False) -> None:
        """Calls the class methods ``_create_ec2_instance`` and ``_instance_info`` to configure the VPN server.

        See Also:
            - Checks if ``server_info.json`` and ``OpenVPN.pem`` files are present, before spinning up a new instance.
            - If present, checks the connection to the existing origin and tears down the instance if connection fails.
            - If connects, notifies user with details and adds key-value pair ``Retry: True`` to ``server_info.json``
            - If another request is sent to start the vpn, creates a new instance regardless of existing info.
            - There is a wait time (20 seconds) for the SSH origin to become active.
        """
        if path.isfile(self.server_file) and path.isfile(f'{self.key_name}.pem'):
            with open(self.server_file) as file:
                data = load(file)
            self.logger.warning(f"Found an existing VPN Server running at {data.get('SERVER')}")
            if reconfig:
                self._configure_vpn(data=data)
                return
            if self._tester(data=data):
                if data.get('RETRY'):
                    self.logger.warning('Received a second request to spin up a new VPN Server. Proceeding this time.')
                else:
                    data.update({'RETRY': True})
                    self._notify(login_details=f"CURRENTLY SERVING: {data.get('SERVER').lstrip('https://')}\n\n"
                                               f"Username: {data.get('USERNAME')}\n"
                                               f"Password: {data.get('PASSWORD')}")
                    with open(self.server_file, 'w') as file:
                        dump(data, file, indent=2)
                    return
            else:
                self.logger.error('Existing server is not responding. Creating a new one.')
                self.shutdown_vpn(partial=True)

        if reconfig:
            self.logger.error(f'Input file: {self.server_file} is missing. CANNOT proceed.')
            return

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

        with open(self.server_file, 'w') as file:
            dump(instance_info, file, indent=2)

        self.logger.info(f'Restricting wide open permissions to {self.key_name}.pem')
        system(f'chmod 400 {self.key_name}.pem')

        self.logger.info('Waiting for SSH origin to be active.')
        self._sleeper(sleep_time=20)

        vpn_username, vpn_password = self._configure_vpn(data=instance_info)

        if not self._tester(data=instance_info):
            self.logger.error('Something went wrong with configuration. Please check the logs for more information.')
            return

        self.logger.info('VPN server has been configured successfully.')
        url = f"https://{instance_info.get('public_ip')}"
        self.logger.info(f"Login Info:\nSERVER: {url}:{self.port}\n"
                         f"USERNAME: {vpn_username}\n"
                         f"PASSWORD: {vpn_password}")
        instance_info.update({'SERVER': f"{url}:{self.port}", 'USERNAME': vpn_username, 'PASSWORD': vpn_password})

        with open(self.server_file, 'w') as file:
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
            "Please specify the port number for the Admin Web UI.": str(self.port),
            "Please specify the TCP port number for the OpenVPN Daemon.": "443",
            "Should client traffic be routed by default through the VPN?": "yes",
            "Should client DNS traffic be routed by default through the VPN?": "no",
            "Use local authentication via internal DB?": "yes",
            "Should private subnets be accessible to clients by default?": "yes",
            "Do you wish to login to the Admin UI as 'openvpn'?": "no",
            "Specify the username for an existing user or for the new user account:": vpn_username,
            f"Type the password for the '{vpn_username}' account:": vpn_password,
            f"Confirm the password for the '{vpn_username}' account:": vpn_password,
            "Please specify your Activation key (or leave blank to specify later):": "\n"
        }

        interactive_ssh(hostname=data.get('public_dns'),
                        username='root',
                        pem_file=f'{self.key_name}.pem',
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

    def shutdown_vpn(self, partial: bool = False) -> None:
        """Disables VPN server by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created.

        Args:
            partial: Flag to indicate whether the ``SecurityGroup`` has to be removed.

        See Also:
            There is a wait time (60 seconds) for the instance to terminate. This may run twice.
        """
        if not path.exists(self.server_file):
            self.logger.error(f'Input file: {self.server_file} is missing. CANNOT proceed.')
            return

        with open(self.server_file, 'r') as file:
            data = load(file)

        if self._delete_key_pair() and self._terminate_ec2_instance(instance_id=data.get('instance_id')):
            if partial:
                system(f'rm {self.server_file}')
                return
            self.logger.info('Waiting for dependent objects to delete SecurityGroup.')
            while True:
                if self._delete_security_group(security_group_id=data.get('security_group_id')):
                    break
                else:
                    self._sleeper(sleep_time=60)
            system(f'rm {self.server_file}')


if __name__ == '__main__':
    run_env = Process(getpid()).parent().name()
    if run_env.endswith('sh'):
        if len(argv) < 2:
            exit("No arguments were passed. Use 'START', 'STOP' [OR] 'CONFIG' to enable or disable the VPN server.")
        if argv[1].upper() == 'START':
            try:
                VPNServer().startup_vpn()
            except KeyboardInterrupt:
                exit("Interrupted during start up!! If VPN wasn't fully configured, please stop and start once again.")
        elif argv[1].upper() == 'STOP':
            try:
                VPNServer().shutdown_vpn()
            except KeyboardInterrupt:
                exit("Interrupted during shut down!! If resources weren't fully cleaned up, please stop once again.")
        elif argv[1].upper() == 'CONFIG':
            try:
                VPNServer().startup_vpn(reconfig=True)
            except KeyboardInterrupt:
                exit("Interrupted during re-configuration!! Run config once again.")
        else:
            exit("The only acceptable arguments are 'START', 'STOP' [OR] 'CONFIG'")
    else:
        exit(f"You're running this script on {run_env}\n"
             "Please use a command line to trigger it, using either of the following arguments.\n"
             "\t1. python3 vpn.py START\n"
             "\t2. python3 vpn.py STOP\n"
             "\t3. python3 vpn.py CONFIG")
