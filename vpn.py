from json import dump, load
from logging import INFO, basicConfig, getLogger
from os import environ, getcwd, getpid, path, system
from platform import system as os_name
from sys import argv, stdout
from time import perf_counter, sleep

from boto3 import client, resource
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from psutil import Process

if path.isfile('.env'):
    load_dotenv(dotenv_path='.env', verbose=True, override=True)


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


class VPNServer:
    """Initiates ``VPNServer`` object to spin up an EC2 instance with a pre-configured AMI which serves as a VPN server.

    >>> VPNServer

    """

    def __init__(self, aws_access_key: str = None, aws_secret_key: str = None):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module.

        Args:
            aws_access_key: Access token for AWS account.
            aws_secret_key: Secret ID for AWS account.

        See Also:
            - If no values (for aws authentication) are passed during object initialization, script checks for env vars.
            - If the environment variables are ``null``, gets the default credentials from ``~/.aws/credentials``.
        """
        # Hard-coded certificate file name, server information file name, security group name
        self.key_name = 'OpenVPN'
        self.server_file = 'server_info.json'
        self.security_group_name = 'OpenVPN Access Server'

        # Logger setup
        basicConfig(
            format='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
            datefmt='%b-%d-%Y %I:%M:%S %p', level=INFO
        )
        self.logger = getLogger(self.key_name)

        # AWS client and resource setup
        if (access_key := environ.get('access_key', aws_access_key)) and \
                (secret_key := environ.get('secret_key', aws_secret_key)):
            self.ec2_client = client(service_name='ec2', region_name='us-west-2',
                                     aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            self.ec2_resource = resource(service_name='ec2', region_name='us-west-2',
                                         aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        else:
            self.ec2_client = client(service_name='ec2', region_name='us-west-2')
            self.ec2_resource = resource(service_name='ec2', region_name='us-west-2')

    def __del__(self):
        """Destructor to print the run time at the end."""
        self.logger.info(f'Total runtime: {time_converter(perf_counter())}')

    def _create_key_pair(self) -> bool:
        """Creates a ``KeyPair`` of type ``RSA`` stored as a ``PEM`` file to use with ``OpenSSH``.

        Returns:
            bool:
            Flag to indicate the calling function if or not a ``KeyPair`` was created.
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
            self.logger.info(f'Successfully created a key pair named: {self.key_name}')
            with open(f'{self.key_name}.pem', 'w') as file:
                file.write(response.get('KeyMaterial'))
            self.logger.info(f'Stored the certificate as {self.key_name}.pem')
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
            Flag to indicate the calling function if or not the security group was authorized.
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
                     'FromPort': 943,
                     'ToPort': 943,
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

    def _create_ec2_instance(self, image_id: str = environ.get('ami_id')) -> str or None:
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
            self._delete_security_group()
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
            self._delete_security_group()
            self.logger.error(f'API call to create instance has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            instance_id = response.get('Instances')[0].get('InstanceId')
            self.logger.info(f'Created the EC2 instance: {instance_id}')
            return instance_id, security_group_id
        else:
            self._delete_key_pair()
            self._delete_security_group()
            self.logger.error('Failed to create an EC2 instance.')

    def _retrieve_server_info(self) -> dict:
        """Retrieves the stored ``json`` file and returns the data as a ``dictionary``.

        Returns:
            dict:
            Dictionary version of the json object that was stored during after instance creation.
        """
        with open(self.server_file, 'r') as file:
            data = load(file)
        return data

    def _delete_key_pair(self, key_name: str = None) -> bool:
        """Deletes the ``KeyPair``.

        Args:
            key_name: Takes ``KeyPair`` name as argument. Defaults to the one mentioned when the object was initialized.

        Returns:
            bool:
            Flag to indicate the calling function if or not the KeyPair was deleted.
        """
        if not key_name:
            key_name = self.key_name
            self.logger.warning(f'No `key_name` was passed. Trying to delete the default Key: {key_name}.pem')

        try:
            response = self.ec2_client.delete_key_pair(
                KeyName=key_name
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

    def _delete_security_group(self, security_group_id: str = None) -> bool:
        """Deletes the security group.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        Returns:
            bool:
            Flag to indicate the calling function if or not the SecurityGroup was deleted.
        """
        if not security_group_id:
            if not path.exists(self.server_file):
                self.logger.error('Cannot delete a security group without the SecurityGroup ID')
                return False

            data = self._retrieve_server_info()
            security_group_id = data.get('security_group_id')
            self.logger.warning(f"Security Group ID wasn't provided. Recent SG, {security_group_id} will be deleted.")

        try:
            response = self.ec2_client.delete_security_group(
                GroupId=security_group_id
            )
        except ClientError as error:
            self.logger.error(f'API call to delete the Security Group {security_group_id} has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'{security_group_id} has been deleted from Security Groups.')
            return True
        else:
            self.logger.error(f'Failed to delete the SecurityGroup: {security_group_id}')

    def _terminate_ec2_instance(self, instance_id: str = None) -> bool:
        """Terminates the requested instance.

        Args:
            instance_id: Takes instance ID as an argument. Defaults to the instance that was created previously.

        Returns:
            bool:
            Flag to indicate the calling function if or not the instance was terminated.
        """
        if not instance_id:
            if not path.exists(self.server_file):
                self.logger.error('Cannot terminate an instance without the Instance ID')
                return False

            data = self._retrieve_server_info()
            instance_id = data.get('instance_id')
            self.logger.warning(f"Instance ID wasn't provided. Recent instance, {instance_id} will be terminated.")

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
        while True:
            try:
                response = self.ec2_client.describe_instance_status(
                    InstanceIds=[instance_id]
                )
            except ClientError as error:
                self.logger.error(f'API call to describe instance has failed.{error}')
                return

            if response.get('ResponseMetadata').get('HTTPStatusCode') != 200:
                sleep(3)
                continue
            if status := response.get('InstanceStatuses'):
                if status[0].get('InstanceState').get('Name') == 'running':
                    instance_info = self.ec2_resource.Instance(instance_id)
                    return instance_info.public_dns_name, instance_info.public_ip_address
                else:
                    sleep(3)
            else:
                sleep(3)

    def _configure_vpn(self, dns_name: str) -> None:
        """Configure the VPN server automatically by running a couple of SSH commands and finally a password reset.

        Args:
            dns_name: Takes the public ``DNSName`` as an argument to form the ``ssh`` command to initiate configuration.

        See Also:
            - Takes ~2 minutes as there is a wait time for each ``stdin`` in the interactive SSH command.

        Notes: # noqa: E501
            .. code-block:: applescript

                tell application "Terminal"
                    delay 5
                    set currentTab to do script ("cd {getcwd()}")
                    delay 2
                    do script ("{initial_config}") in currentTab
                    delay 10
                    do script ("yes") in currentTab  # knownhosts. Are you sure you want to continue connecting (yes/no)?
                    delay 15
                    do script ("yes") in currentTab  # Please enter 'yes' to indicate your agreement [no]:
                    delay 1
                    do script ("") in currentTab  # Will this be the primary Access Server node? Default: yes
                    delay 1
                    do script ("") in currentTab  # Please specify the network interface and IP address to be used by the Admin Web UI: Default: all interfaces: 0.0.0.0
                    delay 1
                    do script ("") in currentTab  # Please specify the port number for the Admin Web UI. Default: 943
                    delay 1
                    do script ("") in currentTab  # Please specify the TCP port number for the OpenVPN Daemon. Default: 443
                    delay 1
                    do script ("yes") in currentTab  # Should client traffic be routed by default through the VPN? Default: No
                    delay 1
                    do script ("") in currentTab  # Should client DNS traffic be routed by default through the VPN? Default: No
                    # If VPN clients should be able to resolve local domain names using an on-site DNS server, then the answer should be "yes". If the previous selection was "yes", all traffic will be routed over the VPN regardless what is set here.
                    delay 1
                    do script ("") in currentTab  # Use local authentication via internal DB? Default: yes
                    delay 1
                    do script ("") in currentTab  # Should private subnets be accessible to clients by default? Default: yes
                    delay 1
                    do script ("") in currentTab  # Do you wish to login to the Admin UI as "openvpn"? Default: yes
                    delay 1
                    do script ("") in currentTab  # Please specify your Activation key (or leave blank to specify later):
                    delay 40
                    do script ("{final_config}") in currentTab
                    delay 20
                    do script ("sudo passwd openvpn") in currentTab
                    delay 3
                    do script ("{vpn_password}") in currentTab
                    delay 2
                    do script ("{vpn_password}") in currentTab
                    delay 2
                end tell

        References:
            - `Configuration in UI <https://openvpn.net/access-server-manual/configuration-vpn-settings/>`__
            - `Configuration in SSH session <https://www.vembu.com/blog/open-vpn-server-aws-overview/#:~:text=Now%20its%20time%20to%20configure%20your%20OpenVPN%20Access%20Server%20Instance>`__
        """
        self.logger.info('Configuring VPN server.')
        initial_config = f'ssh -i {self.key_name}.pem root@{dns_name}'
        final_config = initial_config.replace('root@', 'openvpnas@')
        vpn_password = environ.get('vpn_password', 'awsVPN2021')
        script = f"""osascript -e '
tell application "Terminal"
    delay 5
    set currentTab to do script ("cd {getcwd()}")
    delay 2
    do script ("{initial_config}") in currentTab
    delay 10
    do script ("yes") in currentTab
    delay 15
    do script ("yes") in currentTab
    delay 1
    do script ("") in currentTab
    delay 1
    do script ("") in currentTab
    delay 1
    do script ("") in currentTab
    delay 1
    do script ("") in currentTab
    delay 1
    do script ("yes") in currentTab
    delay 1
    do script ("") in currentTab
    delay 1
    do script ("") in currentTab
    delay 1
    do script ("") in currentTab
    delay 1
    do script ("") in currentTab
    delay 1
    do script ("") in currentTab
    delay 40
    do script ("{final_config}") in currentTab
    delay 20
    do script ("sudo passwd openvpn") in currentTab
    delay 3
    do script ("{vpn_password}") in currentTab
    delay 2
    do script ("{vpn_password}") in currentTab
    delay 2
end tell
'
"""
        script_status = system(script) if os_name() == 'Darwin' else 256
        data = self._retrieve_server_info()
        url = f"https://{data.get('public_ip')}"
        if script_status == 256:
            write_login_details = False
            if os_name() != 'Darwin':
                self.logger.critical('Unsupported Operating System.')
                self.logger.critical(f'Auto config is currently supported only on MacOS. Script was run on {os_name()}')
            self.logger.error('Failed to configure VPN server automatically. '
                              'Run the below commands following the instructions in README.')
            self.logger.error(initial_config)
            self.logger.error(final_config)
            self.logger.error('sudo passwd openvpn')
            self.logger.info('Step1: Now login to the server with the information above and accept the agreement.')
            self.logger.info('Step2: Navigate to `CONFIGURATION` -> `VPN Settings` and Scroll Down to `Routing`.')
            self.logger.info('Step3: Slide `Should client Internet traffic be routed through the VPN?` switch to `Yes`')
            self.logger.info('Step4: Click `Save Settings` (bottom of page) and `Update Running Server` (top of page)')
        else:
            write_login_details = True
            self.logger.info('VPN server has been configured successfully.')
            self.logger.info(f"Login Info:\nSERVER: {url}:943/admin/\n"
                             "USERNAME: openvpn\n"
                             f"PASSWORD: {vpn_password}\n")
        data.update({'initial_config': initial_config, 'final_config': final_config, 'SERVER': f"{url}:943/admin/"})
        if write_login_details:
            data.update({'USERNAME': 'openvpn', 'PASSWORD': vpn_password})
        with open(self.server_file, 'w') as file:
            dump(data, file, indent=2)

    def startup_vpn(self) -> None:
        """Calls the class methods ``_create_ec2_instance`` and ``_instance_info`` to configure the VPN server.

        See Also:
            There is a wait time (30 seconds) for the SSH origin to become active.
        """
        if instance_basic := self._create_ec2_instance():
            instance_id, security_group_id = instance_basic
        else:
            return

        if instance := self._instance_info(instance_id=instance_id):
            public_dns, public_ip = instance
        else:
            return

        instance_info = {
            'instance_id': instance_id,
            'public_dns': public_dns,
            'public_ip': public_ip,
            'security_group_id': security_group_id
        }
        with open(self.server_file, 'w') as file:
            dump(instance_info, file, indent=2)

        self.logger.info(f'Restricting wide open permissions to {self.key_name}.pem')
        system(f'chmod 400 {self.key_name}.pem')

        sleep(1)
        for i in range(30):
            stdout.write(f'\rWaiting for SSH origin to be active. Remaining: {30 - i:02}s')
            sleep(1)
        stdout.write('\r')

        self._configure_vpn(dns_name=public_dns)

    def shutdown_vpn(self) -> None:
        """Disables VPN server by terminating the ``EC2`` instance, ``KeyPair``, and the ``SecurityGroup`` created.

        See Also:
            There is a wait time (30 seconds) for the instance to terminate. This may run twice.
        """
        if self._delete_key_pair() and self._terminate_ec2_instance():
            while True:
                sleep(1)
                for i in range(30):
                    stdout.write(f'\rWaiting for dependent objects to delete SecurityGroup. Remaining: {30 - i:02}s')
                    sleep(1)
                stdout.write('\r')
                if self._delete_security_group():
                    break
            if path.exists(self.server_file):
                system(f'rm {self.server_file}')


if __name__ == '__main__':
    run_env = Process(getpid()).parent().name()
    if run_env.endswith('sh'):
        if len(argv) < 2:
            exit("No arguments were passed. Use 'START' [OR] 'STOP' to enable or disable the VPN server.")
        if argv[1].upper() == 'START':
            VPNServer().startup_vpn()
        elif argv[1].upper() == 'STOP':
            VPNServer().shutdown_vpn()
        else:
            exit("The only acceptable arguments are 'START' [OR] 'STOP'")
    else:
        exit(f"You're running this script on {run_env}\n"
             f"Please use a command line to trigger it, using either of the following arguments.\n"
             f"\t1. python3 vpn.py START\n"
             f"\t2. python3 vpn.py STOP")
