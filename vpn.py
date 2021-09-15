from json import dump, load
from logging import INFO, basicConfig, getLogger
from os import environ, path, system
from time import sleep

from boto3 import client, resource
from botocore.exceptions import ClientError


class VPNServer:
    """Initiates VPNServer object to spin up an EC2 instance with a pre-configured AMI which serves as a VPN server.

    >>> VPNServer

    """

    def __init__(self):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module."""
        self.key_name = 'OpenVPN'
        self.instance_file = 'instance_info.json'
        basicConfig(
            format='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
            datefmt='%b-%d-%Y %I:%M:%S %p', level=INFO
        )
        self.logger = getLogger(self.key_name)
        self.ec2_client = client(service_name='ec2', region_name='us-west-2')
        self.ec2_resource = resource(service_name='ec2', region_name='us-west-2')

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

    def create_ec2_instance(self, image_id: str = environ.get('ami_id')) -> str or None:
        """Creates an EC2 instance of type ``t2.micro`` with the pre-configured AMI id.

        Returns:
            str or None:
            Instance ID.
        """
        if not self._create_key_pair():
            return

        if not image_id:
            self.logger.error('AMI is mandatory to spin up an EC2 instance. Received `null`')
            return

        try:
            response = self.ec2_client.run_instances(
                InstanceType="t2.micro",
                MaxCount=1,
                MinCount=1,
                ImageId=image_id,
                KeyName=self.key_name
            )
        except ClientError as error:
            self.logger.error(f'API call to create instance has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            instance_id = response.get('Instances')[0].get('InstanceId')
            self.logger.info(f'Created the EC2 instance: {instance_id}')
            return instance_id
        else:
            self.logger.error('Failed to create an EC2 instance.')

    def _delete_key_pair(self, key_name: str = None) -> bool:
        """Deletes the ``KeyPair``.

        Args:
            key_name: Takes ``KeyPair`` name as argument. Defaults to the one mentioned when the object was initialized.

        Returns:
            bool:
            Flag to indicate the calling function if or not the ``KeyPair`` was deleted.
        """
        try:
            response = self.ec2_client.delete_key_pair(
                KeyName=key_name or self.key_name
            )
        except ClientError as error:
            self.logger.error(f'API call to delete the key {self.key_name} has failed.\n{error}')
            return False

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'{self.key_name} has been deleted from KeyPairs.')
            return True
        else:
            self.logger.error(f'Failed to delete the key: {self.key_name}')

    def terminate_ec2_instance(self, instance_id: str = None) -> None:
        """Terminates the requested instance.

        Args:
            instance_id: Takes instance ID as an argument. Defaults to the instance that was created previously.
        """
        if not instance_id:
            if not path.exists(self.instance_file):
                self.logger.error('Cannot terminate an instance without the Instance ID')
                return

            with open(self.instance_file, 'r') as file:
                data = load(file)
            instance_id = data.get('instance_id')
            self.logger.warning(f"Instance ID wasn't provided. Recent instance, {instance_id} will be terminated.")

        if not self._delete_key_pair():
            return

        try:
            response = self.ec2_client.terminate_instances(
                InstanceIds=[instance_id]
            )
        except ClientError as error:
            self.logger.error(f'API call to terminate the instance has failed.\n{error}')
            return

        if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
            self.logger.info(f'InstanceId {instance_id} has been set to terminate.')
            if path.exists(f'{self.key_name}.pem'):
                system(f'rm {self.key_name}.pem')
            if path.exists('instance_id'):
                system('rm instance_id')
            if path.exists(self.instance_file):
                system(f'rm {self.instance_file}')
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

    def configure_openvpn(self) -> None:
        """Calls the functions ``create_ec2_instance`` and ``_instance_info`` and then configures the VPN server."""
        if (instance_id := self.create_ec2_instance()) and (instance := self._instance_info(instance_id=instance_id)):
            public_dns, public_ip = instance

            instance_info = {
                'instance_id': instance_id,
                'public_dns': public_dns,
                'public_ip': public_ip
            }
            with open(self.instance_file, 'w') as file:
                dump(instance_info, file, indent=2)

            # print(f"ssh-keyscan {public_ip}")

            self.logger.info(f'Restricting wide open permissions to {self.key_name}.pem')
            system(f'chmod 400 {self.key_name}.pem')

            config_command = f'ssh -i {self.key_name}.pem root@{public_dns}'
            print(config_command)  # base command to configure OpenVPN
            print(config_command.replace('root@', 'openvpnas@'))  # setup OpenVPN using the user id


if __name__ == '__main__':
    vpn = VPNServer()
    vpn.configure_openvpn()
