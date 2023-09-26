import json
import os
import time
import warnings
from typing import Dict, Tuple, Union

import boto3
import inflect
import requests
import urllib3
from boto3.resources.base import ServiceResource
from botocore.exceptions import ClientError, WaiterError
from urllib3.exceptions import InsecureRequestWarning

from vpn.models.config import EnvConfig, Settings, configuration_dict
from vpn.models.exceptions import NotImplementedWarning
from vpn.models.image_factory import ImageFactory
from vpn.models.logger import LOGGER
from vpn.models.route53 import change_record_set, get_zone_id
from vpn.models.server import Server


class VPNServer:
    """Initiates ``VPNServer`` object to spin up an EC2 instance with a pre-configured AMI which serves as a VPN server.

    >>> VPNServer

    """

    def __init__(self, **kwargs):
        """Assigns a name to the PEM file, initiates the logger, client and resource for EC2 using ``boto3`` module.

        Args:
            logger: Bring your own logger.
        """
        self.env = EnvConfig(**kwargs)
        self.settings = Settings()
        self.settings.key_pair_file = f"{self.env.key_pair}.pem"
        if any((self.env.hosted_zone, self.env.subdomain)):
            assert all((self.env.hosted_zone, self.env.subdomain)), "'subdomain' and 'hosted_zone' must co-exist"
            self.settings.entrypoint = f'{self.env.subdomain}.{self.env.hosted_zone}'
        self.settings.openvpn_config_commands = configuration_dict(self.env)

        self.logger = kwargs.get('logger') or LOGGER
        self.session = boto3.Session(region_name=self.env.aws_region_name,
                                     profile_name=self.env.aws_profile_name,
                                     aws_access_key_id=self.env.aws_access_key,
                                     aws_secret_access_key=self.env.aws_secret_key)
        self.logger.info("Session instantiated for region: '%s' with '%s' instance",
                         self.session.region_name, self.env.instance_type)
        self.ec2_resource = self.session.resource(service_name='ec2')
        self.route53_client = self.session.client(service_name='route53')

        self.image_id = None
        self.zone_id = None

    def _init(self,
              start: Union[bool, int]) -> None:
        """Initializer function.

        Args:
            start: Boolean flag to indicate if its startup or shutdown.
        """
        if start:  # Not required during shutdown, since image_id is only used to create an ec2 instance
            variable = "created in"  # var for logging if entrypoint is present
            if self.env.image_id:
                self.image_id = self.env.image_id
            else:
                self.image_id = ImageFactory(self.session, self.logger).get_image_id()
        else:
            variable = "removed from"  # var for logging if entrypoint is present
        if self.env.hosted_zone:
            self.zone_id = get_zone_id(client=self.route53_client,
                                       logger=self.logger,
                                       dns=self.env.hosted_zone,
                                       init=True)
        if self.settings.entrypoint:
            self.logger.info("Entrypoint: '%s' will be %s the hosted zone [%s] '%s'",
                             self.settings.entrypoint, variable, self.zone_id, self.env.hosted_zone)

    def _create_key_pair(self) -> bool:
        """Creates a ``KeyPair`` of type ``RSA`` stored as a ``PEM`` file to use with ``OpenSSH``.

        Returns:
            bool:
            Boolean flag to indicate the calling function if a ``KeyPair`` was created.
        """
        try:
            key_pair = self.ec2_resource.create_key_pair(
                KeyName=self.env.key_pair,
                KeyType='rsa'
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidKeyPair.Duplicate)' in error:
                self.logger.warning('Found an existing KeyPair named: %s. Re-creating it.',
                                    self.env.key_pair)
                self._delete_key_pair()
                return self._create_key_pair()
            self.logger.warning('API call to create key pair has failed.')
            self.logger.error(error)
            return False

        with open(self.settings.key_pair_file, 'w') as file:
            file.write(key_pair.key_material)
            file.flush()
        self.logger.info('Stored KeyPair as %s', self.settings.key_pair_file)
        return True

    def _get_vpc_id(self) -> Union[str, None]:
        """Fetches the default VPC id.

        Returns:
            Union[str, None]:
            Default VPC id.
        """
        try:
            vpcs = list(self.ec2_resource.vpcs.all())
        except ClientError as error:
            self.logger.warning('API call to get VPC ID has failed.')
            self.logger.error(error)
            return
        default_vpc = None
        for vpc in vpcs:
            if vpc.is_default:
                default_vpc = vpc
                break
        if default_vpc:
            self.logger.info('Got the default VPC: %s', default_vpc.id)
            return default_vpc.id
        else:
            self.logger.error('Unable to get the default VPC ID')

    def _authorize_security_group(self,
                                  security_group_id: str) -> bool:
        """Authorizes the security group for certain ingress list.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        See Also:
            `Firewall configuration ports to be open: <https://tinyurl.com/ycxam2sr>`__

            - TCP 22 — SSH access.
            - TCP 443 — Web interface access and OpenVPN TCP connections.
            - TCP 943 — Web interface access (can be dynamic)
            - TCP 945 — Cluster control channel.
            - UDP 1194 — OpenVPN UDP connections.

        Returns:
            bool:
            Flag to indicate the calling function whether the security group was authorized.
        """
        try:
            security_group = self.ec2_resource.SecurityGroup(security_group_id)
            security_group.authorize_ingress(
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 22,
                     'ToPort': 22,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # todo: restrict to current IP and instance IP address
                    {'IpProtocol': 'tcp',
                     'FromPort': 443,
                     'ToPort': 443,
                     'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': self.env.vpn_port,
                     'ToPort': self.env.vpn_port,
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
                self.logger.warning('Identified same permissions in an existing SecurityGroup: %s',
                                    security_group_id)
                return True
            self.logger.error('API call to authorize the security group %s has failed.', security_group_id)
            self.logger.error(error)
            return False
        for sg_rule in security_group.ip_permissions:
            log = 'Allowed protocol: ' + sg_rule['IpProtocol'] + ' '
            if sg_rule['FromPort'] == sg_rule['ToPort']:
                log += 'on port: ' + str(sg_rule['ToPort']) + ' '
            else:
                log += 'from port: ' f"{sg_rule['FromPort']} to port: {sg_rule['ToPort']}" + ' '
            for ip_range in sg_rule['IpRanges']:
                self.logger.info(log + 'with CIDR ' + ip_range['CidrIp'])
        return True

    def _create_security_group(self) -> Union[str, None]:
        """Gets VPC id and creates a security group for the ec2 instance.

        Warnings:
            Deletes and re-creates the SG, in case an SG exists with the same name already.

        Returns:
            Union[str, None]:
            SecurityGroup ID
        """
        if not (vpc_id := self._get_vpc_id()):
            return

        try:
            security_group = self.ec2_resource.create_security_group(
                GroupName=self.env.security_group,
                Description='Security Group to allow certain port ranges for exposing localhost to public internet.',
                VpcId=vpc_id
            )
        except ClientError as error:
            error = str(error)
            if '(InvalidGroup.Duplicate)' in error and self.env.security_group in error:
                security_groups = list(self.ec2_resource.security_groups.all())
                for security_group in security_groups:
                    if security_group.group_name == self.env.security_group:
                        self.logger.info("Re-using existing SecurityGroup '%s'", security_group.group_id)
                        return security_group.group_id
                raise RuntimeError('Duplicate raised, but no such SG found.')
            self.logger.warning('API call to create security group has failed.')
            self.logger.error(error)
            return

        security_group_id = security_group.id
        self.logger.info('Security Group created %s in VPC %s', security_group_id, vpc_id)
        return security_group_id

    def _create_ec2_instance(self) -> Union[Tuple[str, str], None]:
        """Creates an EC2 instance with a pre-configured AMI id.

        Returns:
            Union[Tuple[str, str], None]:
            Instance ID, SecurityGroup ID if successful.
        """
        if not (security_group_id := self._create_security_group()):
            self._delete_key_pair()
            return
        if not self._create_key_pair():
            return
        try:
            # Use the EC2 resource to launch an EC2 instance
            instances = self.ec2_resource.create_instances(
                ImageId=self.image_id,
                MinCount=1,
                MaxCount=1,
                InstanceType=self.env.instance_type,
                KeyName=self.env.key_pair,
                SecurityGroupIds=[security_group_id]
            )
            instance = instances[0]  # Get the first (and only) instance
        except ClientError as error:
            self._delete_key_pair()
            self._delete_security_group(security_group_id=security_group_id)
            self.logger.warning('API call to create instance has failed.')
            self.logger.error(error)
            return None

        instance_id = instance.id
        self.logger.info('Created the EC2 instance: %s', instance_id)
        return instance_id, security_group_id

    def _delete_key_pair(self) -> bool:
        """Deletes the ``KeyPair`` created to access the ec2 instance.

        Returns:
            bool:
            Boolean flag to indicate the calling function if the KeyPair was deleted successfully.
        """
        try:
            key_pair = self.ec2_resource.KeyPair(self.env.key_pair)
            key_pair.delete()
        except ClientError as error:
            self.logger.warning("API call to delete the key '%s' has failed.", self.env.key_pair)
            self.logger.error(error)
            return False

        self.logger.info('%s has been deleted from KeyPairs.', self.env.key_pair)

        # Delete the associated .pem file if it exists
        if os.path.exists(self.settings.key_pair_file):
            os.chmod(self.settings.key_pair_file, int('700', base=8) or 0o700)
            os.remove(self.settings.key_pair_file)
            self.logger.info(f'Removed {self.settings.key_pair_file}.')
            return True

    def _disassociate_security_group(self,
                                     security_group_id: str,
                                     instance: object = None,
                                     instance_id: str = None) -> bool:
        """Disassociates an SG from the ec2 instance by assigning it to the default security group.

        Args:
            security_group_id: Security group ID
            instance: Instance object.
            instance_id: Instance ID if object is unavailable.

        Returns:
            bool:
            Boolean flag to indicate the calling function whether the disassociation was successful.
        """
        try:
            if not instance:
                instance = self.ec2_resource.Instance(instance_id)
            if security_groups := list(self.ec2_resource.security_groups.filter(GroupNames=['default'])):
                default_sg = security_groups[0]
                instance.modify_attribute(Groups=[default_sg.id])
                instance.modify_attribute(Groups=[group_id['GroupId'] for group_id in instance.security_groups
                                                  if group_id['GroupId'] != security_group_id])
                self.logger.info("Security group %s has been disassociated from instance %s.",
                                 security_group_id, instance.id)
                return True
            else:
                self.logger.info("Unable to get default SG to replace association")
        except ClientError as error:
            self.logger.info(error)

    def _delete_security_group(self, security_group_id: str) -> bool:
        """Deletes the security group.

        Args:
            security_group_id: Takes the SecurityGroup ID as an argument.

        Returns:
            bool:
            Boolean flag to indicate the calling function whether the SecurityGroup was deleted.
        """
        try:
            security_group = self.ec2_resource.SecurityGroup(security_group_id)
            security_group.delete()
        except ClientError as error:
            self.logger.warning('API call to delete the Security Group %s has failed.', security_group_id)
            self.logger.error(error)
            if '(InvalidGroup.NotFound)' in str(error):
                return True
            return False
        self.logger.info('%s has been deleted from Security Groups.', security_group_id)
        return True

    def _terminate_ec2_instance(self,
                                instance_id: str = None,
                                instance: object = None) -> ServiceResource or None:
        """Terminates the requested instance.

        Args:
            instance_id: Takes instance ID as an argument.
            instance: Takes the instance object as an optional argument.

        Returns:
            bool:
            Boolean flag to indicate the calling function whether the instance was terminated.
        """
        try:
            if not instance:
                instance = self.ec2_resource.Instance(instance_id)
            if not instance_id:
                instance_id = instance.id
            instance.terminate()
        except ClientError as error:
            self.logger.warning('API call to terminate the instance has failed.')
            self.logger.error(error)
            return
        self.logger.info('InstanceId %s has been set to terminate.', instance_id)
        return instance

    def _tester(self,
                data: Dict[str, Union[str, int]],
                timeout: int = 3) -> bool:
        """Tests ``GET`` and ``SSH`` connections on the existing server.

        Args:
            data: Takes the instance information in a dictionary format as an argument.
            timeout: Timeout to make the test call.

        See Also:
            - Called when a startup request is made but info file and pem file are present already.
            - Called when a manual test request is made.
            - Testing SSH connection will also run updates on the VM.

        Returns:
            bool:
            - ``True`` if the existing connection is reachable and ``ssh`` to the origin succeeds.
            - ``False`` if the connection fails or unable to ``ssh`` to the origin.
        """
        urllib3.disable_warnings(InsecureRequestWarning)  # Disable warnings for self-signed certificates
        self.logger.info(f"Testing GET connection to https://{data.get('public_ip')}:{self.env.vpn_port}")
        try:
            url_check = requests.get(url=f"https://{data.get('public_ip')}:{self.env.vpn_port}",
                                     verify=False, timeout=timeout)
            self.logger.debug(url_check)
        except requests.RequestException as error:
            self.logger.error(error)
            self.logger.error('Unable to connect the VPN server.')
            return False

        self.logger.info(f"Testing SSH connection to {data.get('public_dns')}")
        test_ssh = Server(username=self.env.vpn_username, hostname=data.get('public_dns'), logger=self.logger,
                          env=self.env, settings=self.settings)
        if url_check.ok and test_ssh.test_service(display=False, timeout=5):
            self.logger.info(f"Connection to https://{data.get('public_ip')}:{self.env.vpn_port} and "
                             f"SSH to {data.get('public_dns')} was successful.")
            return True
        else:
            self.logger.error('Unable to establish SSH connection with the VPN server. '
                              'Please check the logs for more information.')
            return False

    def test_vpn(self) -> None:
        """Tests the ``GET`` and ``SSH`` connections to an existing VPN server."""
        if os.path.isfile(self.env.vpn_info) and os.path.isfile(self.settings.key_pair_file):
            with open(self.env.vpn_info) as file:
                data_exist = json.load(file)
            self._tester(data=data_exist)
        else:
            self.logger.error(f'Input file: {self.env.vpn_info} is missing. CANNOT proceed.')

    def create_vpn_server(self) -> None:
        """Calls the class methods ``_create_ec2_instance`` and ``_instance_info`` to configure the VPN server.

        See Also:
            - Checks if info and pem files are present, before spinning up a new instance.
            - If present, checks the connection to the existing origin and tears down the instance if connection fails.
            - If connects, notifies user with details and adds key-value pair ``Retry: True`` to info file.
            - If another request is sent to start the vpn, creates a new instance regardless of existing info.
        """
        if os.path.isfile(self.env.vpn_info) and os.path.isfile(self.settings.key_pair_file):
            self.logger.warning('Received request to start VM, but looks like a session is up and running already.')
            self.logger.warning('Initiating re-configuration.')
            with open(self.env.vpn_info) as file:
                data = json.load(file)
            self.env.image_id = 'ami-0000000000'  # placeholder value since this won't be used in re-configuration
            self._init(True)
            if not self._tester(data):
                self._configure_vpn(data['public_dns'])
            return
        self._init(True)
        if ec2_info := self._create_ec2_instance():
            instance_id, security_group_id = ec2_info
        else:
            return

        instance = self.ec2_resource.Instance(instance_id)
        self.logger.info("Waiting for instance to enter 'running' state")
        try:
            instance.wait_until_running(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )
        except WaiterError as error:
            self.logger.error(error)
            warnings.warn(
                "Failed on waiting for instance to enter 'running' state, please raise an issue at:\n"
                "https://github.com/thevickypedia/vpn-server/issues",
                NotImplementedWarning
            )
            self._delete_key_pair()
            # No need to wait for SG disassociation since this is a handler for a WaiterError already
            self._disassociate_security_group(instance=instance, security_group_id=security_group_id)
            self._terminate_ec2_instance(instance=instance)
            self._delete_security_group(security_group_id)
            return
        instance.reload()
        self.logger.info("Finished re-loading instance '%s'", instance_id)

        if not self._authorize_security_group(security_group_id):
            self._delete_key_pair()
            sg_association = self._disassociate_security_group(instance=instance, security_group_id=security_group_id)
            self._terminate_ec2_instance(instance=instance)
            if not sg_association:
                try:
                    instance.wait_until_terminated(
                        Filters=[{"Name": "instance-state-name", "Values": ["terminated"]}]
                    )
                except WaiterError as error:
                    self.logger.error(error)
                    warnings.warn(
                        "Failed on waiting for instance to enter 'running' state, please raise an issue at:\n"
                        "https://github.com/thevickypedia/vpn-server/issues",
                        NotImplementedWarning
                    )
            self._delete_security_group(security_group_id)
            return

        instance_info = {
            'port': self.env.vpn_port,
            'instance_id': instance_id,
            'public_dns': instance.public_dns_name,
            'public_ip': instance.public_ip_address,
            'security_group_id': security_group_id,
            'ssh_endpoint': f'ssh -i {self.settings.key_pair_file} openvpnas@{instance.public_dns_name}'
        }

        os.chmod(self.settings.key_pair_file, int('400', base=8) or 0o400)

        with open(self.env.vpn_info, 'w') as file:
            json.dump(instance_info, file, indent=2)
            file.flush()

        self._configure_vpn(instance.public_dns_name)
        if self.settings.entrypoint:
            change_record_set(source=self.settings.entrypoint,
                              destination=instance.public_ip_address,
                              logger=self.logger,
                              client=self.route53_client,
                              zone_id=self.zone_id, action='UPSERT')
            instance_info['entrypoint'] = self.settings.entrypoint
            with open(self.env.vpn_info, 'w') as file:
                json.dump(instance_info, file, indent=2)
                file.flush()

        if not self._tester(data=instance_info):
            self.logger.error('Failed to configure VPN server. Please check the logs for more information.')
            return

        self.logger.info('VPN server has been configured successfully. Details have been stored in %s.',
                         self.env.vpn_info)

    def _configure_vpn(self, public_dns: str) -> None:
        """Configures the ec2 instance to take traffic from localhost and initiates tunneling.

        Args:
            public_dns: Public DNS name of the ec2 that was created.
        """
        self.logger.info('Connecting to server via SSH')

        # Max of 10 iterations with 5 second interval between each iteration with default timeout
        for i in range(10):
            try:
                server = Server(hostname=public_dns, username='openvpnas', logger=self.logger,
                                env=self.env, settings=self.settings)
                self.logger.info("Connection established on %s attempt", inflect.engine().ordinal(i + 1))
                break
            except Exception as error:
                self.logger.error(error)
                time.sleep(5)
        else:
            self.delete_vpn_server()
            raise TimeoutError(
                "Unable to connect SSH server, please call the 'start' function once again if instance looks healthy"
            )
        server.run_interactive_ssh()

    def delete_vpn_server(self,
                          instance_id: str = None,
                          security_group_id: str = None,
                          public_ip: str = None) -> None:
        """Disables tunnelling by removing all AWS resources acquired.

        Args:
            instance_id: Instance that has to be terminated.
            security_group_id: Security group that has to be removed.
            public_ip: Public IP address to delete the A record from route53.

        See Also:
            Doesn't require any argument, as long as the JSON dump is neither removed nor modified by hand.

        References:
            - | https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/instance/
              | wait_until_terminated.html
        """
        try:
            with open(self.env.vpn_info) as file:
                data = json.load(file)
        except FileNotFoundError:
            assert instance_id and security_group_id, \
                (f"\n\nInput file: {self.env.vpn_info!r} is missing. "
                 "Arguments 'instance_id' and 'security_group_id' are required to proceed.")
            data = {}
        self._init(False)
        security_group_id = security_group_id or data.get('security_group_id')
        instance_id = instance_id or data.get('instance_id')
        public_ip = public_ip or data.get('public_ip')

        self._delete_key_pair()
        sg_association = self._disassociate_security_group(instance_id=instance_id, security_group_id=security_group_id)
        instance = self._terminate_ec2_instance(instance_id=instance_id)
        if self.env.hosted_zone and self.env.subdomain and public_ip:
            change_record_set(source=self.settings.entrypoint, destination=public_ip,
                              logger=self.logger, client=self.route53_client, zone_id=self.zone_id, action='DELETE')
        if not sg_association and instance:
            try:
                instance.wait_until_terminated(
                    Filters=[{"Name": "instance-state-name", "Values": ["terminated"]}]
                )
            except WaiterError as error:
                self.logger.error(error)
        self._delete_security_group(security_group_id)
        os.remove(self.env.vpn_info) if os.path.isfile(self.env.vpn_info) else None
