from json import dump
from logging import getLogger, basicConfig, INFO
from os import environ, path, system
from time import sleep

from boto3 import client, resource

key_name = 'OpenVPN'

basicConfig(
    format='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
    datefmt='%b-%d-%Y %I:%M:%S %p', level=INFO
)
logger = getLogger(key_name)

ec2_client = client(service_name='ec2', region_name='us-west-2')
ec2_resource = resource(service_name='ec2', region_name='us-west-2')


def _create_key_pair() -> bool:
    key_response = ec2_client.create_key_pair(
        KeyName=key_name,
        KeyType='rsa'
    )
    if key_response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
        logger.info(f'Successfully created a key pair named: {key_name}')
        with open(f'{key_name}.pem', 'w') as file:
            file.write(key_response.get('KeyMaterial'))
        logger.info(f'Stored the certificate as {key_name}.pem')
        return True
    else:
        logger.error(f'Unable to create a key pair: {key_name}')


def create_ec2_instance() -> str or None:
    if not _create_key_pair():
        return

    ec2_response = ec2_client.run_instances(
        InstanceType="t2.micro",
        MaxCount=1,
        MinCount=1,
        ImageId=environ.get('ami_id'),
        KeyName=key_name
    )
    if ec2_response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
        instance_id = ec2_response.get('Instances')[0].get('InstanceId')
        logger.info(f'Created the EC2 instance: {instance_id}')
        return instance_id
    else:
        logger.error('Failed to create an EC2 instance.')


def _delete_key_pair(target_key: str = key_name) -> bool:
    response = ec2_client.delete_key_pair(
        KeyName=target_key
    )
    if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
        logger.info(f'{key_name} has been deleted from KeyPairs.')
        return True
    else:
        logger.error(f'Failed to delete the key: {key_name}')


def terminate_ec2_instance(instance_id: str) -> None:
    if not _delete_key_pair():
        return
    response = ec2_client.terminate_instances(
        InstanceIds=[instance_id]
    )
    if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
        logger.info(f'InstanceId {instance_id} has been set to terminate.')
        if path.exists(f'{key_name}.pem'):
            system(f'rm {key_name}.pem')
        if path.exists('instance_id'):
            system('rm instance_id')
    else:
        logger.error(f'Failed to terminate the InstanceId: {instance_id}')


def _get_public_dns(instance_id: str) -> tuple:
    logger.info('Waiting for the instance to go live.')
    while True:
        info_response = ec2_client.describe_instance_status(
            InstanceIds=[instance_id]
        )
        if info_response.get('ResponseMetadata').get('HTTPStatusCode') != 200:
            sleep(3)
            continue
        if status := info_response.get('InstanceStatuses'):
            if status[0].get('InstanceState').get('Name') == 'running':
                instance_info = ec2_resource.Instance(instance_id)
                return instance_info.public_dns_name, instance_info.public_ip_address
            else:
                sleep(3)
        else:
            sleep(3)


def configure_openvpn() -> None:
    if instance_id := create_ec2_instance():
        public_dns, public_ip = _get_public_dns(instance_id=instance_id)

        instance_info = {
            'instance_id': instance_id,
            'public_dns': public_dns,
            'public_ip': public_ip
        }
        with open('instance_info.json', 'w') as file:
            dump(instance_info, file, indent=2)

        # print(f"ssh-keyscan {public_ip}")

        logger.info(f'Restricting wide open permissions to {key_name}.pem')
        system(f'chmod 400 {key_name}.pem')

        config_command = f'ssh -i {key_name}.pem root@{public_dns}'
        print(config_command)  # base command to configure OpenVPN
        print(config_command.replace('root@', 'openvpnas@'))  # setup OpenVPN using the user id


if __name__ == '__main__':
    configure_openvpn()
