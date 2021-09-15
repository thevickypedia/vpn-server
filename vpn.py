from logging import getLogger, basicConfig, INFO
from os import path, system, environ

from boto3 import client

key_name = 'OpenVPN'

basicConfig(
    format='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
    datefmt='%b-%d-%Y %I:%M:%S %p', level=INFO
)
logger = getLogger(key_name)

ec2_client = client(service_name='ec2', region_name='us-west-2')


def _create_key_pair():
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


def create_ec2_instance():
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
        with open('instance_id', 'w') as file:
            file.write(instance_id)
    else:
        logger.error('Failed to create an EC2 instance.')


def _delete_key_pair(target_key: str = key_name):
    response = ec2_client.delete_key_pair(
        KeyName=target_key
    )
    if response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
        logger.info(f'{key_name} has been deleted from KeyPairs.')
        return True
    else:
        logger.error(f'Failed to delete the key: {key_name}')


def terminate_ec2_instance(instance_id: str):
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


if __name__ == '__main__':
    create_ec2_instance()
