from os import environ

from boto3 import client

key_name = 'OpenVPN'

ec2_client = client(service_name='ec2', region_name='us-west-2')


def _create_key_pair():
    key_response = ec2_client.create_key_pair(
        KeyName=key_name,
        KeyType='rsa'
    )
    if key_response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
        print(f'Successfully created a key pair named: {key_name}')
        with open(f'{key_name}.pem', 'w') as file:
            file.write(key_response.get('KeyMaterial'))
        print(f'Stored the certificate as {key_name}.pem')
        return True
    else:
        exit(f'Unable to create a key pair: {key_name}')


def create_ec2_instance():
    _create_key_pair()
    ec2_response = ec2_client.run_instances(
        InstanceType="t2.micro",
        MaxCount=1,
        MinCount=1,
        ImageId=environ.get('ami_id'),
        KeyName=key_name
    )
    if ec2_response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
        instance_id = ec2_response.get('Instances')[0].get('InstanceId')
        print(f'Created the EC2 instance: {instance_id}')
        return instance_id
    else:
        exit('Failed to create an EC2 instance.')


if __name__ == '__main__':
    create_ec2_instance()
