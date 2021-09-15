from os import environ

from boto3 import client
from botocore.exceptions import ClientError

ec2_client = client('ec2')

try:
    ec2_response = ec2_client.run_instances(
        InstanceType="t2.micro",
        MaxCount=1,
        MinCount=1,
        ImageId=environ.get('ami_id')
    )
except ClientError as error:
    ec2_response = None
    exit(f'Run instance call failed with the message:\n{error}')

if ec2_response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
    instance_id = ec2_response.get('Instances')[0].get('InstanceId')
    print(instance_id)
else:
    print('Failed to spin up an instance.')
