from collections.abc import Generator

import boto3


def available_instance_types() -> Generator[str]:
    """Get all available EC2 instance types looping through describe instances API call.

    Yields:
        Generator[str]:
        Instance type.
    """
    ec2_client = boto3.client('ec2')
    describe_args = {}
    while True:
        describe_result = ec2_client.describe_instance_types(**describe_args)
        yield from [i['InstanceType'] for i in describe_result['InstanceTypes']]
        if 'NextToken' not in describe_result:
            break
        describe_args['NextToken'] = describe_result['NextToken']


def available_regions() -> Generator[str]:
    """Get all available regions with describe regions API call.

    Yields:
        Generator[str]:
        Region name.
    """
    ec2_client = boto3.client('ec2')
    for region in ec2_client.describe_regions()['Regions']:
        yield region['RegionName']
