import logging
from http.client import responses as http_response
from typing import Union

import boto3
from botocore.exceptions import ClientError

from vpn.models.exceptions import AWSResourceError


def get_zone_id(client: boto3.client,
                logger: logging.Logger,
                dns: str,
                init: bool = False) -> Union[str, None]:
    """Gets the zone ID of a DNS name registered in route53.

    Args:
        client: Pre-instantiated boto3 client.
        logger: Custom logger.
        dns: Hosted zone name.
        init: Boolean flag to raise an error in case of missing zone ID.

    Returns:
        Union[str, None]:
        Returns the zone ID.

    Raises:
        AWSResourceError:
        If unable to fetch the hosted zone ID by name.
    """
    response = client.list_hosted_zones_by_name(DNSName=dns, MaxItems='10')

    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
        logger.error(response)
        if init:
            status_code = response.get('ResponseMetadata', {}).get('HTTPStatusCode', 500)
            raise AWSResourceError(status_code, http_response[status_code])
        return

    if hosted_zones := response.get('HostedZones'):
        for hosted_zone in hosted_zones:
            if hosted_zone['Name'] in (dns, f'{dns}.'):
                return hosted_zone['Id'].split('/')[-1]
    if init:
        raise AWSResourceError(404, f'No HostedZones found for the DNSName: {dns}')
    logger.error(f'No HostedZones found for the DNSName: {dns}\n{response}')


def change_record_set(client: boto3.client,
                      source: str,
                      destination: str,
                      logger: logging.Logger,
                      zone_id: str,
                      action: str) -> bool:
    """Changes a record set within an existing hosted zone.

    Args:
        client: Pre-instantiated boto3 client.
        source: Source DNS name.
        destination: Destination hostname or IP address.
        logger: Custom logger.
        zone_id: Hosted zone ID.
        action: Action to perform. Example: UPSERT or DELETE

    Returns:
        bool:
        Flag to indicate the calling function, whether the record was modified successfully.
    """
    logger.info("%s `%s` record::%s -> %s", action, 'A', source, destination)
    try:
        response = client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': f'A: {source} -> {destination}',
                'Changes': [
                    {
                        'Action': action,
                        'ResourceRecordSet': {
                            'Name': source,
                            'Type': 'A',
                            'TTL': 300,
                            'ResourceRecords': [{'Value': destination}],
                        }
                    },
                ]
            }
        )
    except ClientError as error:
        logger.error(error)
        return False
    if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        logger.info(response.get('ChangeInfo', {}).get('Comment'))
        logger.debug(response.get('ChangeInfo'))
        return True
    logger.error(response)
