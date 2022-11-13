from typing import Dict


class AWSDefaults:
    """Default values for missing AWS configuration.

    >>> AWSDefaults

    """

    AMI_SOURCE = 'https://aws.amazon.com/marketplace/server/configuration?' \
                 'productId=fe8020db-5343-4c43-9e65-5ed4a825c931'
    AMI_NAME: str = 'OpenVPN Access Server Community Image-fe8020db-5343-4c43-9e65-5ed4a825c931-ami-06585f7cf2fb8855c.4'

    IMAGE_MAP: Dict = {
        "us-east-1": "ami-037ff6453f0855c46",
        "us-east-2": "ami-04406fdec0f245050",
        "us-west-1": "ami-0ce1d8c91d5b9ee92",
        "us-west-2": "ami-0d10bccf2f1a6d60b"
    }
