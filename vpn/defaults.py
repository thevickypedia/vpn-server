from urllib3.util.url import Url as HttpUrl


class AWSDefaults:
    """Default values for missing AWS configuration.

    >>> AWSDefaults

    """

    AMI_SOURCE: 'HttpUrl' = 'https://aws.amazon.com/marketplace/server/configuration?' \
                            'productId=fe8020db-5343-4c43-9e65-5ed4a825c931'
    AMI_NAME: str = 'OpenVPN Access Server Community Image-fe8020db-5343-4c43-9e65-5ed4a825c931-ami-06585f7cf2fb8855c.4'
    AMI_ALIAS: str = '/aws/service/marketplace/prod-qqrkogtl46mpu/2.8.5'
