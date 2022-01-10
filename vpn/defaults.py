class AWSDefaults:
    """Default values for missing AWS configuration.

    >>> AWSDefaults

    """

    AMI_NAME = 'OpenVPN Access Server Community Image-fe8020db-5343-4c43-9e65-5ed4a825c931-ami-06585f7cf2fb8855c.4'

    IMAGE_MAP = {
        "us-east-1": "ami-037ff6453f0855c46",
        "us-east-2": "ami-04406fdec0f245050",
        "us-west-1": "ami-0ce1d8c91d5b9ee92",
        "us-west-2": "ami-0d10bccf2f1a6d60b"
    }

    REGIONS = {
        "us-east-2": "US East (Ohio)",
        "us-east-1": "US East (N. Virginia)",
        "us-west-1": "US West (N. California)",
        "us-west-2": "US West (Oregon)",
        "af-south-1": "Africa (Cape Town)",
        "ap-east-1": "Asia Pacific (Hong Kong)",
        "ap-south-1": "Asia Pacific (Mumbai)",
        "ap-northeast-3": "Asia Pacific (Osaka)",
        "ap-northeast-2": "Asia Pacific (Seoul)",
        "ap-southeast-1": "Asia Pacific (Singapore)",
        "ap-southeast-2": "Asia Pacific (Sydney)",
        "ap-northeast-1": "Asia Pacific (Tokyo)",
        "ca-central-1": "Canada (Central)",
        "cn-north-1": "China (Beijing)",
        "cn-northwest-1": "China (Ningxia)",
        "eu-central-1": "Europe (Frankfurt)",
        "eu-west-1": "Europe (Ireland)",
        "eu-west-2": "Europe (London)",
        "eu-west-3": "Europe (Paris)",
        "eu-north-1": "Europe (Stockholm)",
        "eu-south-1": "Europe (Milan)",
        "me-south-1": "Middle East (Bahrain)",
        "sa-east-1": "South America (São Paulo)"
    }
