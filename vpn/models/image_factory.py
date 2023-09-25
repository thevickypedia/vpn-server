import logging
import operator
import warnings
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from dateutil import parser

from vpn.models.config import ami_base, settings
from vpn.models.exceptions import AWSResourceError


def deprecation_warning(image_id: str, deprecation_time: str) -> None:
    """Raises a deprecation warning if the chosen AMI is nearing (value is set in config) its DeprecationTime."""
    expired_utc = parser.parse(deprecation_time)
    current_utc = datetime.utcnow().replace(tzinfo=timezone.utc)
    if (expired_utc - current_utc).days < settings.ami_deprecation:
        warnings.simplefilter('always', DeprecationWarning)
        warnings.warn(
            f"\nThe AMI ID {image_id} is set to be deprecated on {deprecation_time}"
            "\nPlease raise an issue at https://github.com/thevickypedia/expose/issues/new "
            "to update the AMI base",
            DeprecationWarning
        )


class ImageFactory:
    """Handles retrieving AMI ID from multiple sources.

    >>> ImageFactory

    """

    def __init__(self, session: boto3.Session, logger: logging.Logger):
        """Instantiates the ``ImageFactory`` object.

        Args:
            session: boto3 session instantiated in the origin class.
            logger: Custom logger.
        """
        self.session = session
        self.logger = logger

        self.name = ami_base.NAME
        self.alias = ami_base.ALIAS
        self.product_page = ami_base.PRODUCT_PAGE
        self.product_code = ami_base.PRODUCT_CODE

        self.ssm_client = self.session.client('ssm')
        self.ec2_client = self.session.client('ec2')

    def get_ami_id_ssm(self) -> str:
        """Retrieve AMI ID using Ami Alias."""
        response = self.ssm_client.get_parameters(Names=[self.alias], WithDecryption=True)
        if response.get('ResponseMetadata', {}).get('HTTPStatusCode', 400) == 200:
            if params := response.get('Parameters'):
                self.logger.info("Images fetched using AMI alias: %d", len(params))
                self.logger.debug(params)
                params.sort(key=operator.itemgetter('LastModifiedDate'))  # Sort by last modified date
                ami_id = params[-1].get('Value')  # Get the most recent AMI ID
                img_response = self.ec2_client.describe_images(ImageIds=[ami_id])
                if valid_until := img_response.get('Images', [{}])[0].get('DeprecationTime'):
                    deprecation_warning(ami_id, valid_until)
                return ami_id

    def get_ami_id_product_code(self) -> str:
        """Retrieve AMI ID using Product Code."""
        filters = [{'Name': 'product-code', 'Values': [self.product_code]}]
        response = self.ec2_client.describe_images(Filters=filters, Owners=['aws-marketplace'])
        if images := response.get('Images'):
            self.logger.info("Images fetched using product code: %d", len(images))
            self.logger.debug(images)
            images.sort(key=operator.itemgetter('CreationDate'))
            image = images[-1]
            if valid_until := image.get('DeprecationTime'):
                deprecation_warning(image.get('ImageId'), valid_until)
            return image.get('ImageId')

    def get_ami_id_name(self) -> str:
        """Retrieve AMI ID using Ami Name."""
        response = self.ec2_client.describe_images(Filters=[{'Name': 'name', 'Values': [self.name]}])
        if images := response.get('Images'):
            self.logger.info("Images fetched using AMI name: %d", len(images))
            self.logger.debug(images)
            images.sort(key=operator.itemgetter('CreationDate'))
            image = images[-1]
            if valid_until := image.get('DeprecationTime'):
                deprecation_warning(image.get('ImageId'), valid_until)
            return image.get('ImageId')

    def get_image_id(self) -> str:
        """Tries to get image id from multiple sources, sequentially.

        See Also:
            Executes in sequence as fastest first.
            - Alias on SSM points to a single parameter that possibly contains a single AMI ID as its value.
            - Lookup AMI with image name is specific and possibly points to a single AMI ID.
            - Lookup AMI with product code will possibly return many images, so grabs the most recently created one.

        Returns:
            str:
            AMI image ID.

        Raises:
            AWSResourceError:
            If unable to fetch AMI ID from any source.
        """
        try:
            if image_id := self.get_ami_id_ssm():
                return image_id
        except ClientError as error:
            self.logger.error(error)

        try:
            if image_id := self.get_ami_id_name():
                return image_id
        except ClientError as error:
            self.logger.error(error)

        try:
            if image_id := self.get_ami_id_product_code():
                return image_id
        except ClientError as error:
            self.logger.error(error)

        if self.name == ami_base.S_NAME:
            raise AWSResourceError(
                status_code=404,
                error_msg=f'Failed to retrieve AMI ID.\n\t'
                          f'Get AMI ID from {self.product_page} and set manually for {self.session.region_name!r}.\n\t'
                          'Please raise an issue at https://github.com/thevickypedia/expose/issues/new'
            )
        else:
            # Retry mechanism to fall back to secondary AMI settings in marketplace before raising an error
            self.logger.critical("Failed to fetch AMI ID via primary source, using secondary resources.")
            self.name = ami_base.S_NAME
            self.alias = ami_base.S_ALIAS
            self.product_page = ami_base.S_PRODUCT_PAGE
            self.product_code = ami_base.S_PRODUCT_CODE
            return self.get_image_id()
