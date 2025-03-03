import os
import re
from typing import List, Union

from pydantic import BaseModel, Field, FilePath, HttpUrl, field_validator
from pydantic_settings import BaseSettings


class ConfigurationSettings(BaseModel):
    """OpenVPN's configuration settings, for SSH interaction.

    >>> ConfigurationSettings

    """

    request: str
    response: Union[str, int]
    timeout: int
    critical: bool


class AMIBase(BaseModel):
    """Default values to fetch AMI image ID.

    >>> AMIBase

    See Also:
        - Subscription Home Page: https://{REGION}.console.aws.amazon.com/marketplace/home#/subscriptions/{_PRODUCT_ID}
        - Product ID: Found in the home page URL under Summary as 'Product ID'
        - Product Code: Offer ID in the home page URL
        - AMI Alias: Found in configuration page (_BASE_URL) as 'Ami Alias'
        - Product Code: Found in configuration page (_BASE_URL) as 'Product Code'
    """

    _BASE_URL: str = (
        "https://aws.amazon.com/marketplace/server/configuration?productId={productId}"
    )
    _BASE_SSM: str = "/aws/service/marketplace/prod-{path}"
    _PRODUCT_ID: str = "fe8020db-5343-4c43-9e65-5ed4a825c931"

    PRODUCT_PAGE: HttpUrl = _BASE_URL.format(productId=_PRODUCT_ID)
    NAME: str = f"OpenVPN Access Server QA Image-{_PRODUCT_ID}"
    ALIAS: str = _BASE_SSM.format(path="qqrkogtl46mpu/2.13.1")
    PRODUCT_CODE: str = "f2ew2wrz425a1jagnifd02u5t"


ami_base = AMIBase()


# noinspection PyMethodParameters
class EnvConfig(BaseSettings):
    """Env configuration.

    >>> EnvConfig

    References:
        https://docs.pydantic.dev/2.3/migration/#required-optional-and-nullable-fields
    """

    vpn_username: str = Field(..., min_length=4, max_length=30)
    vpn_password: str = Field(..., min_length=8, max_length=60)
    vpn_port: int = 943

    aws_profile_name: Union[str, None] = None
    aws_access_key: Union[str, None] = None
    aws_secret_key: Union[str, None] = None

    image_id: Union[str, None] = Field(None, pattern="^ami-.*")
    instance_type: str = "t2.micro"
    aws_region_name: str = "us-east-2"

    key_pair: str = "OpenVPN"
    security_group: str = "OpenVPN Access Server"
    vpn_info: str = Field("vpn_info.json", pattern=r".+\.json$")

    hosted_zone: Union[str, None] = None
    subdomain: Union[str, None] = None

    class Config:
        """Extra config for .env file and extra."""

        extra = "allow"
        env_file = os.environ.get("env_file", os.environ.get("ENV_FILE", ".env"))

    @field_validator("vpn_password", mode="before", check_fields=True)
    def validate_vpn_password(cls, v: str) -> str:
        """Validates vpn_password as per the required regex."""
        if re.match(
            pattern=r"^(?=.*\d)(?=.*[A-Z])(?=.*[!@#$%&'()*+,-/[\]^_`{|}~<>]).+$",
            string=v,
        ):
            return v
        raise ValueError(
            r"Password must contain a digit, an Uppercase letter, and a symbol from !@#$%&'()*+,-/[\]^_`{|}~<>"
        )

    @field_validator("instance_type", mode="before", check_fields=True)
    def validate_instance_type(cls, v: str) -> str:
        """Validate instance type to make sure it is not a nano."""
        if re.match(pattern=r".+\.nano$", string=v):
            raise ValueError(
                "Instance type should at least be a micro, to accommodate memory requirements."
            )
        return v


env = EnvConfig


class Settings(BaseModel):
    """Wrapper for configuration settings.

    >>> Settings

    """

    key_pair_file: FilePath = None
    entrypoint: str = None
    openvpn_config_commands: List[ConfigurationSettings] = []


settings = Settings()


def configuration_dict(param: EnvConfig) -> List[ConfigurationSettings]:
    """Get configuration interaction as a list of dictionaries."""
    for config_dict in [
        {
            "request": "Please enter 'yes' to indicate your agreement \\[no\\]: ",
            "response": "yes",
            "timeout": 5,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[yes\\]: ",
            "response": "yes",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press Enter for default \\[1\\]: ",
            "response": "1",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[rsa\\]:",
            "response": "rsa",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[ 2048 \\]:",
            "response": "2048",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[rsa\\]:",
            "response": "rsa",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[ 2048 \\]:",
            "response": "2048",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[943\\]: ",
            "response": param.vpn_port,
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[443\\]: ",
            "response": "443",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[no\\]: ",
            "response": "yes",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[no\\]: ",
            "response": "yes",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for EC2 default \\[yes\\]: ",
            "response": "yes",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Press ENTER for default \\[yes\\]: ",
            "response": "no",
            "timeout": 1,
            "critical": False,
        },
        {
            "request": "> Specify the username for an existing user or for the new user account: ",
            "response": param.vpn_username,
            "timeout": 1,
            "critical": True,
        },
        {
            "request": f"Type a password for the '{param.vpn_username}' account "
            "(if left blank, a random password will be generated):",
            "response": param.vpn_password,
            "timeout": 1,
            "critical": True,
        },
        {
            "request": f"Confirm the password for the '{param.vpn_username}' account:",
            "response": param.vpn_password,
            "timeout": 1,
            "critical": True,
        },
        {
            "request": "> Please specify your Activation key (or leave blank to specify later): ",
            "response": "\n",
            "timeout": 1,
            "critical": False,
        },
    ]:
        yield ConfigurationSettings(**config_dict)
