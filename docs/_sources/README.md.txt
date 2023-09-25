![Python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue)

###### Platform Supported
![Generic badge](https://img.shields.io/badge/Platform-MacOS|Windows-1f425f.svg)

###### Repo Stats
[![GitHub](https://img.shields.io/github/license/thevickypedia/vpn-server)][LICENSE]
[![GitHub repo size](https://img.shields.io/github/repo-size/thevickypedia/vpn-server)][API_REPO]
[![GitHub code size](https://img.shields.io/github/languages/code-size/thevickypedia/vpn-server)][API_REPO]

###### Deployments
[![pages-build-deployment](https://github.com/thevickypedia/vpn-server/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/thevickypedia/vpn-server/actions/workflows/pages/pages-build-deployment)
[![pypi](https://github.com/thevickypedia/vpn-server/actions/workflows/python-publish.yml/badge.svg)](https://github.com/thevickypedia/vpn-server/actions/workflows/python-publish.yml)

[![Pypi-format](https://img.shields.io/pypi/format/vpn-server)](https://pypi.org/project/vpn-server/#files)
[![Pypi-status](https://img.shields.io/pypi/status/vpn-server)](https://pypi.org/project/vpn-server)
[![sourcerank](https://img.shields.io/librariesio/sourcerank/pypi/vpn-server)](https://libraries.io/pypi/vpn-server)

# VPN Server
- You need a VPN but don't want to pay for it?
- [OpenVPN](https://openvpn.net/) is the solution, but configuring it manually can be a lengthy process.
- Once configured, keeping the instance up all the time costs **$$**.
- Scaling up/down a VPN server on demand can make that lengthy process an absolute nightmare.
- This module allows you to create your own on demand VPN server in under 2 minutes.
- The solution is fully automated and runs with `OpenVPN` using `AWS EC2`.

### How it works
- Create an AWS EC2 instance using a pre-built OpenVPN AMI.
- Create a security group with the necessary ports allowed.
- Configure the vpn server using SSH.
- Download the [OpenVPN client](https://openvpn.net/vpn-client/) and connect using the public DNS of the ec2 instance.
- All set! Now the internet traffic will be routed through the VPN. Verify it using an [IP Lookup](https://whatismyipaddress.com/)
> To take it a step further, if you have a registered domain in AWS,
> vpn-server can be accessed with an alias record in route53 pointing to the public IP of the ec2 instance.
- All the above steps are performed automatically when creating a new VPN server.
- This module can also be used to clean up all the AWS resources spun up for creating a vpn server.

### ENV Variables
Environment variables are loaded from any `env` file if present.

<details>
<summary><strong>More on Environment variables</strong></summary>

- **VPN_USERNAME** - Username to access `OpenVPN Connect` client.
- **VPN_PASSWORD** - Password to access `OpenVPN Connect` client.
- **VPN_PORT** - Port number for web interfaces.

- **IMAGE_ID** - AMI ID to be used. Defaults to a pre-built AMI from SSM parameter for [OpenVPN Access Server AMI Alias][AMI_ALIAS].
- **INSTANCE_TYPE** - Instance type to use for the VPN server. Defaults to `t2.nano`, use `t2.micro` if under [free-tier](https://aws.amazon.com/free).
- **KEY_PAIR** - Name of the key pair file to connect to ec2.
- **SECURITY_GROUP** - Name of the security group.
- **VPN_INFO** - Name of the JSON file to dump the server information.
- **HOSTED_ZONE** - Domain name for the hosted zone.
- **SUBDOMAIN** - Alias record name using which the VPN server has to be accessed.

*Optionally `env vars` for AWS config (`AWS_PROFILE_NAME`, `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `AWS_REGION_NAME`) can be setup.*
</details>

### Install
```shell
python -m pip install vpn-server
```

### Usage
```python
import os

os.environ['env_file'] = 'custom'  # to load a custom .env file

import vpn

# Instantiates the object, takes the same args as env vars.
vpn_server = vpn.VPNServer()  # Defaults to console logging, but supports custom logger.

vpn_server.create_vpn_server()  # Create a VPN Server, login information will be saved to a JSON file.

# Test an existing VPN Server (not required, as a test is run right after creation anyway)
# vpn_server.test_vpn()

vpn_server.delete_vpn_server()  # Deletes the VPN Server removing the AWS resources acquired during creation.
```

<br>

<details>
<summary><strong>Limitations</strong></summary>

Currently `expose` cannot handle, tunneling multiple port numbers without modifying the following env vars in the `.env` file.
```shell
KEY_PAIR        # SSH connection to AWS ec2
KEY_FILE        # Private key filename for self signed SSL
CERT_FILE       # Public certificate filename for self signed SSL
SERVER_INFO     # Filename to dump JSON data with server configuration information
SECURITY_GROUP  # Ingress and egress firewall rules to control traffic allowed via VPC
```
</details>

## Coding Standards
Docstring format: [`Google`](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) <br>
Styling conventions: [`PEP 8`](https://www.python.org/dev/peps/pep-0008/) <br>
Clean code with pre-commit hooks: [`flake8`](https://flake8.pycqa.org/en/latest/) and 
[`isort`](https://pycqa.github.io/isort/)

### [Release Notes](https://github.com/thevickypedia/vpn-server/blob/main/release_notes.rst)
**Requirement**
```shell
python -m pip install gitverse
```

**Usage**
```shell
gitverse-release reverse -f release_notes.rst -t 'Release Notes'
```

### Linting
`PreCommit` will ensure linting, and the doc creation are run on every commit.

**Requirement**
```shell
pip install sphinx==5.1.1 pre-commit recommonmark
```

**Usage**
```shell
pre-commit run --all-files
```

### Links
[Repository](https://github.com/thevickypedia/vpn-server)

[Runbook](https://thevickypedia.github.io/vpn-server/)

[Package](https://pypi.org/project/vpn-server/)

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License][LICENSE]

[LICENSE]: https://github.com/thevickypedia/vpn-server/blob/main/LICENSE
[API_REPO]: https://api.github.com/repos/thevickypedia/vpn-server
[AMI_ALIAS]: https://aws.amazon.com/marketplace/server/configuration?productId=fe8020db-5343-4c43-9e65-5ed4a825c931#:~:text=Ami%20Alias
[PRODUCT_PAGE]: https://aws.amazon.com/marketplace/server/procurement?productId=fe8020db-5343-4c43-9e65-5ed4a825c931
