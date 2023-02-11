![Python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue)

###### Platform Supported
![Generic badge](https://img.shields.io/badge/Platform-MacOS|Windows-1f425f.svg)

###### Repo Stats
[![GitHub](https://img.shields.io/github/license/thevickypedia/vpn-server)][LICENSE]
[![GitHub repo size](https://img.shields.io/github/repo-size/thevickypedia/vpn-server)][API_REPO]
[![GitHub code size](https://img.shields.io/github/languages/code-size/thevickypedia/vpn-server)][API_REPO]
[![LOC](https://img.shields.io/tokei/lines/github/thevickypedia/vpn-server)][API_REPO]

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
- Download the [OpenVPN client](https://openvpn.net/vpn-client/) and connect using public IP of the ec2 instance.
- All set! Now the internet traffic will be routed through the VPN. Verify it using an [IP Lookup](https://whatismyipaddress.com/)
> To take it a step further, if you have a registered domain in AWS,
> vpn-server can be accessed with an alias record in route53 pointing to the public IP of the ec2 instance.
- All the above steps are performed automatically when creating a new VPN server.
- This module can also be used to clean up all the AWS resources spun up for creating a vpn server.

### ENV Variables
Environment variables are loaded from `.env` file if present.

<details>
<summary><strong>More on Environment variables</strong></summary>

- **IMAGE_ID** - AMI ID to be used. Defaults to a pre-built AMI from SSM parameter for [OpenVPN Access Server AMI Alias][AMI_ALIAS].
- **INSTANCE_TYPE** - Instance type to use for the VPN server. Defaults to `t2.nano`, use `t2.micro` if under [free-tier](https://aws.amazon.com/free).
- **VPN_USERNAME** - Username to access `OpenVPN Connect` client. Defaults to log in profile or `openvpn`
- **VPN_PASSWORD** - Password to access `OpenVPN Connect` client. Defaults to `awsVPN2021`
- **DOMAIN** - Domain name for the hosted zone.
- **RECORD_NAME** - Alias record name using which the VPN server has to be accessed.

**To get notification about login information:**<br>
- **GMAIL_USER** - Username of the gmail account.
- **GMAIL_PASS** - Password of the gmail account.
- **RECIPIENT** - Email address to which the notification has to be sent.
- **PHONE** - Phone number to which the notification has to be sent (Works only for `US` based cellular)

*Optionally `env vars` for AWS config (`AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `AWS_REGION_NAME`) can be setup.*
</details>

### Install
```shell
python -m pip install vpn-server
```

### Usage
```python
import vpn

# Instantiates the object, takes the same args as env vars.
vpn_server = vpn.VPNServer()  # Defaults to console logging, but supports custom logger.

vpn_server.create_vpn_server()  # Create a VPN Server, login information will be saved to a JSON file.

# Re-configure an existing VPN Server (not required, unless the configuration steps have been interrupted)
# vpn_server.reconfigure_vpn()

# Test an existing VPN Server (not required, as a test is run right after creation anyway)
# vpn_server.test_vpn()

vpn_server.delete_vpn_server()  # Deletes the VPN Server removing the AWS resources acquired during creation.
```

<details>
<summary><strong>Manual Configuration</strong></summary>

*Following are the prompts and response required to configure the VPN server.*

- Are you sure you want to continue connecting (yes/no)? `yes` 
1. Please enter 'yes' to indicate your agreement [no]: `yes`
2. Will this be the primary Access Server node? Default: `yes`
3. Please specify the network interface and IP address to be used by the Admin Web UI: `Default: all interfaces: 0.0.0.0`
4. Please specify the port number for the Admin Web UI. Default: `943`
5. Please specify the TCP port number for the OpenVPN Daemon. Default: `443`
6. Should client traffic be routed by default through the VPN? `yes`
7. Should client DNS traffic be routed by default through the VPN? Default: `No`
8. Use local authentication via internal DB? Default: `yes`
9. Should private subnets be accessible to clients by default? Default: `yes`
10. Do you wish to login to the Admin UI as "openvpn"? Default: `yes`
11. Specify the username for an existing user or for the new user account: `{USERNAME}`
12. Type the password for the 'vicky' account: `{PASSWORD}`
13. Confirm the password for the 'vicky' account: `{PASSWORD}`
14. Please specify your Activation key (or leave blank to specify later): `{ENTER/RETURN}`

- Download the `OpenVPN` application and get connected to the VPN server.

</details>

### AWS Resources Used
- EC2
  - Instance - _To redirect traffic through the instance's IP_
  - SecurityGroup - _To allow traffic over specific TCP ports_
  - Systems Manager - _To access [OpenVPN SSM parameter store][AMI_ALIAS] to retrieve the AMI ID_
  - Route53 [Optional] - _To access VPN server using an `A` record in `Route 53`_
- VPC [Default]
- Subnet [Default]

### [Release Notes](https://github.com/thevickypedia/vpn-server/blob/main/release_notes.rst)
**Requirement**
```shell
python -m pip install changelog-generator
```

**Usage**
```shell
changelog reverse -f release_notes.rst -t 'Release Notes'
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

&copy; Vignesh Sivanandha Rao

Licensed under the [MIT License][LICENSE]

[LICENSE]: https://github.com/thevickypedia/vpn-server/blob/main/LICENSE
[API_REPO]: https://api.github.com/repos/thevickypedia/vpn-server
[AMI_ALIAS]: https://aws.amazon.com/marketplace/server/configuration?productId=fe8020db-5343-4c43-9e65-5ed4a825c931#:~:text=Ami%20Alias
[PRODUCT_PAGE]: https://aws.amazon.com/marketplace/server/procurement?productId=fe8020db-5343-4c43-9e65-5ed4a825c931
