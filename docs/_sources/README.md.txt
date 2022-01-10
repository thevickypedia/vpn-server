[![Python 3.8](https://img.shields.io/badge/python-3.8-orange.svg)](https://www.python.org/downloads/release/python-385/)
[![Python 3.9](https://img.shields.io/badge/python-3.9-blue.svg)](https://www.python.org/downloads/release/python-391/)

###### Platform Supported
![Generic badge](https://img.shields.io/badge/Platform-MacOS|Windows-1f425f.svg)

###### Repo Stats
[![GitHub](https://img.shields.io/github/license/thevickypedia/vpn-server)](https://github.com/thevickypedia/vpn-server/blob/main/LICENSE)
[![GitHub repo size](https://img.shields.io/github/repo-size/thevickypedia/vpn-server)](https://api.github.com/repos/thevickypedia/vpn-server)
[![GitHub code size](https://img.shields.io/github/languages/code-size/thevickypedia/vpn-server)](https://api.github.com/repos/thevickypedia/vpn-server)
[![LOC](https://img.shields.io/tokei/lines/github/thevickypedia/vpn-server)](https://api.github.com/repos/thevickypedia/vpn-server)

###### Deployments
[![docs](https://github.com/thevickypedia/vpn-server/actions/workflows/docs.yml/badge.svg)](https://thevickypedia.github.io/vpn-server/)

# VPN Server
Create an on demand VPN Server running with `OpenVPN` using `AWS EC2` and `Python`.

### ENV Variables
If a `.env` file is present (with the required variables) in current working directory, there is no need for env vars,
as [`vpn-server`](https://github.com/thevickypedia/vpn-server) loads `.env` files during start up.

<details>
<summary><strong>More on Environment variables</strong></summary>

Use [cloudping.info](https://www.cloudping.info/) to pick the fastest (from current location) available region.

> AMI IDs are got from `OpenVPN Access Server Community Images` per region.

- **AMI_ID_{REGION_NAME}** - AMI ID in a region. Looks for `AMI_ID_us-west-2` since `us-west-2` is the default region.
- **VPN_USERNAME** - Username to access VPN Server once, configuration is done. If `null`, looks for the env var `USER`.
Defaults to `openvpn`
- **VPN_PASSWORD** - Password to access VPN Server once, configuration is done. Defaults to `awsVPN2021`
- **VPN_PORT** - Port number where the traffic has to be forwarded. Defaults to `943`
- **REGION_NAME** - Region where the VPN Server should live. Defaults to `us-west-2`

**To get notification of login information:**<br>
- **gmail_user** - Username of the gmail account.
- **gmail_pass** - Password of the gmail account.
- **phone** - Phone number to which the notification has to be sent.
- **recipient** - Email address to which the notification has to be sent.

Optionally `env vars` for AWS config (`ACCESS_KEY`, `SECRET_KEY`, `REGION_NAME`) can be setup.
</details>

### Install
`pip install vpn-server`

### Usage
```python
from vpn.controller import VPNServer

vpn_server = VPNServer()

vpn_server.create_vpn_server()  # Create a VPN Server

vpn_server.reconfigure_vpn()  # Re-configure an existing VPN Server

vpn_server.test_vpn()  # Test an existing VPN Server

vpn_server.delete_vpn_server()  # Delete the VPN Server
```

<details>
<summary><strong>Manual Configuration</strong></summary>

1. Are you sure you want to continue connecting (yes/no)? `yes` 
2. Please enter 'yes' to indicate your agreement [no]: `yes`
3. Will this be the primary Access Server node? Default: `yes`
4. Please specify the network interface and IP address to be used by the Admin Web UI: `Default: all interfaces: 0.0.0.0`
5. Please specify the port number for the Admin Web UI. Default: `{PORT}`
6. Please specify the TCP port number for the OpenVPN Daemon. Default: `443`
7. Should client traffic be routed by default through the VPN? `yes`
8. Should client DNS traffic be routed by default through the VPN? Default: `No`
9. Use local authentication via internal DB? Default: `yes`
10. Should private subnets be accessible to clients by default? Default: `yes`
11. Do you wish to login to the Admin UI as "openvpn"? Default: `yes`
12. Specify the username for an existing user or for the new user account: `{USERNAME}`
13. Type the password for the 'vicky' account: `{PASSWORD}`
14. Confirm the password for the 'vicky' account: `{PASSWORD}`
15. Please specify your Activation key (or leave blank to specify later): `{ENTER/RETURN}`
16. Download the `OpenVPN` application and get connected to the VPN server.

</details>

### AWS Resources Used
- EC2
  - Instances
  - AMI
  - KeyPairs
  - SecurityGroups
- Network Interfaces
- VPC [Default]
- Subnet [Default]

### Linting
`PreCommit` will ensure linting, and the doc creation are run on every commit.

Requirement:
<br>
`pip install --no-cache --upgrade sphinx pre-commit recommonmark`

Usage:
<br>
`pre-commit run --all-files`

### Links
[Repository](https://github.com/thevickypedia/vpn-server)

[Runbook](https://thevickypedia.github.io/vpn-server/)

[Package](https://pypi.org/project/vpn-server/)

## License & copyright

&copy; Vignesh Sivanandha Rao

Licensed under the [MIT License](https://github.com/thevickypedia/vpn-server/blob/main/LICENSE)
