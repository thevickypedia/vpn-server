<br>

[![Python 3.8](https://img.shields.io/badge/python-3.8-orange.svg)](https://www.python.org/downloads/release/python-385/)
[![Python 3.9](https://img.shields.io/badge/python-3.9-blue.svg)](https://www.python.org/downloads/release/python-391/)

###### Platform Supported
![Generic badge](https://img.shields.io/badge/Platform-MacOS-1f425f.svg)

###### Repo Stats
[![GitHub](https://img.shields.io/github/license/thevickypedia/vpn-server)](https://github.com/thevickypedia/vpn-server/blob/main/LICENSE)
[![GitHub repo size](https://img.shields.io/github/repo-size/thevickypedia/vpn-server)](https://api.github.com/repos/thevickypedia/vpn-server)
[![GitHub code size](https://img.shields.io/github/languages/code-size/thevickypedia/vpn-server)](https://api.github.com/repos/thevickypedia/vpn-server)
[![LOC](https://img.shields.io/tokei/lines/github/thevickypedia/vpn-server)](https://api.github.com/repos/thevickypedia/vpn-server)

###### Deployments
[![docs](https://github.com/thevickypedia/vpn-server/actions/workflows/docs.yml/badge.svg)](https://thevickypedia.github.io/vpn-server/)

# VPN Server
On demand VPN Server creation running with `OpenVPN` using `AWS EC2` and `Python`.

Got 5 minutes to spare? Spin up your own VPN server on demand.

### Setup and Configuration
1. `git clone https://github.com/thevickypedia/vpn-server.git`
2. `python3 -m venv venv`
3. `source venv/bin/activate`
4. `pip install -r requirements.txt`
5. `export ami_id=ami-0e21cddg3k0c9a930 vpn_password=awsOpenVPN2021` - Sample
6. `python vpn.py`
   - Call the class method:
     - `startup_vpn` to initiate the `VPN Server`
     - `shutdown_vpn` to delete all resource spun up for the `VPN Server`
   - `Runtime: ~3 minutes`

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

### Limitations
- Currently, runs only on `MacOS`
- Can be run only from a local `Macbook` or `iMac`
- There is an over provisioned waiter time running for few AWS interactions.

### Links
[Repository](https://github.com/thevickypedia/vpn-server)

[Runbook](https://thevickypedia.github.io/vpn-server/)

## License & copyright

&copy; Vignesh Sivanandha Rao

Licensed under the [MIT License](https://github.com/thevickypedia/vpn-server/blob/main/LICENSE)
