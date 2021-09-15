# VPN Server
Automate on demand VPN Server creation running with OpenVPN using AWS EC2 and Python

### Instructions
#### Setup
1. `git clone https://github.com/thevickypedia/openvpn.git`
2. `python3 -m venv venv`
3. `source venv/bin/activate`
4. `pip3 install -r requirements.txt`
5. `python3 vpn.py`

#### Configuration
1. Run the first command printed in `STDOUT`.
2. Enter `yes` when prompted to allow the PEM file.
3. Accept the agreement when prompted.
   - `Please enter 'yes' to indicate your agreement [no]: `
4. Hit `Enter/Return` for rest of the prompts.
5. Run the second command printed in `STDOUT` to finish the configuration.

### Linting
`PreCommit` will ensure linting, and the doc creation are run on every commit.

Requirement:
<br>
`pip install --no-cache --upgrade sphinx pre-commit recommonmark`

Usage:
<br>
`pre-commit run --all-files`

### Links
[Repository](https://github.com/thevickypedia/openvpn)

[Runbook](https://thevickypedia.github.io/openvpn/)

## License & copyright

&copy; Vignesh Sivanandha Rao

Licensed under the [MIT License](LICENSE)
