Release Notes
=============

0.6.9 (02/11/2023)
------------------
- Make available regions accessible at module level

0.6.8 (02/11/2023)
------------------
- Add a feature to spin up `vpn-server` in any region
- Automate AMI ID retrieval for all regions
- Remove vpn server from region spun up instead of the one instantiated in

0.6.7 (02/10/2023)
------------------
- Add alias record in notifications

0.6.6 (02/09/2023)
------------------
- Replace arrow sign to avoid unicode error

0.6.5 (02/09/2023)
------------------
- Bug fix on custom logger

0.6.4 (02/09/2023)
------------------
- Bug fix when using custom logger
- Update gen_docs.sh and bump version

0.6.3 (02/09/2023)
------------------
- Add `bring your own logger`
- Upgrade gmail-connector
- Switch build to pyproject.toml
- Update README.md
- Switch changelog to release_notes.rst

0.6.2 (11/18/2022)
------------------
- Update README.md

0.6.1 (11/16/2022)
------------------
- Remove port number requirement
- Remove env vars displayed in docs
- Update README.md

0.6.0 (11/15/2022)
------------------
- Provide option for instance types and validate
- Include validations for env vars
- Dedicated config module for prompts and responses
- Set pypi publish to run on release tags

0.5.9 (11/13/2022)
------------------
- Add route53 record to set custom dns name
- Clean up route53 record while deleting vpn server
- Update README.md and docs
- Simplify python-publish.yml

0.5.8 (10/27/2022)
------------------
- Improve type hinting
- Upgrade paramiko
- Set build to kick off on push to main branch
- Setup manual workflow dispatch for pypi build

0.5.7 (10/26/2022)
------------------
- Add option to store run time files in any directory
- Refactor code
- Bump gmail-connector version to 0.5.4
- Update requirements.txt
- Fix imports

0.5.6 (01/19/2022)
------------------
- Flush screen output before carriage return

0.5.5 (01/19/2022)
------------------
- Take optional args to delete vpn server

0.5.4 (01/17/2022)
------------------
- Redirect prints to log file when used
- Split server config into its own module

0.5.3 (01/12/2022)
------------------
- Take `vpn_username` and `vpn_password` as args
- Create log files only when requested
- Notify upon failure and attach logfile in email

0.5.2 (01/10/2022)
------------------
- Disable printing final config when logged in a file

0.5.1 (01/10/2022)
------------------
- Change configuration input to match regex
- Set interactive timeouts

0.5.0 (01/10/2022)
------------------
- Take notification args during class instantiation

0.4.9 (01/09/2022)
------------------
- Bump `gmail-connector` version
- Include sender in email notification

0.4.8 (01/09/2022)
------------------
- Update return types and docstrings

0.4.7 (01/09/2022)
------------------
- Remove AMI_ID from mandatory args
- Retrieve AMI_ID automatically
- Setup AWS defaults
- Update docs

0.4.6 (01/09/2022)
------------------
- Make `vpn-server` a package and onboard to pypi

0.4.5 (01/09/2022)
------------------
- Automate onboarding to pypi

0.4.4 (01/09/2022)
------------------
- Remove `os.system` usage and introduce hybrid logger

0.4.3 (01/09/2022)
------------------
- Add a note on firewall configuration ports

0.4.2 (01/02/2022)
------------------
- Change sensitive values to a list to hide from logs
- Do not log server info

0.4.1 (01/02/2022)
------------------
- Hide port number and password from the logs
- Add timeout and display options as arguments
- Add one more option to test/update existing connection

0.4.0 (01/01/2022)
------------------
- Add more logging and remove unnecessary args
- Pass the initial 'yes' as part of the configuration dict
- Bump timeout to 30 seconds

0.3.9 (01/01/2022)
------------------
- Restructure static methods into a single module

0.3.8 (01/01/2022)
------------------
- Use paramiko for interactive ssh commands
- Get rid of the OS limitation
- Improve the overall speed of configuration
- Add an option to reconfigure

0.3.7 (12/31/2021)
------------------
- Upgrade gmailconnector version
- Update year in LICENSE file

0.3.6 (10/04/2021)
------------------
- Strip https from notification URL
- Distinguish attempt wise notification
- Log a warning message if env vars for notification is missing

0.3.5 (09/24/2021)
------------------
- FEATURE::Sends a notification when a second instance is triggered
- Swap delete security group and sleeper

0.3.4 (09/24/2021)
------------------
- Simplify notification process
- Add logs to .gitignore

0.3.3 (09/23/2021)
------------------
- Write only to file when triggered by Jarvis
- Remove root logger
- Move sleeper within class

0.3.2 (09/23/2021)
------------------
- Add `loggingWrapper` for file and console logging
- Create log files when triggered by `Jarvis`
- Add datetime to email subject to avoid threads

0.3.1 (09/22/2021)
------------------
- Add optional email notification upon vpn startup

0.3.0 (09/21/2021)
------------------
- Fix buggy walrus operator which kept failing notifications
- Reduce file IO operations
- Strip https from url in notification
- Increase wait time while shutting down vpn
- Modify sleeper in _instance_info
- Remove optional arguments

0.2.9 (09/21/2021)
------------------
- Split sleep time as its own function to avoid redundancy

0.2.8 (09/21/2021)
------------------
- Log results of notification
- Change method name to avoid conflict with module
- Add waiting time for file IO to finish

0.2.7 (09/20/2021)
------------------
- Add a feature to send login details via SMS
- Update requirements.txt and docstrings

0.2.6 (09/20/2021)
------------------
- Add custom `PORT` number feature

0.2.5 (09/20/2021)
------------------
- Add `VPN_USERNAME` option for custom login info
- Write region name in `server_info.json`
- Add a color to terminal
- Update README.md and docstrings

0.2.4 (09/20/2021)
------------------
- Update styling in `README.md` to populate in sphinx docs

0.2.3 (09/20/2021)
------------------
- Use region specific AMI IDs
- Add more info on env vars to README.md
- Clean up and update docstrings

0.2.2 (09/20/2021)
------------------
- Redirect client traffic via VPN automatically
- Update README.md and add applescript in docstring

0.2.1 (09/20/2021)
------------------
- Optionally load `env-vars` from `.env` file

0.2.0 (09/20/2021)
------------------
- Make script to initiate only from `commandline`
- Don't exit script until `SecurityGroup` is deleted
- Update requirements.txt and docs

0.1.9 (09/16/2021)
------------------
- Change branch name to `main` to pick up page build

0.1.8 (09/16/2021)
------------------
- Add manual config info for `Windows OS`
- Clean up
- Update README.md and docs

0.1.7 (09/16/2021)
------------------
- FEATURE::Spins up a VPN Server on EC2 with a single click
- Add all the automation bits
- Add time converter to calculate run time
- Add an apple script for the automation
- Add functionality to re-use AWS resources

0.1.6 (09/16/2021)
------------------
- Setup github action for docs

0.1.5 (09/15/2021)
------------------
- Add features to create and delete `SecurityGroups`
- Reconfigure flow of code
- Update docstrings and docs

0.1.4 (09/15/2021)
------------------
- Proceed to terminate instance even when `KeyPair` deletion fails
- Add access key and secret id as optional arguments during class initialization

0.1.3 (09/15/2021)
------------------
- First automation to add `ip` and `host` entry in known_hosts file

0.1.2 (09/15/2021)
------------------
- Delete recent instance if an instance id is not provided to terminate
- Delete instance_info.json while terminating an instance

0.1.1 (09/14/2021)
------------------
- Onboard sphinx auto docs
- Add pre-commit and sync up with doc generation
- Rename repo from openvpn to vpn-server

0.1.0 (09/14/2021)
------------------
- Update README.md

0.0.9 (09/14/2021)
------------------
- Wrap everything inside a class and add docstrings

0.0.8 (09/14/2021)
------------------
- Add exception handlers where necessary

0.0.7 (09/14/2021)
------------------
- Get public dns name and public ip address and write as JSON

0.0.6 (09/14/2021)
------------------
- Add functions to delete keypair and terminate instance

0.0.5 (09/14/2021)
------------------
- Add logging instead of print statements

0.0.4 (09/14/2021)
------------------
- Create pem file while spinning up an instance

0.0.3 (09/14/2021)
------------------
- Base script to create an instance using an AMI ID
- Add `requirements.txt`

0.0.2 (09/14/2021)
------------------
- Update LICENSE, README.md and add .gitignore

0.0.1 (09/14/2021)
------------------
- Initial commit
