Release Notes
=============

1.5 (09/28/2023)
----------------
- Includes an option to take ``kwargs`` during object instantiation
- Allows users to run without the need for a ``.env`` file
- Improved test scenarios with all possible server hostnames

1.4a (09/26/2023)
-----------------
- Allow ``kwargs`` during object instantiation
- Update README.md
- Release alpha version

1.3.2 (09/26/2023)
------------------
- Includes minor improvements for increased compatibility

1.3 (09/25/2023)
----------------
- Includes bug fixes and upgrades to latest OpenVPN Access Server version
- Removes notification features and redundancies
- Increases security, reliability, performance and overall stability
- Uses pydantic for validations
- Improves run-time by 2x

1.0.5b (09/25/2023)
-------------------
- Remove unreferenced secondary attributes
- Release beta version v1.0.5b

1.0.5a (09/25/2023)
-------------------
- Remove entrypoint arg for deletion
- Release alpha version v1.0.5a

1.0.4b (09/25/2023)
-------------------
- Store entrypoint in JSON dump
- Use it during cleanup
- Release beta version

1.0.4a (09/25/2023)
-------------------
- Release `v1.0.4a`
- Include package data

0.9.1 (08/30/2023)
------------------
- Includes some minor modifications in type hinting and build process

0.9.1a (08/30/2023)
-------------------
- Set return type to `None` from `NoReturn`
- Add dependencies to requirements.txt
- Use gitverse for generating release notes
- Upgrade to latest flake8 and isort
- Set to beta version

0.9 (04/03/2023)
----------------
- Upgrade `gmail-connector` and references
- Un-hook package version dependencies

0.7.0 (02/11/2023)
------------------
- Make `PEM_FILE` and `INFO_FILE` available at module level

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
