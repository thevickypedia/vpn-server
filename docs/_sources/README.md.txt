![Python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue)

###### Platform Supported
![Generic badge](https://img.shields.io/badge/Platform-MacOS|Windows-1f425f.svg)

###### Repo Stats
[![GitHub](https://img.shields.io/github/license/thevickypedia/vpn-server)][LICENSE]
[![GitHub repo size](https://img.shields.io/github/repo-size/thevickypedia/vpn-server)][API_REPO]
[![GitHub code size](https://img.shields.io/github/languages/code-size/thevickypedia/vpn-server)][API_REPO]

###### Deployments
[![doc](https://github.com/thevickypedia/vpn-server/actions/workflows/pages/pages-build-deployment/badge.svg)][gha_pages]
[![pypi](https://github.com/thevickypedia/vpn-server/actions/workflows/python-publish.yml/badge.svg)][gha_pypi]
[![markdown](https://github.com/thevickypedia/vpn-server/actions/workflows/markdown-validation.yml/badge.svg)][gha_markdown]

[![Pypi-format](https://img.shields.io/pypi/format/vpn-server)](https://pypi.org/project/vpn-server/#files)
[![Pypi-status](https://img.shields.io/pypi/status/vpn-server)](https://pypi.org/project/vpn-server)
[![sourcerank](https://img.shields.io/librariesio/sourcerank/pypi/vpn-server)](https://libraries.io/pypi/vpn-server)

# VPN Server
Establish a scalable, on-demand VPN Server powered by OpenVPN on AWS EC2.

### Install
```shell
python -m pip install vpn-server
```

### Usage
```python
import vpn

# Instantiates the object
vpn_server = vpn.VPNServer()

# Create a VPN Server
vpn_server.create_vpn_server()

# Test an existing VPN Server
# vpn_server.test_vpn()

# Deletes the VPN Server
vpn_server.delete_vpn_server()
```

> :bulb: &nbsp; Please refer to the [wiki page](https://github.com/thevickypedia/vpn-server/wiki) for more usage instructions and payload requirements.

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

## Project Links
[Wiki](https://github.com/thevickypedia/vpn-server/wiki)

[Repository](https://github.com/thevickypedia/vpn-server)

[Runbook](https://thevickypedia.github.io/vpn-server/)

[Package](https://pypi.org/project/vpn-server/)

## License & copyright

&copy; Vignesh Rao

Licensed under the [MIT License][LICENSE]

[LICENSE]: https://github.com/thevickypedia/vpn-server/blob/main/LICENSE
[API_REPO]: https://api.github.com/repos/thevickypedia/vpn-server
[gha_pages]: https://github.com/thevickypedia/vpn-server/actions/workflows/pages/pages-build-deployment
[gha_pypi]: https://github.com/thevickypedia/vpn-server/actions/workflows/python-publish.yml
[gha_markdown]: https://github.com/thevickypedia/vpn-server/actions/workflows/markdown-validation.yml
