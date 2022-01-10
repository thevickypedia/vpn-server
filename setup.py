from os.path import dirname, isfile, join, realpath, sep

from setuptools import setup

from version import version_info

classifiers = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Information Technology',
    'Operating System :: MacOS :: MacOS X',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3.9',
    'Topic :: System :: Networking :: Firewalls'
]


def read(name):
    """Reads the file that was received as argument.

    Args:
        name: Name of the file that has to be opened and read.

    Returns:
        Content of the file that was read.

    References:
        https://pythonhosted.org/an_example_pypi_project/setuptools.html#setting-up-setup-py
    """
    with open(join(dirname(__file__), name)) as file:
        content = file.read()
    return content


def dependencies() -> list:
    """Gathers dependencies from requirements file.

    Returns:
        List of dependencies to be installed.
    """
    requirement_file = dirname(realpath(__file__)) + f'{sep}vpn{sep}requirements.txt'
    if isfile(requirement_file):
        with open(requirement_file) as requirements:
            install_requires = requirements.read().splitlines()
    return install_requires


setup(
    name='vpn-server',
    version='.'.join(str(c) for c in version_info),
    description='Create an on demand VPN Server running with OpenVPN using AWS EC2.',
    long_description=read('README.md') + '\n\n' + read('CHANGELOG'),
    url='https://github.com/thevickypedia/vpn-server',
    author='Vignesh Sivanandha Rao',
    author_email='svignesh1793@gmail.com',
    License='MIT',
    classifiers=classifiers,
    keywords='openvpn-server, vpn-server, aws-ec2',
    packages=['.vpn'],
    install_requires=dependencies(),
    project_urls={
        'Docs': 'https://thevickypedia.github.io/vpn-server',
        'Bug Tracker': 'https://github.com/thevickypedia/vpn-server/issues'
    },
)
