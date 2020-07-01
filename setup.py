from setuptools import setup

setup(
    name='sshkeystore',
    description="Load SSH keys from a directory of GPG encrypted keys",
    url='https://github.com/computator/sshkeystore',
    packages=['sshkeystore'],
    entry_points={
        'console_scripts': [
            'sshks=sshkeystore:cli',
        ]
    }
)
