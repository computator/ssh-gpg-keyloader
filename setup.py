from setuptools import setup

setup(
    name='ssh-gpg-keyloader',
    description="Load SSH keys from a directory of GPG encrypted keys",
    url='https://github.com/computator/ssh-gpg-keyloader',
    py_modules=['ssh-gpg-keyloader'],
    entry_points={
        'console_scripts': [
            'ssh-gpg-keyloader=ssh-gpg-keyloader:cli',
        ]
    }
)
