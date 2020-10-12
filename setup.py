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
    },
    install_requires=[
        'importlib-metadata>=1.0; python_version<"3.8"',
    ],
    python_requires='>=3',
    setup_requires=['setuptools_scm'],
    use_scm_version=True,
)
