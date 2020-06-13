#!/usr/bin/env python3
import glob
import os.path
import subprocess


def cli():
    for keyfile in glob.iglob(os.path.expanduser('~/.ssh-keystore/*.key.gpg')):
        try:
            key = subprocess.run(
                ['gpg2', '--quiet', '--batch', '--decrypt', keyfile],
                check=True,
                stdout=subprocess.PIPE
            ).stdout
            subprocess.run(
                ['ssh-add', '-k', '-q', '-'],
                input=key,
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(e)


if __name__ == '__main__':
    cli()
