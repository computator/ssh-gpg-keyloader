#!/usr/bin/env python3
import glob
import os.path
import subprocess
import sys


def cli():
    for keyfile in glob.iglob(os.path.expanduser('~/.ssh-keystore/*.key.gpg')):
        try:
            key = subprocess.run(
                ['gpg2', '--quiet', '--batch', '--decrypt', keyfile],
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
            output = subprocess.run(
                ['ssh-add', '-k', '-q', '-'],
                check=True,
                input=key,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ).stdout
            if output != b'Identity added: (stdin) ((stdin))\n':
                sys.stderr.write(output.decode())
        except subprocess.CalledProcessError as e:
            print(e)


if __name__ == '__main__':
    cli()
