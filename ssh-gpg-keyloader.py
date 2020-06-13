#!/usr/bin/env python3
import glob
import os.path
import subprocess
import sys


def cli():
    for keyfile in glob.iglob(os.path.expanduser('~/.ssh-keystore/*.key.gpg')):
        try:
            name = os.path.basename(keyfile)[:-8]
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
            print(f"{e}\nError adding private key '{name}'")
        else:
            print(f"Added '{name}'")
            try:
                pubkey = subprocess.run(
                    ['ssh-keygen', '-y', '-f', '/proc/self/fd/0'],
                    check=True,
                    input=key,
                    stdout=subprocess.PIPE,
                ).stdout
                pubkey = f'{pubkey.decode().strip()} ssh-gpg-keyloader:{name}'
                print(pubkey)
            except subprocess.CalledProcessError as e:
                print(f"{e}\nError storing public key for '{name}'")


if __name__ == '__main__':
    cli()
