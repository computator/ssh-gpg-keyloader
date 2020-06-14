#!/usr/bin/env python3
import getpass
import glob
import os.path
import stat
import subprocess
import sys


def make_pubkey_dir():
    if 'KEYLOADER_PUBKEY_PATH' in os.environ:
        keypath = os.environ['KEYLOADER_PUBKEY_PATH']
    else:
        keypath = f'/tmp/ssh-keystore-pub_{getpass.getuser()}'
    keypath = os.path.abspath(keypath)
    try:
        info = os.stat(keypath)
    except FileNotFoundError:
        os.mkdir(keypath, stat.S_IRWXU)  # 0o700
        os.chmod(keypath, stat.S_IRWXU)  # in case mkdir() doesn't set the mode
        info = os.stat(keypath)  # get final stats for next checks
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"'{keypath}' is not a directory")
    if info.st_uid != os.getuid():
        raise RuntimeError(f"'{keypath}' is owned by another user")
    # only traversal permissions are allowed for others
    if stat.S_IMODE(info.st_mode) & ~(stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH):
        raise RuntimeError(f"'{keypath}' has unsafe permissions")
    return keypath


def cli():
    pubdir = None
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
            except subprocess.CalledProcessError as e:
                print(f"{e}\nError retriving public key for '{name}'")
            else:
                if not pubdir:
                    pubdir = make_pubkey_dir()
                with open(os.path.join(pubdir, f'{name}.pub'), 'w') as f:
                    fno = f.fileno()
                    info = os.stat(fno)
                    # remove write and execute permissions for others
                    newmode = stat.S_IMODE(info.st_mode) & (
                        stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH  # 0o744
                    )
                    os.chmod(fno, newmode)
                    f.write(pubkey)


if __name__ == '__main__':
    cli()
