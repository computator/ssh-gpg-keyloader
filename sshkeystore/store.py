import getpass
import subprocess
import glob
import os.path
import stat

from . import keys

KEY_SUFFIX = '.key.gpg'


class Keystore:
    @classmethod
    def get_default_store(cls):
        return cls('~/.ssh-keystore')

    def __init__(self, path):
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isdir(path):
            os.mkdir(path, stat.S_IRWXU)  # 0o700
        self.store = path

    def get(self, name):
        keypath = self._namepath(name)
        if not os.path.exists(keypath):
            return None
        return keys.Keypair(keypath, name)

    def addkey(self, name, key):
        keypath = self._namepath(name)
        if not len(key):
            raise ValueError("Invalid key length: 0")
        try:
            subprocess.run(
                [
                    'gpg2',
                    '--quiet',
                    '--batch',
                    '--compress-algo=none',
                    '--no-encrypt-to',
                    '--encrypt',
                    '--output',
                    keypath,
                ]
                + [arg for kid in self._key_ids() for arg in ('--recipient', kid)],
                check=True,
                input=key,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Encryption error: {e.stdout.decode().rstrip()}") from e

    def _key_ids(self):
        with open(os.path.join(self.store, '.gpg-id'), 'r') as f:
            return [kid.strip() for kid in f]

    def _namepath(self, name):
        path = os.path.split(name)
        if path[0]:
            raise ValueError(f"'{name}' contains a path separator")
        elif not path[1]:
            raise ValueError(f"'name' is empty")
        return os.path.join(self.store, path[1] + KEY_SUFFIX)

    def __iter__(self):
        return (
            keys.Keypair(keypath)
            for keypath in glob.iglob(os.path.join(self.store, '*' + KEY_SUFFIX))
        )


class PubdirStore:
    @classmethod
    def get_default_store(cls):
        if 'KEYLOADER_PUBKEY_PATH' in os.environ:
            path = os.environ['KEYLOADER_PUBKEY_PATH']
        else:
            path = f'/tmp/ssh-keystore-pub_{getpass.getuser()}'
        return cls(path)

    def __init__(self, path):
        path = os.path.abspath(path)
        try:
            info = os.stat(path)
        except FileNotFoundError:
            os.mkdir(path, stat.S_IRWXU)  # 0o700
            os.chmod(path, stat.S_IRWXU)  # in case mkdir() doesn't set the mode
            info = os.stat(path)  # get final stats for next checks
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"'{path}' is not a directory")
        if info.st_uid != os.getuid():
            raise RuntimeError(f"'{path}' is owned by another user")
        # only traversal permissions are allowed for others
        if stat.S_IMODE(info.st_mode) & ~(stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH):
            raise RuntimeError(f"'{path}' has unsafe permissions")
        self.store = path

    def add(self, name, pubkey):
        path = os.path.split(name)
        if path[0]:
            raise ValueError(f"'{name}' contains a path separator")
        elif not path[1]:
            raise ValueError(f"'name' is empty")
        with open(os.path.join(self.store, f'{path[1]}.pub'), 'w') as f:
            fno = f.fileno()
            info = os.stat(fno)
            # remove write and execute permissions for others
            newmode = stat.S_IMODE(info.st_mode) & (
                stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH  # 0o744
            )
            os.chmod(fno, newmode)
            f.write(pubkey)
