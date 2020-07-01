import getpass
import glob
import os.path
import stat
import subprocess

from . import ssh

KEY_SUFFIX = '.key.gpg'


class KeyLoadError(Exception):
    pass


class Keypair:
    def __init__(self, keypath, keyname=None):
        if not os.path.isfile(keypath):
            raise FileNotFoundError(
                f"'{keypath}' does not exist or is not a regular file"
            )
        self.keypath = keypath
        self.name = (
            keyname if keyname else os.path.basename(keypath)[: -len(KEY_SUFFIX)]
        )
        self._private = None
        self._public = None

    def private(self):
        if self._private:
            return self._private
        try:
            key = subprocess.run(
                ['gpg2', '--quiet', '--batch', '--decrypt', self.keypath],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            self._private = ssh.PrivateKey(key)
            return self._private
        except subprocess.CalledProcessError as e:
            raise KeyLoadError(f"Decryption error: {e.stderr.decode().rstrip()}") from e

    def public(self):
        if not self._public:
            self._public = self.private().get_public(f'sshkeystore:{self.name}')
        return self._public

    def __repr__(self):
        return f"{__class__.__name__}({self.keypath!r}, {self.name!r})"


class Keystore:
    @classmethod
    def get_default_store(cls):
        if 'SSH_KEYSTORE' in os.environ:
            path = os.environ['SSH_KEYSTORE']
        else:
            path = '~/.sshkeystore'
        return cls(path)

    def __init__(self, path):
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isdir(path):
            os.mkdir(path, stat.S_IRWXU)  # 0o700
        self.store = path

    def get(self, name):
        keypath = self._namepath(name)
        if not os.path.exists(keypath):
            return None
        return Keypair(keypath, name)

    def addkey(self, name, key):
        keypath = self._namepath(name)
        if not len(key):
            raise ValueError("Invalid key length: 0")
        if os.path.exists(keypath):
            raise RuntimeError(f"Key '{name}' already exists")
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

    def __contains__(self, name):
        try:
            return os.path.exists(self._namepath(name))
        except Exception:
            return False

    def __iter__(self):
        return (
            Keypair(keypath)
            for keypath in glob.iglob(os.path.join(self.store, '*' + KEY_SUFFIX))
        )


class PubdirStore:
    @classmethod
    def get_default_store(cls):
        if 'KEYSTORE_PUBKEY_PATH' in os.environ:
            path = os.environ['KEYSTORE_PUBKEY_PATH']
        else:
            path = f'/tmp/sshkeystore-pub_{getpass.getuser()}'
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
            f.write(pubkey.rstrip() + '\n')
