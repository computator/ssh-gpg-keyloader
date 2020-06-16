import os.path
import subprocess

from . import store


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
            keyname if keyname else os.path.basename(keypath)[: -len(store.KEY_SUFFIX)]
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
            if not key:
                raise KeyLoadError("Invalid key length: 0")
            self._private = key
            return self._private
        except subprocess.CalledProcessError as e:
            raise KeyLoadError(f"Decryption error: {e.stderr.decode().rstrip()}") from e

    def public(self):
        if self._public:
            return self._public
        try:
            key = subprocess.run(
                ['ssh-keygen', '-y', '-f', '/proc/self/fd/0'],
                check=True,
                input=self.private(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            if not key:
                raise KeyLoadError("Invalid key length: 0")
            self._public = f'{key.decode().strip()} sshkeystore:{self.name}'
            return self._public
        except subprocess.CalledProcessError as e:
            raise KeyLoadError(f"Conversion error: {e.stderr.decode().rstrip()}") from e

    def __repr__(self):
        return f"{__class__.__name__}({self.keypath!r}, {self.name!r})"
