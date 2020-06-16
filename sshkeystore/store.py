import glob
import os.path
import stat

from . import keys

KEY_SUFFIX = '.key.gpg'


class Keystore:
    def __init__(self, path):
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isdir(path):
            os.mkdir(path, stat.S_IRWXU)  # 0o700
        self.store = path

    def get(self, key):
        path = os.path.split(key)
        if path[0]:
            raise ValueError(f"'{key}' contains a path separator")
        elif not path[1]:
            raise ValueError(f"'key' is empty")
        keypath = os.path.join(self.store, path[1] + KEY_SUFFIX)
        if not os.path.exists(keypath):
            return None
        return keys.Keypair(keypath, key)

    def __iter__(self):
        return (
            keys.Keypair(keypath)
            for keypath in glob.iglob(os.path.join(self.store, '*' + KEY_SUFFIX))
        )
