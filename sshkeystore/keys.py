import os.path


class Keypair:
    def __init__(self, keypath, keyname=None):
        if not os.path.isfile(keypath):
            raise FileNotFoundError(
                f"'{keypath}' does not exist or is not a regular file"
            )
        self.keypath = keypath
        self.name = keyname if keyname else os.path.basename(keypath)[:-8]
