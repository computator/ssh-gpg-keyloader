import base64
import subprocess
from tempfile import NamedTemporaryFile


class DecryptionError(Exception):
    pass


class PrivateKey:
    WRAP_FMT_STR = b'-----%b %b PRIVATE KEY-----'
    OLD_FORMATS = {
        b'RSA': 'rsa',
        b'DSA': 'dsa',
        b'EC': 'ecdsa',
    }
    NEW_FORMAT = b'OPENSSH'

    def __init__(self, keydata):
        if not isinstance(keydata, bytes):
            raise TypeError(f"'keydata' must be type bytes")
        self.rawkey = keydata
        self.datafmt = None
        self.headers = {}
        self.type = None
        self.keyinner = None
        self.encrypted = False
        self._parsekey()

    def _parsekey(self):
        keydata = self.rawkey.strip()
        for fmt in list(self.OLD_FORMATS) + [self.NEW_FORMAT]:
            if keydata.startswith(self.WRAP_FMT_STR % (b'BEGIN', fmt)):
                if not keydata.endswith(self.WRAP_FMT_STR % (b'END', fmt)):
                    ValueError("Malformed key")
                self.datafmt = fmt
                break
        else:
            raise ValueError("Unrecognized key format")
        start, end = [
            len(self.WRAP_FMT_STR % (p, self.datafmt)) for p in (b'BEGIN', b'END')
        ]
        keydata = keydata[start:-end].strip()
        splitkey = keydata.partition(b'\n\n')
        if splitkey[2]:
            keydata = splitkey[2]
            self.headers = {
                k.lower(): v.strip() if v else None
                for k, _, v in [hdr.partition(b':') for hdr in splitkey[0].splitlines()]
            }
        else:
            keydata = splitkey[0]
            self.headers = {}
        self.keyinner = base64.b64decode(keydata)

        if self.datafmt == self.NEW_FORMAT:
            raise NotImplementedError
        else:
            self.type = self.OLD_FORMATS[self.datafmt]
            encrypted = False
            if b'proc-type' in self.headers:
                fmt, _, val = self.headers[b'proc-type'].partition(b',')
                if int(fmt) != 4:
                    raise ValueError("Unsupported PEM Proc-Type version")
                if val.strip() == b'ENCRYPTED':
                    encrypted = True
            self.encrypted = encrypted

    def decrypt(self):
        if not self.encrypted:
            return
        with NamedTemporaryFile() as kf:
            kf.write(self.rawkey)
            kf.flush()
            for i in range(3):
                try:
                    subprocess.run(
                        ['ssh-keygen', '-p', '-f', kf.name, '-N', ''],
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                    )
                    break
                except subprocess.CalledProcessError as e:
                    if b'incorrect passphrase' in e.stderr:
                        continue
                    raise RuntimeError(
                        f"Error removing passphrase: {e.stderr.decode().rstrip()}"
                    ) from e
            else:
                raise DecryptionError("Too many failed password attempts")
            kf.seek(0)
            decrypted = kf.read()
        try:
            new = self.__class__(decrypted)
        except Exception as e:
            raise RuntimeError(f"Invalid decrypted key: {e}") from e
        else:
            if new.encrypted:
                raise DecryptionError("Resulting key is still encrypted")
            return new


class AgentError(Exception):
    pass


class Agent:
    @staticmethod
    def addkey(key):
        try:
            output = subprocess.run(
                ['ssh-add', '-k', '-q', '-'],
                check=True,
                input=key,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ).stdout
            if output != b'Identity added: (stdin) ((stdin))\n':
                raise AgentError(f"Unexpected output: {output.decode().rstrip()}")
        except subprocess.CalledProcessError as e:
            raise AgentError(f"Add error: {e.stdout.decode().rstrip()}") from e