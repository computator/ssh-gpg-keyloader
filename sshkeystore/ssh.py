import base64
import subprocess
from tempfile import NamedTemporaryFile


class DecryptionError(Exception):
    pass


class PassphraseError(Exception):
    pass


class InvalidKeyError(Exception):
    pass


class PrivateKey:
    WRAP_FMT_STR = b'-----%b %b PRIVATE KEY-----'
    OLD_FORMATS = {
        b'RSA': 'rsa',
        b'DSA': 'dsa',
        b'EC': 'ecdsa',
    }
    NEW_FORMAT = b'OPENSSH'
    NEW_FORMAT_INT_HDR = b'openssh-key-v1\x00'
    NEW_FORMAT_TYPES = {
        b'ssh-rsa': 'rsa',
        b'ssh-dss': 'dsa',
        b'ecdsa-sha2-nistp256': 'ecdsa',
        b'ssh-ed25519': 'ed25519',
    }

    def __init__(self, keydata):
        if not isinstance(keydata, bytes):
            raise TypeError(f"'keydata' must be type bytes")
        self.rawkey = keydata
        self.datafmt = None
        self.headers = {}
        self.type = None
        self.keyinner = None
        self.encrypted = False
        self._public = None
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
            self._parsekey_newfmt()
        else:
            self._parsekey_oldfmt()

    def _parsekey_newfmt(self):
        keydata = self.keyinner
        if not keydata.startswith(self.NEW_FORMAT_INT_HDR):
            raise ValueError("Unrecognized OpenSSH key format")
        keydata = keydata[len(self.NEW_FORMAT_INT_HDR) :]
        params = {}
        # get the 3 encryption headers
        for f in 'cipher', 'kdf', 'kdfargs':
            n, keydata = int.from_bytes(keydata[:4], 'big'), keydata[4:]
            params[f], keydata = keydata[:n], keydata[n:]
        # skip past keycount
        keydata = keydata[4:]
        # get the pubkey block
        n, keydata = int.from_bytes(keydata[:4], 'big'), keydata[4:]
        pubdata, keydata = keydata[:n], keydata[n:]
        # get keytype from pubkey block
        n, pubdata = int.from_bytes(pubdata[:4], 'big'), pubdata[4:]
        params['keytype'], pubdata = pubdata[:n], pubdata[n:]
        self.type = self.NEW_FORMAT_TYPES.get(params['keytype'], params['keytype'])
        self.encrypted = params['cipher'] != b'none'

    def _parsekey_oldfmt(self):
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
                    raise DecryptionError(
                        f"Error removing passphrase: {e.stderr.decode().rstrip()}"
                    ) from e
            else:
                raise PassphraseError("Incorrect passphrase entered 3 times")
            kf.seek(0)
            decrypted = kf.read()
        try:
            new = self.__class__(decrypted)
        except Exception as e:
            raise InvalidKeyError(f"Invalid decrypted key: {e}") from e
        else:
            if new.encrypted:
                raise DecryptionError("Resulting key is still encrypted")
            return new

    def get_public(self):
        if self._public:
            return self._public
        try:
            key = subprocess.run(
                ['ssh-keygen', '-y', '-f', '/proc/self/fd/0'],
                check=True,
                input=self.rawkey if not self.encrypted else self.decrypt().rawkey,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            if not key:
                raise InvalidKeyError("Invalid key length: 0")
            self._public = key.decode().strip()
            return self._public
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Conversion error: {e.stderr.decode().rstrip()}") from e


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
