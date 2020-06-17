import subprocess
import sys

from . import store
from .keys import KeyLoadError


def cli():
    try:
        pubstore = store.PubdirStore.get_default_store()
    except Exception as e:
        pubstore = None
        print(f"Error getting PubdirStore: {e}")
    for kp in store.Keystore.get_default_store():
        try:
            output = subprocess.run(
                ['ssh-add', '-k', '-q', '-'],
                check=True,
                input=kp.private(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ).stdout
            if output != b'Identity added: (stdin) ((stdin))\n':
                sys.stderr.write(output.decode())
        except subprocess.CalledProcessError as e:
            print(f"{e}\nError adding private key '{kp.name}' to agent")
        except KeyLoadError as e:
            print(f"Error loading key '{kp.name}': {e}")
        else:
            print(f"Added '{kp.name}'")
            try:
                if pubstore:
                    pubstore.add(kp.name, kp.public())
            except KeyLoadError as e:
                print(f"Error loading public key for '{kp.name}': {e}")
