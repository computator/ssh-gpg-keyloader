import sys

from . import ssh
from . import store


def load(args):
    try:
        pubstore = (
            store.PubdirStore(args.pubdir)
            if args.pubdir
            else store.PubdirStore.get_default_store()
        )
    except Exception as e:
        pubstore = None
        print(f"Error getting PubdirStore: {e}", file=sys.stderr)
    privstore = (
        store.Keystore(args.store) if args.store else store.Keystore.get_default_store()
    )
    failed = False
    for key in args.keys:
        try:
            kp = privstore.get(key)
        except ValueError as e:
            print(f"Invalid key '{key}': {e}", file=sys.stderr)
            failed = True
            continue
        if not kp:
            print(f"Key '{key}' not found!", file=sys.stderr)
            failed = True
            continue
        try:
            ssh.Agent.addkey(kp.private())
            print(f"Added '{kp.name}'")
            if pubstore:
                try:
                    pubstore.add(kp.name, kp.public())
                except store.KeyLoadError as e:
                    print(
                        f"Error loading public key for '{kp.name}': {e}",
                        file=sys.stderr,
                    )
        except ssh.AgentError as e:
            print(f"Error adding key '{kp.name}' to ssh.Agent: {e}", file=sys.stderr)
            failed = True
        except store.KeyLoadError as e:
            print(f"Error loading key '{kp.name}': {e}", file=sys.stderr)
            failed = True
    if failed:
        sys.exit(1)


def loadall(args):
    try:
        pubstore = (
            store.PubdirStore(args.pubdir)
            if args.pubdir
            else store.PubdirStore.get_default_store()
        )
    except Exception as e:
        pubstore = None
        print(f"Error getting PubdirStore: {e}", file=sys.stderr)
    privstore = (
        store.Keystore(args.store) if args.store else store.Keystore.get_default_store()
    )
    for kp in privstore:
        try:
            ssh.Agent.addkey(kp.private())
        except ssh.AgentError as e:
            print(f"Error adding key '{kp.name}' to ssh.Agent: {e}", file=sys.stderr)
        except store.KeyLoadError as e:
            print(f"Error loading key '{kp.name}': {e}", file=sys.stderr)
        else:
            print(f"Added '{kp.name}'")
            try:
                if pubstore:
                    pubstore.add(kp.name, kp.public())
            except store.KeyLoadError as e:
                print(f"Error loading public key for '{kp.name}': {e}", file=sys.stderr)


def insert(args):
    privstore = (
        store.Keystore(args.store) if args.store else store.Keystore.get_default_store()
    )
    if args.name in privstore:
        sys.exit(f"'{args.name}' is already in the store!")
    try:
        pk = ssh.PrivateKey(args.keyfile.read())
    except ValueError as e:
        sys.exit(f"Invalid keyfile: {e}")
    if pk.encrypted:
        print("Key is encrypted, decrypting...")
        try:
            pk = pk.decrypt()
        except ssh.PassphraseError as e:
            sys.exit(e)
        except Exception as e:
            raise RuntimeError(f"Error decrypting key: {e}") from e
    privstore.addkey(args.name, pk.rawkey)
    print(f"Successfully added '{args.name}' to the store")


def list(args):
    privstore = (
        store.Keystore(args.store) if args.store else store.Keystore.get_default_store()
    )
    for kp in privstore:
        print(kp.name)
