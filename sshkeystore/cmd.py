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
    kp = privstore.get(args.keyname)
    if not kp:
        sys.exit(f"Key '{args.keyname}' not found!")
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
    privstore.addkey(args.name, args.keyfile.read())


def list(args):
    privstore = (
        store.Keystore(args.store) if args.store else store.Keystore.get_default_store()
    )
    for kp in privstore:
        print(kp.name)
