import sys

from . import store
from .agent import Agent, AgentError
from .keys import KeyLoadError


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
        Agent.addkey(kp.private())
    except AgentError as e:
        print(f"Error adding key '{kp.name}' to agent: {e}", file=sys.stderr)
    except KeyLoadError as e:
        print(f"Error loading key '{kp.name}': {e}", file=sys.stderr)
    else:
        print(f"Added '{kp.name}'")
        try:
            if pubstore:
                pubstore.add(kp.name, kp.public())
        except KeyLoadError as e:
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
            Agent.addkey(kp.private())
        except AgentError as e:
            print(f"Error adding key '{kp.name}' to agent: {e}", file=sys.stderr)
        except KeyLoadError as e:
            print(f"Error loading key '{kp.name}': {e}", file=sys.stderr)
        else:
            print(f"Added '{kp.name}'")
            try:
                if pubstore:
                    pubstore.add(kp.name, kp.public())
            except KeyLoadError as e:
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
