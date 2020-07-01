import argparse

from . import cmd


def parse_args():
    parser = argparse.ArgumentParser(
        description="Manage a directory of GPG encrypted SSH keys"
    )
    parser.add_argument('-S', '--store', help="location of the encrypted keystore")
    parser.add_argument(
        '-P',
        '--pubdir',
        help="temporary location to store the corresponding public keys",
    )
    sub = parser.add_subparsers(dest='cmd', description="choose an action to perform")

    # list
    sub.add_parser('list', help="lists all keys in the keystore (DEFAULT)")

    # load
    cmd_load = sub.add_parser('load', help="loads a single key into the agent")
    cmd_load.add_argument(
        'keys', nargs='+', metavar="keyname", help="the name of the key to load"
    )

    # loadall
    sub.add_parser('loadall', help="loads all keys in the keystore into the agent")

    # insert
    cmd_insert = sub.add_parser(
        'insert', help="encrypts a SSH private key and inserts it into the keystore"
    )
    cmd_insert.add_argument('name', help="the name to store the key as")
    cmd_insert.add_argument(
        'keyfile',
        type=argparse.FileType('rb'),
        help="the SSH private key file to insert",
    )

    args = parser.parse_args()
    if not args.cmd:
        args.cmd = 'list'
    return args


def cli():
    args = parse_args()
    try:
        command = getattr(cmd, args.cmd)
    except AttributeError:
        raise Exception(f"Invalid command '{args.cmd}'")
    command(args)
