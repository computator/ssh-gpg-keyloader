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

    cmd_load = sub.add_parser('load', help="loads a single key into the agent")
    cmd_load.add_argument('key')

    cmd_loadall = sub.add_parser(
        'loadall', help="loads all keys in the keystore into the agent"
    )

    args = parser.parse_args()
    if not args.cmd:
        parser.error("subcommand is required")
    return args


def cli():
    args = parse_args()
    try:
        command = getattr(cmd, args.cmd)
    except AttributeError:
        raise Exception(f"Invalid command '{args.cmd}'")
    command(args)
