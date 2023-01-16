# sshkeystore
Manage a directory of GPG encrypted SSH keys

## Internals
sshkeystore takes private SSH keys, removes passwords if necessary, encrypts them with GPG, and then
puts them as files in a store directory (`~/.sshkeystore` by default). The store is designed similarly
to the `pass` utility, and is intended to be synced between computers via `git`.

When keys are `load`ed, the decrypted private keys are added the active SSH agent. They are inserted into
the agent over a pipe to avoid storing the descrypted private key on disk. Since there can be many keys
in an agent, the corresponding public keys are generated and stored as files in a well-known directory
(`/tmp/sshkeystore-pub_$USER` by default). These files can then be passed to SSH as an identity file to
load the matching key. Under normal circumstances SSH expects identity files to be a private key, but if
given a public key it will try and find the corresponding private key in the same directory. In this case,
there are no matching private keys to be found, however, we are able to exploit the fact that SSH checks
the running SSH agent for matching keys before trying to load keys from disk. This allows us to specify the
private key to use without actually having to have the private key on disk.

## Usage
```
usage: sshks [-h] [-S STORE] [-P PUBDIR] [-V] {list,load,loadall,insert} ...

Manage a directory of GPG encrypted SSH keys

options:
  -h, --help            show this help message and exit
  -S STORE, --store STORE
                        location of the encrypted keystore
  -P PUBDIR, --pubdir PUBDIR
                        temporary location to store the corresponding public keys
  -V, --version         show program's version number and exit

subcommands:
  choose an action to perform

  {list,load,loadall,insert}
    list                lists all keys in the keystore (DEFAULT)
    load                loads a single key into the agent
    loadall             loads all keys in the keystore into the agent
    insert              encrypts a SSH private key and inserts it into the keystore
```
