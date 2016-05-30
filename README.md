# Syncrypt client

Syncrypt is a fully encrypted file storage service for groups and private
backups. This is the client that you can use to store and retrieve files.
The client will also do all encryption.

## Installation

Option 1: Download one of the distribution packages:

* OS X (*TBD*)
* Linux (*TBD*)
* Windows (*TBD*)

Option 2: Install from PyPI (*TBD*)

    pip install syncrypt-client

Option 3: Install from source:

    pip install git+https://github.com/syncrypt/client

## Let's get started

The ``syncrypt`` executable is the command line client for Syncrypt. Initialize
the current directory as a vault:

    syncrypt init

This will ask for the email and the password of your Syncrypt account. If you
do not have an account yet, please sign up for our closed alpha mailing list
and we might sent you an invite.

After you've set up the directory, you can push all of its contents by typing:

    syncrypt push

To retrieve files from Syncrypt, simply write:

    syncrypt pull

Print out vault information:

    syncrypt info

You can also give your vault a name. This name will be visible to other users
of the vault as well, but not to anyone else. To set a new name, use:

    syncrypt set vault.name "My Library"
    syncrypt push

### Securely share your vault

In order to share your vault with another user, use:

    syncrypt add-user mail@example.org

This command will add the user to the vault. To safely transfer the vault's
private key to the user, the command will also download the user's public
keys and encrypt the vault information with it. The package will then be
send to the new user over the Syncrypt server. Note that the server will
never be able to see the vault's private key.

Make sure that the other user has uploaded at least one public key. The public
keys get uploaded automatically after a successful ``init`` (see above) or via:

    syncrypt keys --upload

### Backup your keys

It is important to store your vault's keys at another place other than your
computer. Otherwise, you won't be able to recover your files in case of a
disk failure. You can create a ZIP file with all necessary information to
decrypt a Vault by typing:

    syncrypt export -o vault-backup.zip

It is recommened to save this file on an USB stick or a similar not-connected
storage and keep it at a safe place.

If you want to share your vault with another person, they need to get this
file as well.

In order to restore a backup or download your vault on another machine, copy
this file into an empty folder, and type:

    unzip vault-backup.zip
    syncrypt init
    syncrypt pull

### Advanced Usage

Watch current directory (this is like a daemon running the foreground as it
also provides the HTTP interface):

    syncrypt watch

For each command listed above, alternate directories can be specified with
``-d``, like:

    syncrypt -d ~/myfolder watch

Debug logging can be activated via ``-l DEBUG``.


## Syncrypt Daemon

The ``syncrypt_daemon`` is a daemon script for UNIX-like systems. It provides
a HTTP API through which it can be queried and commanded to take action.

Run the daemon:

     syncrypt_daemon

Query statistics:

     curl http://127.0.0.1:28080/v1/stats

Query all vaults:

     curl http://127.0.0.1:28080/v1/vault/

Add a vault (current directory in this example):

    curl -X PUT -d $PWD 'http://127.0.0.1:28080/v1/vault/'

## Tests

Run tests:

    bin/pip install -e '.[test]'
    bin/python setup.py test

## Develop

Setup in virtualenv for development:

    virtualenv .
    bin/pip install -e '.[dev]'

## Deploy

Make Syncrypt distribution package for the current platform:

    bin/pip install -e '.[dist]'
    bin/python setup.py dist
