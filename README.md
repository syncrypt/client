# Syncrypt platform independent desktop client

## Syncrypt CLI

The ``syncrypt`` executable is the command line client for Syncrypt.

### Let's get started

Initialize the current directory as a vault:

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

### Backup your keys

It is important to store your vault's keys at another place other than your
computer. Otherwise, you won't be able to recover your files in case of a
disk failure. You can create a ZIP file with all necessary information to
decrypt a Vault by typing:

    syncrypt export vault-backup.zip

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

## Installation

Currently requires Python 3.

Install globally:

    pip install .

Setup in virtualenv for development:

    virtualenv .
    bin/pip install -e .

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

In order to rebuild the UI files, you can use the ``build_ui`` command:

    bin/pip install -e '.[dev]'
    bin/python setup.py build_ui

## Deploy

Make Syncrypt distribution package for the current platform:

    bin/pip install -e '.[dist]'
    bin/python setup.py dist
