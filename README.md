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
