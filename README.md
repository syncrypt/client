# Syncrypt client

Syncrypt is a fully encrypted file storage service for groups and private
backups. This is the client that you can use to store and retrieve files.
The client will also do all encryption.

The source code for this client is released under the GNU General Public License
Version 3. For more information have a look at the `LICENSE` file in this
directory. Additional information on the GNU GPLv3 can be found here:
http://www.gnu.org/licenses/quick-guide-gplv3.html

## Installation

Option 1: Install from PyPI (requires Python 3)

    pip install syncrypt

This requires the ``snappy-c`` library in order to build the
[python-snappy](https://github.com/andrix/python-snappy) dependency. In Ubuntu,
you can install it with the APT package ``libsnappy-dev``.

Option 2: Download one of the distribution packages:

* OS X (*TBD*)
* Linux (*TBD*)
* Windows (*TBD*)

Option 3: Install from source:

    pip install git+https://github.com/syncrypt/client

## Let's get started

The ``syncrypt`` executable is the command line interface for Syncrypt. You
can login to syncrypt so that you won't have to enter your login for every
command you issue.

    syncrypt login

This will ask for the email and the password of your Syncrypt account. If you
do not have an account yet, please [sign up](https://syncrypt.space/) for our
closed alpha mailing list and we will send you an invite.

You can now initialize an arbitary directory as a vault. Simply change into
this directory using ``cd`` and call:

    syncrypt init

After you've set up the directory, you can push all of its contents by typing:

    syncrypt push

For an extensive description of syncrypt commands, please see the [client
manual](docs/manual.md).

## Further Information

 * [Syncrypt Alpha Signup](https://syncrypt.space/)
 * [Syncrypt Encryption](docs/encryption.md)
 * [Syncrypt CLI Manual](docs/manual.md)
 * [A guide through the Syncrypt client source code](docs/source_guide.md)

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
