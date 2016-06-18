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

To retrieve files from Syncrypt, simply write:

    syncrypt pull

Print out vault information via:

    syncrypt info

You can also give your vault a name. This name will be visible to other users
of the vault as well, but not to anyone else. To set a new name, use:

    syncrypt set vault.name "My Library"
    syncrypt push

### Securely share your vault

In order to share your vault with another user, use:

    syncrypt add-user mail@example.org

This command will add the user to the vault. To safely transfer the vault's
key to the target user or device, the command will ask the Syncrypt server
for all keys of this user. Syncrypt will ask you know to verify each
fingerprint (for example over another communication channel like over the
phone).

Only if you are sure about the matching fingerprints, proceed by typing ``y``.
Syncrypt will now create a package containing the vault keys and encrypt this
package with the public key of the target device. This encrypted package will
then be sent to the new user or device through the Syncrypt server.

If you don't see any fingerprints of the target user, make sure that the other
user has uploaded at least one public key. The public keys for a device will
get uploaded after a successful ``login`` (see above) or by typing:

    syncrypt keys --upload

### Backup your keys

It is important to store your vault's keys at another place other than your
computer. Otherwise, you won't be able to recover your files in case of a
disk failure. We can't give you your keys back if you lose them, since we never
store them on our servers. This is deliberate and to protect your data against
theft and unauthorized access.

You can create a ZIP file with all necessary information to decrypt a Vault by
typing:

    syncrypt export -o vault-backup.zip

We recommend to save this file on a USB stick or a similar disconnected
storage and keep it in a safe place.

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
