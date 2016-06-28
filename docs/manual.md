# Syncrypt Client Manual

## Basics

Initialize current directory as a vault:

    syncrypt init

Encrypt and push all files in this directory to the server:

    syncrypt push

To retrieve files from Syncrypt, simply write:

    syncrypt pull

Print out vault information via:

    syncrypt info

You can also give your vault a name. This name will be visible to other users
of the vault as well, but not to anyone else. To set a new name, use:

    syncrypt set vault.name "My Library"
    syncrypt push

## Securely share your vault

In order to share your vault with another user, use:

    syncrypt add-user mail@example.org

This command will add the user to the vault. To safely transfer the vault's
key to the target user or device, the command will ask the Syncrypt server
for all keys of this user. Syncrypt will ask you then to verify each
fingerprint (for example by using an already trusted external communication
channel).

Only if you are sure about the matching fingerprints, proceed by typing ``y``.
Syncrypt will now create a package containing the vault keys and encrypt this
package with the public key of the target device. This encrypted package will
then be sent to the new user or device through the Syncrypt server.

If you don't see any fingerprints of the target user, make sure that the other
user has uploaded at least one public key. The public keys for a device will
get uploaded after a successful ``login`` (see above) or by typing:

    syncrypt keys --upload

## Backup your keys

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

## Advanced Usage

Watch current directory (this is like a daemon running the foreground as it
also provides the HTTP interface):

    syncrypt watch

For each command listed above, alternate directories can be specified with
``-d``, like:

    syncrypt -d ~/myfolder watch

Debug logging can be activated via ``-l DEBUG``.
