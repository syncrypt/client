The Syncrypt Encryption Scheme
==============================

In this document you will find a detailed description on how Syncrypt encrypts
your files, interacts with the server and handles your cryptographic keys.
Remember that you don't have to take our word for it, you can verify the
described scheme with our [GPLv3-licensed client](https://github.com/syncrypt/client).

You should understand the basics of symmetric as well as public key cryptography.


Vaults
------

Syncrypt employs both symmetric and asymmetric encryption to secure your files.
Asymmetric encryption on the level of the vault means that you hold the private
key to the vault and the server will never see it. That keypair will be used to
encrypt vault metadata and file metadata.

Syncrypt uses RSA ... *todo*

The vault metadata protected by the vault key consists of:

    * vault name
    * ...


File encryption
---------------

For the actual encryption of the contents of a file, Syncrypt uses AES, a symmetric
encryption scheme. *todo*

The file metadata (which is also protected by the *vault* key) consists of:

    * file name
    * ....


Sharing files with new users or devices
---------------------------------------

In addition the vault and file keys, Syncrypt also has the concept of user
keys. These keys identify a user (or a device). In order to share a vault with
a new user or a new device, the above mentioned vault keys need to be
transmitted to the new device. This can either be done either

    * manually by exporting and importing the keys or
    * by letting Syncrypt encrypt those key with the public key of the target user or device.

In the latter case, Syncrypt will transmit those encrypted keys over the Syncrypt
server. Note that this step is fully optional and secured by the same strong
public key cryptography that secures your vault in the first place.


Example
-------

...
