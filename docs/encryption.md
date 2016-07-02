Syncrypt Encryption
===================

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
encrypt *file* metadata and *vault* metadata.

Currently, the vault metadata protected by the vault key solely consists of

 * the vault name.

By default, Syncrypt uses 4096 bit RSA keys.

File encryption
---------------

For the actual encryption of the contents of a file, Syncrypt uses AES, a symmetric
encryption algorithm. The AES key is part of the file metadata and is protected
by the vault key.

What is sent to the server when a file is uploaded?

 * SHA-256 Hash of the file path
 * Message Authentication Code (MAC), see *Authenticated Encryption* below
 * File metadata (which is also protected by the *vault* key):
   * file name and path
   * AES key
 * Encrypted file contents

Prior to the encryption, the file content is compressed using [snappy](http://google.github.io/snappy/).

Authenticated Encryption
------------------------

To ensure data integrity, Syncrypt uses a Message Authentication Code (MAC) for
each file revision. This code is basically the SHA-256 hash of the plaintext file
contents and the file's AES key. In Authenticated Encryption, this is known as
*Encrypt-and-MAC*. We might change the AE protocol to *Encrypt-then-MAC* in the
future, because it has been proven more robust.

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

In this section you can find a description of all files that are created by the
Syncrypt client and what they are used for.

Lets say you've created a vault and also pushed some files. To see all files that
Syncrypt uses for this vault, simply type

    find .vault

in the vault's directory. It should give you a list of files like this:

    .vault
    .vault/metadata
    .vault/metadata/ac
    .vault/metadata/ac/7599eb8787664eb1c45b915539f7d3eb2dd796eecf24b919ce9b5b80d930ed
    .vault/metadata/36
    .vault/metadata/36/65d65394f4f58a56a256ad6dd8621c68118d90fe56a19387e251c19cec2d2e
    .vault/metadata/7d
    .vault/metadata/7d/72b25977fd4b48208b8242906a307d477d7d5b26b655cd2c80fb6f12cf7e5f
    .vault/config
    .vault/id_rsa
    .vault/id_rsa.pub

If you are familiar with SSH keys, you should recognise the keypair ``id_rsa``
and ``id_rsa.pub``. These files are the private and public key to this vault,
respectively. The ``config`` file contains such information as the vault's name,
ID and files to ignore.

In the folder ``.vault/metadata`` the metadata of all files is stored. As
mentioned above, we will identify a file by the SHA-256 hash of its file name. This
hash is also the filename in the metadata folder. In this metadata, you can find
the AES key and the actual filename of the file.

