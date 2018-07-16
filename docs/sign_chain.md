# Sign chain (draft)

## Integrity

The Syncrypt protocol employs a chain of all transactions for each Vault. This chain is a
merkle-tree and each new transaction is signed by the sender. This way, each client can verify
the history of the vault and a malicious server can not spoof transactions or files.

## Web of trust

Besides the vault history, the chain can be used to establish a web of trust between all invited
users of the vault. Because the transaction of each newly added user key is signed, the added key
is from then on trusted by all other participants and can thus be used to sign transactions.

## Transaction types

A technical description of all transaction types follows. In the current implementation the User ID
is the user's email.

### Create Vault

The genesis transaction for each vault. It is signed by the vault creator. The user's public key is
added to the trusted key list for this vault.

Signed contents: ``"OP_CREATE_VAULT"``, Vault public key, User public key

### Set Metadata

The signing user made changes to the vault metadata, such as the vault name.

Signed contents: ``"OP_SET_METADATA"``, Encrypted Vault Metadata

### Upload Revision

The signing user uploaded a new file or a new revision for an existing file.

Signed contents: ``"OP_UPLOAD"``, Hash of encrypted filename, Hash of encrypted blob, Encrypted File Metadata, file size of
encrypted blob

### Delete File

Signed contents: ``"OP_DELETE_FILE"``, Hash of encrypted filename

### Add User

Signed contents: ``"OP_ADD_USER"``, User ID

### Add User Vault Key

Signed contents: ``"OP_ADD_USER_KEY"``, User ID, User Public Key

## Example

* Alice creates a new vault thus creates a new *Create Vault* message including her public key.
* Alice adds a *Set Metadata* transaction to the chain.
* Alice adds an *Add User* message with Bobs user ID.
* Alice adds an *Add User vault Key* message with Bobs key for Machine #1.
* Alice adds an *Add User vault Key* message with Bobs key for Machine #2.
* Bob uploads a file from machine #2 and thus adds a *Upload revision* message.

Every user who has access to this vault sign chain can now verify each transaction and can be sure
that the uploaded file is the intended file (as long as the user machines are not comprised). Even
the Syncrypt server can not add items to the chain, only users that have been added by Alice or
other authorized accounts can add transactions.
