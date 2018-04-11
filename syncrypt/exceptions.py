class SecurityError(Exception):
    pass


class VaultException(Exception):
    pass


class VaultNotInitialized(VaultException):
    pass


class VaultFolderDoesNotExist(VaultException):
    pass


# the vault already exists on disk
class VaultAlreadyExists(VaultException):
    pass


## Daemon exceptions


class VaultNotFound(ValueError):
    pass


# the vault is already in the daemons list of syncing vaults
class VaultIsAlreadySyncing(ValueError):
    def __str__(self):
        return "The given folder is already in the list of syncing vaults: {0}"\
                .format(self.args[0])
