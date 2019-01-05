class SyncryptBaseException(Exception):
    status = 500


class FolderExistsAndIsNotEmpty(SyncryptBaseException):
    status = 400

    def __str__(self):
        return "The given folder does already exists and is not empty: {0}".format(
            self.args
        )


class InvalidBundleMetadata(SyncryptBaseException):
    pass


class InvalidBundleKey(SyncryptBaseException):
    pass


class InvalidRevision(SyncryptBaseException):
    pass


class UnexpectedParentInRevision(InvalidRevision):
    pass


class VaultException(SyncryptBaseException):
    pass


class AlreadyPresent(SyncryptBaseException):
    pass


class VaultNotInitialized(VaultException):
    pass


class VaultFolderDoesNotExist(VaultException):
    pass


class VaultAlreadyExists(VaultException):
    pass


class VaultNotFound(VaultException):
    status = 404


class VaultIsAlreadySyncing(VaultException):
    status = 400

    def __str__(self):
        return "The given folder is already in the list of syncing vaults: {0}".format(
            self.args
        )


class InvalidVaultPackage(VaultException):
    status = 400


class BinaryStorageException(SyncryptBaseException):
    pass


class InvalidAuthentification(BinaryStorageException):
    status = 401


class UnsuccessfulResponse(BinaryStorageException):
    status = 400


class ServerError(UnsuccessfulResponse):
    pass


class SyncRequired(ServerError):
    pass


class ConnectionResetException(BinaryStorageException):
    pass


class UnexpectedResponseException(BinaryStorageException):
    pass


class IdentityError(SyncryptBaseException):
    pass


class IdentityStateError(IdentityError):
    status = 400


class IdentityNotInitialized(IdentityStateError):
    status = 401
