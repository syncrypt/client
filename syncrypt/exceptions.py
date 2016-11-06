class SecurityError(Exception):
    pass

class VaultException(Exception):
    pass

class VaultNotInitialized(VaultException):
    pass

class VaultFolderDoesNotExist(VaultException):
    pass
