from abc import abstractmethod

from typing_extensions import Protocol

from syncrypt.models import Revision, Vault


class StorageBackend(Protocol):
    vault = None # type: Vault

    def __init__(self, vault):
        self.vault = vault
        self.connected = False
        self.invalid_auth = False

    def version(self):
        raise NotImplementedError()

    async def open(self):
        raise NotImplementedError()

    @abstractmethod
    async def init(self) -> Revision:
        raise NotImplementedError()

    @abstractmethod
    async def upload(self, bundle) -> Revision:
        raise NotImplementedError()

    async def download(self, bundle):
        raise NotImplementedError()

    async def stat(self, bundle):
        raise NotImplementedError()

    async def upload_identity(self, identity, description=""):
        pass

    async def user_info(self):
        raise NotImplementedError

    async def add_user_vault_key(self, vault, email, identity):
        pass

    async def changes(self, since_rev, to_rev, verbose=False):
        raise NotImplementedError
