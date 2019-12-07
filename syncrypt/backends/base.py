import asyncio  # pylint: disable=unused-import
from abc import abstractmethod
from typing import Any, List, NewType, Optional, Union  # pylint: disable=unused-import

from typing_extensions import Protocol

from syncrypt.models import Bundle, Identity, Revision


class StorageBackend(Protocol):

    def version(self):
        raise NotImplementedError()

    async def open(self):
        raise NotImplementedError()

    @abstractmethod
    def set_auth(self, username: str, password: str):
        raise NotImplementedError()

    @abstractmethod
    def list_keys(self, username: Optional[str] = None):
        raise NotImplementedError()

    @abstractmethod
    async def init(self, identity: Identity) -> Revision:
        raise NotImplementedError()

    @abstractmethod
    async def upload(self, bundle: Bundle, identity: Identity) -> Revision:
        raise NotImplementedError()

    @abstractmethod
    async def list_vaults(self) -> List[Any]: # is this needed at all?
        raise NotImplementedError()

    @abstractmethod
    async def list_vaults_for_identity(self, identity: Identity) -> List[Any]:
        raise NotImplementedError()

    @abstractmethod
    async def set_vault_metadata(self, identity: Identity) -> Revision:
        raise NotImplementedError()

    @abstractmethod
    async def changes(self, since_rev, to_rev):
        raise NotImplementedError

    @abstractmethod
    async def remove_file(self, bundle: Bundle, identity: Identity) -> Revision:
        raise NotImplementedError

    async def download(self, bundle):
        raise NotImplementedError()

    async def upload_identity(self, identity, description=""):
        raise NotImplementedError

    async def user_info(self):
        raise NotImplementedError

    async def add_vault_user(self, user_id: str, identity: Identity):
        raise NotImplementedError

    async def remove_vault_user(self, user_id: str, identity: Identity):
        raise NotImplementedError

    async def add_user_vault_key(self, identity: Identity, user_id: str, user_identity: Identity, vault_key_package: bytes):
        raise NotImplementedError
