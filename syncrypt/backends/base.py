import asyncio  # pylint: disable=unused-import
from abc import abstractmethod
from typing import NewType, Union  # pylint: disable=unused-import

from typing_extensions import Protocol

from syncrypt.models import Bundle, Identity, Revision

RevisionQueue = NewType("RevisionQueue", "asyncio.Queue[Union[Revision, None]]")


class StorageBackend(Protocol):

    def version(self):
        raise NotImplementedError()

    async def open(self):
        raise NotImplementedError()

    @abstractmethod
    def set_auth(self, username: str, password: str):
        raise NotImplementedError()

    @abstractmethod
    async def init(self, identity: Identity) -> Revision:
        raise NotImplementedError()

    @abstractmethod
    async def upload(self, bundle: Bundle, identity: Identity) -> Revision:
        raise NotImplementedError()

    @abstractmethod
    async def set_vault_metadata(self, identity: Identity) -> Revision:
        raise NotImplementedError()

    @abstractmethod
    async def changes(self, since_rev, to_rev) -> RevisionQueue:
        raise NotImplementedError

    @abstractmethod
    async def delete_file(self, bundle: Bundle, identity: Identity) -> Revision:
        raise NotImplementedError

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
