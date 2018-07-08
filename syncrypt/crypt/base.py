from abc import abstractmethod
from typing import Tuple

from typing_extensions import Protocol

from syncrypt.models import Bundle
from syncrypt.pipes import Pipe


class CryptEngine(Protocol):

    async def get_crypt_hash_and_size(self, bundle: Bundle) -> Tuple[str, int]:
        raise NotImplementedError()

    @abstractmethod
    def read_encrypted_stream(self, bundle: Bundle) -> Pipe:
        raise NotImplementedError()

    @abstractmethod
    async def write_encrypted_stream(self, bundle: Bundle, stream: Pipe, assert_hash=None):
        raise NotImplementedError()
