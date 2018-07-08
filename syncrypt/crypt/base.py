import asyncio
from abc import abstractmethod
from typing import NewType, Tuple, Union

from syncrypt.models import Bundle, Identity, Revision, Vault
from syncrypt.pipes import (Buffered, Count, DecryptAES, DecryptRSA_PKCS1_OAEP, EncryptAES,
                            EncryptRSA_PKCS1_OAEP, FileReader, FileWriter, Hash, Once, PadAES, Pipe,
                            SnappyCompress, SnappyDecompress, UnpadAES)
from typing_extensions import Protocol


class CryptEngine(Protocol):

    async def get_crypt_hash_and_size(self, bundle: Bundle) -> Tuple[str, int]:
        raise NotImplementedError()

    @abstractmethod
    def read_encrypted_stream(self, bundle: Bundle) -> Pipe:
        raise NotImplementedError()

    @abstractmethod
    async def write_encrypted_stream(self, bundle: Bundle, stream: Pipe, assert_hash=None):
        raise NotImplementedError()
