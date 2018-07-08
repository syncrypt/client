import logging
import os
from typing import Tuple

from syncrypt.models import Bundle
from syncrypt.pipes import (Buffered, Count, DecryptAES, EncryptAES, FileReader, FileWriter, Hash,
                            PadAES, Pipe, SnappyCompress, SnappyDecompress, UnpadAES)

from .base import CryptEngine

logger = logging.getLogger(__name__)


class AESCBCEngine(CryptEngine):

    def read_encrypted_stream(self, bundle: Bundle) -> Pipe:
        assert not bundle.key is None
        return FileReader(bundle.path) \
                >> SnappyCompress() \
                >> Buffered(bundle.vault.config.enc_buf_size) \
                >> PadAES() \
                >> EncryptAES(bundle.key)

    async def get_crypt_hash_and_size(self, bundle: Bundle) -> Tuple[str, int]:

        # This will calculate the hash of the file contents
        # As such it will never be sent to the server (see below)
        # TODO: check impact of SnappyCompress and PadAES pipes on
        #       performance. Both are only needed for knowing the
        #       file size in upload. If they have a huge impact on
        #       performance, try to change the protocol so that the
        #       stream size does not need to be known inb4 by the
        #       client source.
        hashing_reader = FileReader(bundle.path) \
                    >> Hash(bundle.vault.config.hash_algo)

        counting_reader = hashing_reader \
                    >> SnappyCompress() \
                    >> Buffered(bundle.vault.config.enc_buf_size) \
                    >> PadAES() \
                    >> Count()
        await counting_reader.consume()

        # We add the AES key to the hash so that the hash stays
        # constant when the files is not changed, but the original
        # hash is also not revealed to the server
        assert len(bundle.key) == bundle.key_size
        hash_obj = hashing_reader.hash_obj
        hash_obj.update(bundle.key)

        crypt_hash = hash_obj.hexdigest()

        # Add one time the symmetric block_size to the encrypted file size.
        # This is the length of the IV.
        file_size_crypt = counting_reader.count + \
                bundle.vault.config.block_size

        return crypt_hash, file_size_crypt

    async def write_encrypted_stream(self, bundle: Bundle, stream: Pipe, assert_hash=None):
        hash_pipe = Hash(bundle.vault.config.hash_algo)

        if bundle.key is None:
            await bundle.load_key()

        # Security check against malicious path not inside
        vault_path = os.path.abspath(bundle.vault.folder)
        bundle_path = os.path.abspath(bundle.path)

        if os.path.commonpath([vault_path]) != os.path.commonpath([vault_path, bundle_path]):
            raise AssertionError("Refusing to write to given bundle path: " + bundle_path)

        sink = stream \
                >> Buffered(bundle.vault.config.enc_buf_size, bundle.vault.config.block_size) \
                >> DecryptAES(bundle.key) \
                >> UnpadAES() \
                >> SnappyDecompress() \
                >> hash_pipe \
                >> FileWriter(bundle.path, create_dirs=True, create_backup=True, store_temporary=True)

        await sink.consume()

        hash_obj = hash_pipe.hash_obj
        hash_obj.update(bundle.key)
        received_hash = hash_obj.hexdigest()

        passed = not assert_hash or received_hash == assert_hash

        if not passed:
            logger.error('hash mismatch: {} != {}'.format(assert_hash, received_hash))

        await sink.finalize()

        return passed
