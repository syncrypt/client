import logging
import os
from typing import Tuple

from syncrypt.models import Bundle
from syncrypt.pipes import FileReader, FileWriter, Hash, Pipe

from .base import CryptEngine

logger = logging.getLogger(__name__)


class PlaintextEngine(CryptEngine):

    def read_encrypted_stream(self, bundle: Bundle) -> Pipe:
        return FileReader(bundle.path)

    async def get_crypt_hash_and_size(self, bundle: Bundle) -> Tuple[str, int]:
        hash_pipe = Hash(bundle.vault.config.hash_algo)

        sink = FileReader(bundle.path) >> hash_pipe
        await sink.consume()

        hash_obj = hash_pipe.hash_obj
        stat = os.stat(bundle.path)
        return hash_obj.hexdigest(), stat.st_size

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
