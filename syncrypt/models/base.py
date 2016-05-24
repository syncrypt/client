import asyncio
import umsgpack
from syncrypt.pipes import (DecryptRSA_PKCS1_OAEP, EncryptRSA_PKCS1_OAEP, Once,
                            SnappyCompress, SnappyDecompress)


class MetadataHolder:

    @property
    def metadata(self):
        raise NotImplementedError()

    @metadata.setter
    def metadata_setter(self):
        raise NotImplementedError()

    @property
    def identity(self):
        raise NotImplementedError()

    @property
    def serialized_metadata(self):
        return umsgpack.packb(self.metadata)

    def encrypted_metadata_reader(self):
        return Once(self.serialized_metadata) \
                >> SnappyCompress() \
                >> EncryptRSA_PKCS1_OAEP(self.identity.public_key)

    @asyncio.coroutine
    def write_encrypted_metadata(self, stream):
        sink = stream \
                >> DecryptRSA_PKCS1_OAEP(self.identity.private_key) \
                >> SnappyDecompress()
        yield from self.update_serialized_metadata(sink)

    @asyncio.coroutine
    def update_serialized_metadata(self, stream):
        serialized_metadata = yield from stream.read()
        self.metadata = umsgpack.unpackb(serialized_metadata)

