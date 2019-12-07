import umsgpack
from sqlalchemy.ext.declarative import declarative_base

from syncrypt.pipes import (DecryptRSA_PKCS1_OAEP, EncryptRSA_PKCS1_OAEP, Once, SnappyCompress,
                            SnappyDecompress)

Base = declarative_base()


class MetadataHolder:

    @property
    def _metadata(self):
        raise NotImplementedError()

    @_metadata.setter  # type: ignore
    def _metadata_setter(self):
        raise NotImplementedError()

    @property
    def identity(self):
        raise NotImplementedError()

    @property
    def serialized_metadata(self):
        return umsgpack.packb(self._metadata)

    def unserialize_metadata(self, serialized_metadata):
        return umsgpack.unpackb(serialized_metadata)

    def encrypted_metadata_reader(self):
        return (
            Once(self.serialized_metadata)
            >> SnappyCompress()
            >> EncryptRSA_PKCS1_OAEP(self.identity.public_key)
        )

    def encrypted_metadata_decoder(self, stream):
        return (
            stream
            >> DecryptRSA_PKCS1_OAEP(self.identity.private_key)
            >> SnappyDecompress()
        )

    async def decrypt_metadata(self, metadata):
        sink = self.encrypted_metadata_decoder(Once(metadata))
        serialized_metadata = await sink.read()
        return umsgpack.unpackb(serialized_metadata)

    async def write_encrypted_metadata(self, stream):
        sink = self.encrypted_metadata_decoder(stream)
        await self.update_serialized_metadata(sink)

    async def update_serialized_metadata(self, stream):
        serialized_metadata = await stream.read()
        self._metadata = self.unserialize_metadata(serialized_metadata)  # type: ignore
