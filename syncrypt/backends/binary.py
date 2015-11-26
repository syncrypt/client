from .base import StorageBackend
import time
import asyncio
import logging

logger = logging.getLogger(__name__)

class BinaryStorageBackend(StorageBackend):
    def __init__(self, vault, auth='foo', host='127.0.0.1', port=1337):
        self.host = host
        self.port = port
        self.auth = auth
        self.buf_size = 10 * 1024
        super(BinaryStorageBackend, self).__init__(vault)

    @asyncio.coroutine
    def open(self):
        pass

    @asyncio.coroutine
    def upload(self, bundle):
        logger.info('Uploading %s', bundle)
        reader, writer = \
                yield from asyncio.open_connection(self.host, self.port)

        writer.write('AUTH:{0}\r\n'
                .format(self.auth)
                .encode(self.vault.config.encoding))
        yield from writer.drain()

        line = yield from reader.readline()
        if line != b'SUCCESS\r\n':
            raise Exception(line)

        # upload key and file
        writer.write('UPLOAD:{0.store_hash}:{0.key_size_crypt}:{0.file_size_crypt}\r\n'
                .format(bundle)
                .encode(self.vault.config.encoding))
        yield from writer.drain()

        line = yield from reader.readline()
        if line != b'WAITING\r\n':
            raise Exception(line)

        with open(bundle.path_key, 'rb') as f:
            while f.tell() < bundle.key_size_crypt:
                buf = f.read(self.buf_size)
                writer.write(buf)
                yield from writer.drain()

        with open(bundle.path_crypt, 'rb') as f:
            while f.tell() < bundle.file_size_crypt:
                buf = f.read(self.buf_size)
                writer.write(buf)
                yield from writer.drain()

        line = yield from reader.readline()
        if line != b'SUCCESS\r\n':
            raise Exception(line)

        writer.write(b'DISCONNECT\r\n')
        yield from writer.drain()
