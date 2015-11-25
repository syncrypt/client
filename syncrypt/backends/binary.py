from .base import StorageBackend
import time
import asyncio

class BinaryStorageBackend(StorageBackend):
    def __init__(self, vault, auth='foo', host='127.0.0.1', port=1337):
        self.host = host
        self.port = port
        self.auth = auth
        self.encoding = 'utf-8'
        self.buf_size = 10 * 1024
        super(BinaryStorageBackend, self).__init__(vault)

    @asyncio.coroutine
    def open(self):
        self.reader, self.writer = \
                yield from asyncio.open_connection(self.host, self.port)

        self.writer.write('AUTH:{0}\r\n'
                .format(self.auth)
                .encode(self.encoding))
        yield from self.writer.drain()

        line = yield from self.reader.readline()
        if line != b'SUCCESS\r\n':
            raise Exception(line)

    @asyncio.coroutine
    def upload(self, bundle):
        self.writer.write('UPLOAD:{0}\r\n'
                .format(bundle.store_hash)
                .encode(self.encoding))
        yield from self.writer.drain()

        self.writer.write('{0}\r\n'
                .format(bundle.file_size_crypt)
                .encode(self.encoding))
        yield from self.writer.drain()

        with open(bundle.path_crypt, 'rb') as f:
            while f.tell() < bundle.file_size_crypt:
                buf = f.read(self.buf_size)
                self.writer.write(buf)
                yield from self.writer.drain()

