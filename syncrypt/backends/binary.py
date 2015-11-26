import logging
import time

import asyncio
import umsgpack

from .base import StorageBackend

logger = logging.getLogger(__name__)

class BinaryStorageConnection(object):
    def __init__(self, storage):
        self.storage = storage

    @asyncio.coroutine
    def __enter__(self):
        self.reader, self.writer = \
                yield from asyncio.open_connection(self.storage.host,
                                                   self.storage.port)

        self.writer.write('AUTH:{0}\r\n'
                .format(self.storage.auth)
                .encode(self.storage.vault.config.encoding))
        yield from self.writer.drain()

        line = yield from self.reader.readline()
        if line != b'SUCCESS\r\n':
            raise Exception(line)

        return self

    def __exit__(self, *args):

        self.writer.write(b'DISCONNECT\r\n')
        yield from self.writer.drain()

        self.writer.close()


class BinaryStorageBackend(StorageBackend):

    def __init__(self, vault, auth='foo', host='127.0.0.1', port=1337, concurrency=4):
        self.host = host
        self.port = port
        self.auth = auth
        self.buf_size = 10 * 1024
        self.concurrency = int(concurrency)
        self.upload_sem = asyncio.Semaphore(value=self.concurrency)
        super(BinaryStorageBackend, self).__init__(vault)

    @asyncio.coroutine
    def open(self):
        pass

    @asyncio.coroutine
    def stat(self, bundle):
        yield from self.upload_sem.acquire()
        try:
            yield from self._stat(bundle)
        finally:
            self.upload_sem.release()

    @asyncio.coroutine
    def _stat(self, bundle):
        logger.info('Stat %s', bundle)

        with BinaryStorageConnection(self) as conn:
            conn = yield from conn
            conn.writer.write('STAT:{0.store_hash}\r\n'
                    .format(bundle)
                    .encode(self.vault.config.encoding))
            yield from conn.writer.drain()

            line = yield from conn.reader.readline()
            try:
                byte_count = int(line)
            except TypeError:
                print("File not found")

            msg = yield from conn.reader.read(byte_count)
            print (umsgpack.loads(msg))

    @asyncio.coroutine
    def upload(self, bundle):
        yield from self.upload_sem.acquire()
        try:
            yield from self._upload(bundle)
        finally:
            self.upload_sem.release()

    @asyncio.coroutine
    def _upload(self, bundle):

        logger.info('Uploading %s', bundle)

        assert bundle.uptodate

        with BinaryStorageConnection(self) as conn:
            conn = yield from conn

            # upload key and file
            conn.writer.write('UPLOAD:{0.store_hash}:{0.key_size_crypt}:{0.file_size_crypt}:{0.crypt_hash}\r\n'
                    .format(bundle)
                    .encode(self.vault.config.encoding))
            yield from conn.writer.drain()

            line = yield from conn.reader.readline()
            if line != b'WAITING\r\n':
                raise Exception(line)

            with open(bundle.path_key, 'rb') as f:
                while f.tell() < bundle.key_size_crypt:
                    buf = f.read(self.buf_size)
                    conn.writer.write(buf)
                    yield from conn.writer.drain()

            with open(bundle.path_crypt, 'rb') as f:
                while f.tell() < bundle.file_size_crypt:
                    buf = f.read(self.buf_size)
                    conn.writer.write(buf)
                    yield from conn.writer.drain()

            line = yield from conn.reader.readline()
            if line != b'SUCCESS\r\n':
                raise Exception(line)
