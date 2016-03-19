import logging
import ssl
import struct
import time
from getpass import getpass

import asyncio
import bert
from syncrypt.pipes import Limit, StreamReader, Once
from erlastic import Atom

from .base import StorageBackend, StorageBackendInvalidAuth

logger = logging.getLogger(__name__)

class UnsuccessfulResponse(Exception):
    pass

class ConnectionResetException(Exception):
    pass

def rewrite_atoms_dict(bert_dict):
    # Convert a dict with Atom keys to a list of str keys
    # In the future, generalize this to a complete BERT Atom->str
    # rewriter
    return {str(k): v for (k, v) in bert_dict.items()}

class BinaryStorageConnection(object):
    def __init__(self, storage):
        self.storage = storage
        self.available = asyncio.Event()
        self.available.clear()
        self.connected = False
        self.connecting = False
        self.writer = None
        self.reader = None

    def __repr__(self):
        return "<Slot %d %d %d>" % (self.connecting, self.connected, self.available.is_set())

    @asyncio.coroutine
    def read_term(self, assert_ok=True):
        '''reads a BERT tuple, asserts that first item is "ok"'''
        pl_read = (yield from self.reader.read(4))
        if len(pl_read) != 4:
            raise ConnectionResetException()
        pl_tuple = struct.unpack('!I', pl_read)
        packet_length = pl_tuple[0]
        assert packet_length > 0
        packet = yield from self.reader.read(packet_length)
        if len(packet) != packet_length:
            raise ConnectionResetException()
        decoded = bert.decode(packet)
        if assert_ok and decoded[0] != Atom('ok'):
            raise UnsuccessfulResponse(packet)
        return decoded

    @asyncio.coroutine
    def read_response(self, assert_ok=True):
        decoded = yield from self.read_term(assert_ok=True)
        return decoded[1]

    @asyncio.coroutine
    def write_term(self, *term):
        '''write a BERT tuple'''
        packet = bert.encode((Atom(term[0]),) + term[1:])
        packet_length = len(packet)
        assert packet_length > 0
        self.writer.write(struct.pack('!I', packet_length))
        self.writer.write(packet)
        yield from self.writer.drain()

    @asyncio.coroutine
    def connect(self):

        if self.storage.ssl:
            sc = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if self.storage.host == '127.0.0.1' or self.storage.host == 'prod1.syncrypt.space':
                sc.check_hostname = False
                sc.verify_mode = ssl.CERT_NONE
        else:
            sc = None

        logger.debug('Connecting to server %s:%d ssl=%s...', self.storage.host,
                int(self.storage.port), bool(sc))

        self.reader, self.writer = \
                yield from asyncio.open_connection(self.storage.host,
                                                   int(self.storage.port), ssl=sc)

        version_info = yield from self.read_term()
        self.server_version = version_info[1]

        if self.storage.auth:
            yield from self.write_term('auth',
                self.storage.auth)
            response = yield from self.read_term(assert_ok=False)
            if response[0] != Atom('ok'):
                yield from self.disconnect()
                raise StorageBackendInvalidAuth(response)
        else:
            # we don't have auth token yet
            vault = self.storage.vault
            logger.debug('Log into %s...', vault)

            if vault.config.id is None:
                yield from self.write_term('login', self.storage.username,
                        self.storage.password)

                response = yield from self.read_term(assert_ok=False)

                if response[0] != Atom('ok'):
                    yield from self.disconnect()
                    raise StorageBackendInvalidAuth(response)

                key = vault.public_key.exportKey()

                yield from self.write_term('create_vault', str(len(key)))

                response = yield from self.read_term(assert_ok=False)

                if response[0] == Atom('ok'):
                    self.storage.auth = response[2].decode(self.storage.vault.config.encoding)
                    logger.info('Created vault %s', response[1])
                    vault.config.update('remote', {
                        'auth': self.storage.auth
                    })
                    vault.config.update('vault', {
                        'id': response[1].decode(self.storage.vault.config.encoding)
                    })
                    vault.write_config()
                else:
                    yield from self.disconnect()
                    raise StorageBackendInvalidAuth(response)

            else:
                yield from self.write_term('vault_login', self.storage.username,
                        self.storage.password, vault.config.id)

                login_response = yield from self.read_term(assert_ok=False)

                if login_response[0] == Atom('ok') and login_response[1] != '':
                    self.storage.auth = login_response[1].decode(self.storage.vault.config.encoding)
                else:
                    yield from self.disconnect()
                    raise StorageBackendInvalidAuth(login_response[1])

        self.connected = True
        self.connecting = False
        self.available.set()

    @asyncio.coroutine
    def disconnect(self):
        try:
            if self.writer:
                yield from self.write_term('disconnect')
        except ConnectionResetError:
            pass
        finally:
            if self.writer:
                self.writer.close()
                self.writer = None
            self.connected = False
            self.connecting = False
            self.available.set()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.available.set()

    @asyncio.coroutine
    def stat(self, bundle):
        logger.info('Stat %s', bundle)

        yield from self.write_term('stat', bundle.store_hash)

        response = yield from self.read_term()

        return rewrite_atoms_dict(response[1])

    @asyncio.coroutine
    def upload(self, bundle):

        logger.info('Uploading %s', bundle)

        assert bundle.uptodate

        fileinfo = yield from bundle.encrypted_fileinfo_reader().readall()
        fileinfo_size = len(fileinfo)

        # upload key and file
        yield from self.write_term('upload', bundle.store_hash,
                bundle.crypt_hash, fileinfo, bundle.file_size_crypt)

        yield from self.read_term() # make sure server returns 'ok'

        logger.info('Uploading bundle (fileinfo: {0} bytes, content: {1} bytes)'\
                .format(fileinfo_size, bundle.file_size_crypt))

        bytes_written = 0
        reader = bundle.read_encrypted_stream()
        try:
            while True:
                buf = yield from reader.read()
                if len(buf) == 0:
                    break
                self.writer.write(buf)
                bytes_written += len(buf)
                yield from self.writer.drain()
        finally:
            yield from reader.close()
        assert bytes_written == bundle.file_size_crypt

        yield from self.read_term() # make sure server returns 'ok'

    @asyncio.coroutine
    def list_files(self):

        logger.info('Getting a list of files for vault %s', self.storage.vault)

        # upload key and file
        yield from self.write_term('list_files')

        response = yield from self.read_response()

        assert type(response) == tuple

        if response[0] == Atom('stream_response'):
            assert isinstance(response[1], int)
            for n in range(response[1]):
                server_info = yield from self.read_term(assert_ok=False)
                store_hash = server_info['hash'].decode()
                file_info = server_info['key']
                yield from self.storage.vault.add_bundle_by_fileinfo(store_hash, file_info)

    @asyncio.coroutine
    def download(self, bundle):

        logger.info('Downloading %s', bundle)

        # download key and file
        yield from self.write_term('download', bundle.store_hash)

        response = yield from self.read_term()

        server_info = rewrite_atoms_dict(response[1])

        content_hash = server_info['content_hash'].decode()
        fileinfo = server_info['key']
        file_size = server_info['size']

        assert type(file_size) == int

        logger.info('Downloading content ({} bytes)'.format(file_size))

        # read content hash
        logger.debug('content hash: %s', content_hash)

        yield from bundle.write_encrypted_fileinfo(Once(fileinfo))

        yield from bundle.load_key()

        yield from bundle.write_encrypted_stream(
                StreamReader(self.reader) >> Limit(file_size),
                assert_hash=content_hash)

    @asyncio.coroutine
    def version(self):
        return self.server_version

class BinaryStorageManager(object):

    def __init__(self, backend, concurrency):
        self.backend = backend
        self.concurrency = concurrency
        self.slots = [BinaryStorageConnection(backend) for i in range(concurrency)]

    @asyncio.coroutine
    def close(self):
        logged = False
        for conn in self.slots:
            if conn.connected or conn.connecting:
                if not logged:
                    logger.info('Disconnecting from server')
                    logged = True
                yield from conn.disconnect()

    @asyncio.coroutine
    def acquire_connection(self):
        'return an available connection or block until one is free'
        # trigger at most one connection
        for conn in self.slots:
            if not conn.connected and not conn.connecting:
                conn.connecting = True
                yield from conn.connect()
                break
            if conn.connected and conn.available.is_set():
                break

        logger.debug("Wait for empty slot in: %s", self.slots)

        # wait until one slot is available
        done, running = yield from \
                asyncio.wait([conn.available.wait() for conn in self.slots],
                            return_when=asyncio.FIRST_COMPLETED)

        for f in running: f.cancel()

        # find this slot
        for conn in self.slots:
            if conn.connected and conn.available.is_set():
                conn.available.clear()
                return conn

        # if we haven't found one, try again
        return (yield from self.acquire_connection())

class BinaryStorageBackend(StorageBackend):

    def __init__(self, vault, auth=None, host='127.0.0.1', port=1337,
            concurrency=4, username=None, password=None, ssl=False):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.vault = vault
        self.username = username
        self.password = password
        self.auth = auth
        self.buf_size = 10 * 1024
        self.concurrency = int(concurrency)
        self.manager = BinaryStorageManager(self, self.concurrency)
        super(BinaryStorageBackend, self).__init__(vault)

    @asyncio.coroutine
    def init(self):
        self.auth = None
        try:
            with (yield from self.manager.acquire_connection()) as conn:
                # after successful login, write back config
                self.vault.config.update('remote', {'auth': self.auth})
                self.vault.write_config()
                self.invalid_auth = False
                logger.info('Successfully logged in and stored auth token')
        except StorageBackendInvalidAuth as e:
            logger.error('Invalid auth')
            self.invalid_auth = True

    @asyncio.coroutine
    def open(self):
        with (yield from self.manager.acquire_connection()) as conn:
            self.invalid_auth = False
            self.connected = True
            version = yield from conn.version()
            logger.info('Logged in to server (version %s)', version)

    @asyncio.coroutine
    def stat(self, bundle):
        with (yield from self.manager.acquire_connection()) as conn:
            bundle.remote_crypt_hash = None
            try:
                stat_info = yield from conn.stat(bundle)
                if 'content_hash' in stat_info:
                    bundle.remote_crypt_hash = stat_info['content_hash'].decode()
            except UnsuccessfulResponse:
                pass

    @asyncio.coroutine
    def list_files(self):
        with (yield from self.manager.acquire_connection()) as conn:
            yield from conn.list_files()

    @asyncio.coroutine
    def upload(self, bundle):
        with (yield from self.manager.acquire_connection()) as conn:
            yield from conn.upload(bundle)

    @asyncio.coroutine
    def download(self, bundle):
        with (yield from self.manager.acquire_connection()) as conn:
            try:
                yield from conn.download(bundle)
            except UnsuccessfulResponse:
                logger.error('Could not download bundle: %s', str(bundle))

    @asyncio.coroutine
    def close(self):
        yield from self.manager.close()

