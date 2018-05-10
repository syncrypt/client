import asyncio
import logging
import math
import os.path
import re
import ssl
import struct
import sys
import time
from getpass import getpass

import certifi
from erlastic import Atom
from tenacity import (retry, retry_if_exception_type, retry_unless_exception_type,
                      stop_after_attempt, wait_exponential)

import syncrypt
from syncrypt import __project__, __version__
from syncrypt.exceptions import (ConnectionResetException, InvalidAuthentification, ServerError,
                                 UnexpectedResponseException, UnsuccessfulResponse,
                                 VaultNotInitialized)
from syncrypt.pipes import (BufferedFree, ChunkedURLWriter, Limit, Once, StreamReader, StreamWriter,
                            URLReader, URLWriter)
from syncrypt.utils.format import format_size
from syncrypt.vendor import bert

from .base import StorageBackend

logger = logging.getLogger(__name__)

BINARY_DEBUG = False

NIL = Atom('nil')

# additional vault fields
V_BYTE_SIZE      = Atom('byte_size')
V_FILE_COUNT     = Atom('file_count')
V_REVISION_COUNT = Atom('revision_count')
V_USER_COUNT     = Atom('user_count')
V_MODIFICATION_DATE = Atom('modification_date')

ALL_VAULT_FIELDS = [V_BYTE_SIZE, V_FILE_COUNT, V_REVISION_COUNT, V_USER_COUNT, V_MODIFICATION_DATE]


def bert_val(bert_term):
    # Convert a nil atom to None
    if bert_term == NIL:
        return None
    else:
        return bert_term


def rewrite_atoms_dict(bert_dict):
    # Convert a dict with Atom keys to a str keys
    # In the future, generalize this to a complete BERT Atom->str
    # rewriter
    return {str(k): bert_val(v) for (k, v) in bert_dict.items()}


class BinaryStorageConnectionLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, connection, logger):
        self.connection = connection
        super(BinaryStorageConnectionLoggerAdapter, self).__init__(logger, {})

    def process(self, msg, kwargs):
        if self.connection.vault and self.connection.vault.id:
            return (msg, dict(kwargs, extra={'vault_id': self.connection.vault.id}))
        else:
            return (msg, kwargs)


class BinaryStorageConnection(object):
    '''
    A connection slot which is instantiated by BinaryStorageManager.

    The states of a slot are: 'closed', 'opening', 'busy', 'idle'. Additionally a slot can either
    be general purpose or associated with a Vault (i.e. it is logged in to that Vault and can
    execute commands related to it).
    '''

    def __init__(self, manager):
        self.manager = manager
        self.writer = None
        self.reader = None
        self.logger = BinaryStorageConnectionLoggerAdapter(self, logger)

        # State
        self.vault = None
        self.available = asyncio.Event()
        self.available.clear()
        self.connected = False
        self.connecting = False

    @property
    def state(self):
        if self.connected:
            if self.available.is_set():
                return 'idle'
            else:
                return 'busy'
        elif self.connecting:
            return 'opening'
        else:
            return 'closed'

    def __repr__(self):
        return "<Connection 0x%x %s%s>" % (
               id(self),
               self.state,
               self.vault and ' vault={0}'.format(str(self.vault)) or '')

    async def read_term(self, assert_ok=True):
        '''reads a BERT tuple, asserts that first item is "ok"'''
        pl_read = (await self.reader.read(4))

        if len(pl_read) != 4:
            raise ConnectionResetException()

        pl_tuple = struct.unpack('!I', pl_read)
        packet_length = pl_tuple[0]
        assert packet_length > 0

        packet = b''
        while len(packet) < packet_length:
            buf = await self.reader.read(packet_length - len(packet))
            if len(buf) == 0:
                raise ConnectionResetException()
            packet += buf

        if BINARY_DEBUG:
            logger.debug('[READ] Serialized: %s', packet)

        decoded = bert.decode(packet)

        if BINARY_DEBUG:
            self.logger.debug('[READ] Unserialized: %s', decoded)

        if assert_ok and decoded[0] != Atom('ok'):
            if decoded[0] == Atom('error'):
                raise ServerError(decoded[1:])
            else:
                raise UnsuccessfulResponse(decoded)

        return decoded

    async def read_response(self):
        decoded = await self.read_term(assert_ok=True)
        return decoded[1] if len(decoded) > 1 else None

    async def write_term(self, *term):
        '''write a BERT tuple'''
        if BINARY_DEBUG:
            self.logger.debug('[WRITE] Unserialized: %s', term)
        packet = bert.encode((Atom(term[0]),) + term[1:])
        packet_length = len(packet)
        assert packet_length > 0
        if BINARY_DEBUG:
            self.logger.debug('[WRITE] Serialized: %s', packet)
        self.writer.write(struct.pack('!I', packet_length))
        self.writer.write(packet)
        await self.writer.drain()

    async def connect(self):

        if not self.connected:
            if self.manager.ssl:
                sc = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=certifi.where())
                if not self.manager.ssl_verify or self.manager.host in ('127.0.0.1', 'localhost'):
                    self.logger.warn('Continuing without verifying SSL cert')
                    sc.check_hostname = False
                    sc.verify_mode = ssl.CERT_NONE
            else:
                sc = None

            self.logger.debug('Connecting to server %s:%d ssl=%s...', self.manager.host,
                    int(self.manager.port), bool(sc))

            self.reader, self.writer = \
                    await asyncio.open_connection(self.manager.host,
                                                       int(self.manager.port), ssl=sc)

            version_info = await self.read_term()
            self.server_version = version_info[1].decode()

            client_version = '%s' % __version__
            client_ident = (__project__, client_version)
            self.logger.debug('Identifying to server as %s', client_ident)
            await self.write_term('hello', client_ident)

            await self.read_term() # expect OK

            self.logger.debug('Connected (client: %s; server; %s)', client_version, self.server_version)

    async def login(self, vault=None):

        self.vault = vault
        if vault and vault.config.id:
            self.logger.debug('Login to vault %s', vault.config.id)

        auth = self.vault and self.vault.config.get('remote.auth')

        if auth:
            await self.write_term('auth', auth)
            response = await self.read_term(assert_ok=False)
            if response[0] != Atom('ok'):
                await self.disconnect()
                raise InvalidAuthentification(response)
        else:
            if not self.manager.global_auth and (self.manager.username is None or self.manager.username == ''):
                # we don't have auth token yet
                await self.disconnect()
                raise InvalidAuthentification('No username/email or auth token provided')

            if vault is None:
                if self.manager.global_auth:
                    await self.write_term('auth', self.manager.global_auth)
                else:
                    await self.write_term('login', self.manager.username,
                            self.manager.password)

                response = await self.read_term(assert_ok=False)

                if response[0] != Atom('ok'):
                    await self.disconnect()
                    raise InvalidAuthentification(response)

                if len(response) == 2:
                    self.manager.global_auth = response[1].decode()

            elif vault.config.id is None:
                if self.manager.global_auth:
                    await self.write_term('auth', self.manager.global_auth)
                else:
                    await self.write_term('login', self.manager.username,
                            self.manager.password)

                response = await self.read_term(assert_ok=False)

                if response[0] != Atom('ok'):
                    await self.disconnect()
                    raise InvalidAuthentification(response)

                if len(response) == 2:
                    self.manager.global_auth = response[1].decode()

                key = vault.identity.export_public_key()

                await self.write_term('create_vault', str(len(key)))

                response = await self.read_term(assert_ok=False)

                if response[0] == Atom('ok'):
                    auth = response[2].decode(self.vault.config.encoding)
                    self.logger.info('Created vault %s', response[1])
                    with vault.config.update_context():
                        vault.config.update('remote', {
                            'auth': auth
                        })
                        vault.config.update('vault', {
                            'id': response[1].decode(self.vault.config.encoding)
                        })
                else:
                    await self.disconnect()
                    raise InvalidAuthentification(response)

            else:
                if self.manager.global_auth:
                    await self.write_term('vault_login', self.manager.global_auth, vault.config.id)
                else:
                    await self.write_term('vault_login', self.manager.username,
                            self.manager.password, vault.config.id)

                login_response = await self.read_term(assert_ok=False)

                if login_response[0] == Atom('ok') and login_response[1] != '':
                    auth = login_response[1].decode(self.vault.config.encoding)
                    with vault.config.update_context():
                        vault.config.update('remote', {
                            'auth': auth
                        })
                else:
                    await self.disconnect()
                    raise InvalidAuthentification(login_response[1])

        self.connected = True
        self.connecting = False
        self.available.set()

    async def disconnect(self):
        logger.debug('Disconnecting %s', self)
        try:
            if self.writer:
                await self.write_term('disconnect')
        except ConnectionResetError:
            pass
        finally:
            if self.writer:
                self.writer.close()

                # Add a little delay so that the connection socket is actually
                # closed. This is not needed in Python 3.5+, but somehow in 3.4.
                if sys.version_info < (3, 5): await asyncio.sleep(0.1)

                self.writer = None
            self._clear_connection()

    async def __aenter__(self):
        # This enables the connection to be used as a context manager. When the context is closed,
        # the connection is automatically set to "idle" (available).
        return self

    async def __aexit__(self, ex_type, ex_value, ex_st):
        if ex_value:
            # When an exception happened, let's force a disconnect and clear
            # the slot
            if isinstance(ex_value, asyncio.CancelledError):
                self.logger.debug('Task has been cancelled within context, clearing connection.')
            else:
                self.logger.debug('Exception %s has been raised within context, clearing connection.',
                    ex_value)
            self._clear_connection()
        else:
            # Let's assume there was no problem
            self.available.set()

        # Explicitely return False to signal that exception should be processed
        # normally
        return False

    def _clear_connection(self):
        if self.writer:
            self.writer.close()
            self.writer = None
        self.connected = False
        self.connecting = False
        self.vault = None
        self.available.clear()

    async def stat(self, bundle):
        self.logger.debug('Stat %s (%s)', bundle, bundle.store_hash)

        await self.write_term('stat', bundle.store_hash)

        response = await self.read_term()

        if isinstance(response[1], (tuple, list)) and response[1][0] == Atom('not_found'):
            self.logger.debug('File not found: %s', bundle.store_hash)
            return None

        dct = rewrite_atoms_dict(response[1])
        dct.update(**rewrite_atoms_dict(response[2]))
        return dct

    async def upload(self, bundle):

        self.logger.info('Uploading %s', bundle)

        assert bundle.uptodate

        metadata = await bundle.encrypted_metadata_reader().readall()
        metadata_size = len(metadata)

        # upload key and file
        await self.write_term('upload', bundle.store_hash,
                bundle.crypt_hash, metadata, bundle.file_size_crypt)

        response = await self.read_response() # make sure server returns 'ok'

        self.logger.debug('Uploading bundle (metadata: {0} bytes, content: {1} bytes)'\
                .format(metadata_size, bundle.file_size_crypt))

        bundle.bytes_written = 0
        upload_id = None
        urls = None
        reader = bundle.read_encrypted_stream()

        if isinstance(response, tuple) and len(response) > 0 and response[0] == Atom('url'):
            if isinstance(response[1], tuple) and response[1][0] == Atom('multi'):
                _, upload_id, urls = response[1]
                chunksize = int(math.ceil(bundle.file_size_crypt * 1.0 / len(urls)))
                self.logger.info('Chunked URL upload to %d urls. chunksize=%d', len(urls), chunksize)
                writer = reader >> ChunkedURLWriter([u.decode() for u in urls], chunksize,\
                        total_size=bundle.file_size_crypt)
                url = None
            else:
                url = response[1].decode()
                self.logger.info('Non-chunked URL upload to %s.', url)
                writer = reader >> URLWriter(url, size=bundle.file_size_crypt)
                upload_id = None

            await writer.consume()

            if writer.bytes_written != bundle.file_size_crypt:
                self.logger.error('Uploaded size did not match: should be %d, is %d (diff %d)',
                        bundle.file_size_crypt, writer.bytes_written,
                        writer.bytes_written - bundle.file_size_crypt)
                raise Exception('Uploaded size did not match')

            if upload_id:
                await self.write_term('uploaded', (Atom('multi'), upload_id, writer.etags))
            else:
                await self.write_term('uploaded', url)
        else:
            self.logger.debug('Streaming upload requested.')

            writer = reader >> StreamWriter(self.writer)
            await writer.consume()

            if writer.bytes_written != bundle.file_size_crypt:
                self.logger.error('Uploaded size did not match: should be %d, is %d (diff %d)',
                        bundle.file_size_crypt, writer.bytes_written,
                        writer.bytes_written - bundle.file_size_crypt)
                raise Exception('Uploaded size did not match')

        # server should return the response
        response = await self.read_response()
        server_info = rewrite_atoms_dict(response)

        # if all went well, store revision_id in vault
        self.vault.update_revision(server_info['id'])

    async def vault_metadata(self):
        self.logger.debug('Getting metadata for %s', self.vault)

        await self.write_term('vault_metadata')

        metadata = await self.read_response()

        if metadata is None:
            self.logger.debug('Metadata is not yet set')
        else:
            self.logger.debug('Metadata size is %d bytes', len(metadata))

        if not metadata is None:
            await self.vault.write_encrypted_metadata(Once(metadata))
        else:
            self.logger.warn('Empty metadata for %s', self.vault)

    async def user_info(self):
        self.logger.debug('Retrieving user information from server')
        await self.write_term('user_info')
        user_info = await self.read_response()
        user_info = rewrite_atoms_dict(user_info)
        if 'first_name' in user_info:
            user_info['first_name'] = user_info['first_name'].decode()
        if 'last_name' in user_info:
            user_info['last_name'] = user_info['last_name'].decode()
        if 'email' in user_info:
            user_info['email'] = user_info['email'].decode()
        return user_info

    async def set_vault_metadata(self):

        vault = self.vault
        metadata = await vault.encrypted_metadata_reader().readall()

        self.logger.debug('Setting metadata for %s (%d bytes)', self.vault,
                len(metadata))

        # upload metadata
        await self.write_term('set_vault_metadata', metadata)

        # assert :ok
        await self.read_response()

    async def changes(self, since_rev, to_rev, queue, verbose=False):
        self.logger.info('Getting a list of changes for %s (%s to %s)',
                self.vault, since_rev or 'earliest', to_rev or 'latest')

        if verbose:
            await self.write_term('changes_with_email', since_rev, to_rev)
        else:
            await self.write_term('changes', since_rev, to_rev)

        response = await self.read_response()

        # response is either list or stream
        if len(response) > 0 and response[0] == Atom('stream_response'):
            (_, file_count) = response
            assert isinstance(file_count, int)
            for n in range(file_count):
                server_info = await self.read_term(assert_ok=False)
                server_info = rewrite_atoms_dict(server_info)
                store_hash = server_info['file_hash'].decode()
                metadata = server_info['metadata']
                if metadata is None:
                    self.logger.warn('Skipping file %s (no metadata!)', store_hash)
                    continue
                self.logger.debug('Server sent us: %s (%d bytes metadata)', store_hash,
                        len(metadata))
                await queue.put((store_hash, metadata, server_info))
            await queue.put(None)
        else:
            for server_info in response:
                server_info = rewrite_atoms_dict(server_info)
                store_hash = server_info['file_hash'].decode()
                metadata = server_info['metadata']
                user_email = server_info['email'].decode()
                if metadata is None:
                    self.logger.warn('Skipping file %s (no metadata!)', store_hash)
                    continue
                self.logger.debug('Server sent us: %s (%d bytes metadata)', store_hash,
                        len(metadata))
                await queue.put((store_hash, metadata, server_info))
            await queue.put(None)

    async def list_vaults(self):
        self.logger.info('Getting a list of vaults')

        await self.write_term('list_vaults', ALL_VAULT_FIELDS)
        response = await self.read_term()

        return list(map(rewrite_atoms_dict, response[1]))

    async def list_vaults_by_fingerprint(self, fingerprint):

        self.logger.info('Getting a list of vaults by fingerprint: %s', fingerprint)

        await self.write_term('list_vaults_by_fingerprint', str(fingerprint))
        response = await self.read_term()

        # return [(vault, user_vault_key, metadata)]
        return ((rewrite_atoms_dict(r[0]), r[1]['encrypted_content'], r[2]) for r in response[1])

    async def list_vault_users(self):

        self.logger.info('Getting a list of vault users')

        await self.write_term('list_vault_users')
        response = await self.read_term()

        return [{k: v.decode() for k, v in user.items()}
                for user in map(rewrite_atoms_dict, response[1])]

    async def list_files(self, queue):

        self.logger.info('Getting a list of files for vault %s', self.vault)

        await self.write_term('list_files')

        response = await self.read_response()

        assert type(response) == tuple

        if response[0] == Atom('stream_response'):
            (_, file_count, revision_id) = response
            assert isinstance(file_count, int)
            for n in range(file_count):
                server_info = await self.read_term(assert_ok=False)
                server_info = rewrite_atoms_dict(server_info)
                store_hash = server_info['file_hash'].decode()
                metadata = server_info['metadata']
                if metadata is None:
                    self.logger.warn('Skipping file %s (no metadata!)', store_hash)
                    continue
                self.logger.debug('Server sent us: %s (%d bytes metadata)', store_hash,
                        len(metadata))
                await queue.put((store_hash, metadata, server_info))
            await queue.put(None)

    async def add_user_vault_key(self, email, fingerprint, content):
        await self.write_term('add_user_vault_key', fingerprint, content)
        await self.read_term()

    async def get_user_vault_key(self, fingerprint, vault_id):
        if self.manager.global_auth:
            await self.write_term('vault_login', self.manager.global_auth, vault_id)
        else:
            await self.write_term('vault_login', self.manager.username,
                    self.manager.password, vault_id)
        auth_token = await self.read_response()
        auth_token = auth_token.decode()
        await self.write_term('get_user_vault_key', fingerprint, vault_id)
        response = await self.read_response()
        response = rewrite_atoms_dict(response)
        return auth_token, response['encrypted_content']

    async def download(self, bundle):

        self.logger.info('Downloading %s', bundle)

        # download key and file
        await self.write_term('download', bundle.store_hash)

        response = await self.read_term()

        if len(response) == 3:
            server_info = rewrite_atoms_dict(response[1])
            server_info.update(**rewrite_atoms_dict(response[2]))
            url = None
        elif len(response) == 2 and isinstance(response[1], tuple) and response[1][0] == Atom('url'):
            response_obj = response[1]
            url = response_obj[1].decode()
            server_info = rewrite_atoms_dict(response_obj[2])
            server_info.update(**rewrite_atoms_dict(response_obj[3]))
        else:
            raise Exception('xx')

        content_hash = server_info['content_hash'].decode()
        metadata = server_info['metadata']
        file_size = server_info['size']

        assert type(file_size) == int

        if url:
            self.logger.debug('Downloading content ({} bytes) from URL: {}'.format(file_size, url))
        else:
            self.logger.debug('Downloading content ({} bytes) from stream.'.format(file_size))

        # read content hash
        self.logger.debug('Content hash: %s', content_hash)

        await bundle.write_encrypted_metadata(Once(metadata))

        await bundle.load_key()

        if url:
            stream_source = URLReader(url)
        else:
            stream_source = StreamReader(self.reader) >> Limit(file_size)

        hash_ok = await bundle.write_encrypted_stream(
                stream_source,
                assert_hash=content_hash
            )

        if not hash_ok:
            # alert server of hash mismatch
            await self.write_term('invalid_content_hash', bundle.store_hash, self.vault.revision)


    async def vault_size(self, vault):
        self.logger.debug('Querying vault size: %s', vault.config.id)

        # download key and file
        await self.write_term('vault_size', vault.config.id)

        size = await self.read_response()
        return size

    async def list_keys(self, user=None):
        if user:
            await self.write_term('list_user_keys', user)
        else:
            await self.write_term('list_user_keys')

        keys = await self.read_response()

        def transform_key(key):
            key = rewrite_atoms_dict(key)
            key['fingerprint'] = key['fingerprint'].decode()
            key['created_at'] = key['created_at'].decode()
            key['description'] = key['description'].decode()
            return key

        return map(transform_key, keys)

    async def list_vault_user_key_fingerprints(self):
        await self.write_term('list_vault_user_key_fingerprints')
        fingerprints = [fp.decode() for fp in (await self.read_response())]
        return fingerprints

    async def upload_identity(self, identity, description=""):
        self.logger.debug('Uploading my public key to server')

        # upload public key and fingerprint
        await self.write_term('add_user_key', identity.export_public_key(),
                              identity.get_fingerprint(), description)

        response = await self.read_term()

        if response[0] == Atom('user_key_added'):
            raise UnexpectedResponseException()

    async def add_vault_user(self, email):
        await self.write_term('add_vault_user', email)
        await self.read_term()

    async def remove_vault_user(self, email):
        await self.write_term('remove_vault_user', email)
        await self.read_term()

    async def delete_vault(self, vault_id=None):
        '''
        Delete/wipe a vault. When vault_id is given, this will delete the vault with the given
        vault id on the server. If it is not given, this will delete the current vault for this
        connection.
        '''
        if vault_id is None:
            vault_id = self.vault.config.id
        self.logger.info('Wiping vault: %s', vault_id)
        await self.write_term('delete_vault', vault_id)
        await self.read_response()

    def __getattr__(self, name):
        '''
        Generic API call
        '''
        async def myco(*args, **kwargs):
            self.logger.info('Calling generic API %s/%d', name, len(args))
            await self.write_term(name, *args)
            return (await self.read_response())

        return myco

    async def version(self):
        return self.server_version


class BinaryStorageManager(object):
    '''
    The BinaryStorageManager will manage n connection slots of type BinaryStorageConnection.

    It will automatically open new connections or find idle connections when a new connection
    is requested through the "acquire_connection" function. It will also close connection that
    have been idle for some time.
    '''

    def __init__(self):
        self.host = None
        self.port = None
        self.ssl = None
        self.ssl_verify = None

        # Global user auth information
        self.global_auth = None
        self.username = None
        self.password = None
        self.concurrency = None

        self._monitor_task = None
        self.slots = []
        self.loop = None

    def init(self):
        if self.loop is not None and self.loop != asyncio.get_event_loop():
            if self.loop.is_running():
                raise ValueError('manager has been initialized with a differnt loop which is still running')
            self.slots = []
            self.loop = None
        self.loop = asyncio.get_event_loop()
        if not self.slots:
            logger.debug('Registering %d connection slots for loop %s',
                         self.concurrency, id(asyncio.get_event_loop()))
            self.slots = [BinaryStorageConnection(self) for i in range(self.concurrency)]

    def get_stats(self):
        states = {'closed': 0}
        if self.slots:
            for conn in self.slots:
                states[conn.state] = states.get(conn.state, 0) + 1
            states['total'] = len(self.slots)
        else:
            states['total'] = 0
        return states

    async def close(self):
        logger.info('Closing backend manager')
        logged = False
        for conn in self.slots:
            if conn.connected or conn.connecting:
                if not logged:
                    logger.debug('Disconnecting from server')
                    logged = True
                await conn.disconnect()
        if not self._monitor_task is None:
            self._monitor_task.cancel()
        self.slots = []
        self.loop = None

    async def monitor_connections(self):
        '''
        Monitor and close open and non-busy connections one-by-one.
        '''
        while True:
            await asyncio.sleep(30.0)
            def sign_for_state(state):
                if state == 'idle':
                    return '*'
                elif state == 'busy':
                    return 'B'
                elif state == 'opening':
                    return 'o'
                elif state == 'closed':
                    return '-'
                return ' '

            if BINARY_DEBUG:
                logger.debug('Slots: [%s]',
                             ''.join([sign_for_state(slot.state) for slot in self.slots]))

            for conn in self.slots:
                if conn.connected and conn.available.is_set():
                    logger.debug('Closing due to idleness: %s', conn)
                    await conn.disconnect()
                    break

    @retry(retry=retry_if_exception_type() & retry_unless_exception_type(InvalidAuthentification),
           stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, max=10))
    async def acquire_connection(self, vault, skip_login=False):
        'return an available connection or block until one is free'
        if self._monitor_task is None:
            self._monitor_task = \
                    asyncio.get_event_loop().create_task(self.monitor_connections())

        # Prefer slots that have the same vault as we want
        prio_slots = sorted(self.slots, key=lambda c: c.vault == vault, reverse=True)

        for conn in prio_slots:
            if conn.connected and conn.available.is_set():
                conn.available.clear()
                if conn.vault != vault:
                    logger.debug('Found an available connection, but we need to switch the vault to %s', vault)
                    conn.connecting = True
                    try:
                        await conn.connect()
                        if not skip_login:
                            await conn.login(vault)
                    except:
                        conn._clear_connection()
                        raise
                elif vault:
                    logger.debug('Found an available connection for %s', vault)
                else:
                    logger.debug('Found an available connection %s', conn)
                conn.available.clear()
                return conn

        # Try to find an unconnected slot and open a connection
        for conn in prio_slots:
            if not conn.connected and not conn.connecting:
                conn.connecting = True
                try:
                    await conn.connect()
                    if not skip_login:
                        await conn.login(vault)
                    conn.available.clear()
                    logger.debug("Choosing %s", conn)
                    return conn
                except:
                    conn._clear_connection()
                    raise
                break

        logger.debug("Wait for empty slot in: %s", self.slots)

        await asyncio.sleep(1.0)

        # if we haven't found one, try again
        return await self.acquire_connection(vault)


def get_manager_instance():
    if not hasattr(get_manager_instance, '_manager'):
        get_manager_instance._manager = BinaryStorageManager()
    return get_manager_instance._manager


class BinaryStorageBackend(StorageBackend):
    '''
    Implements the actual backend for the vault. Each Vault will have its own BinaryStorageBackend
    object associated with it, but all will use the same manager.
    '''

    def __init__(self, vault=None, auth=None, host=None, port=None,
            concurrency=None, username=None, password=None, ssl=True,
            ssl_verify=True):

        assert isinstance(ssl, bool)
        assert isinstance(ssl_verify, bool)

        manager = get_manager_instance()

        # Global connection settings
        manager.host = host
        manager.port = port
        manager.ssl = ssl
        manager.ssl_verify = ssl_verify

        # Global user auth information
        if not manager.username: manager.username = username
        if not manager.password: manager.password = password
        manager.concurrency = int(concurrency)

        manager.init()

        # Vault specific login information
        self.vault = vault
        self.auth = auth

        super(BinaryStorageBackend, self).__init__(vault)

    @property
    def global_auth(self):
        return get_manager_instance().global_auth

    @global_auth.setter
    def global_auth(self, value):
        manager = get_manager_instance()
        if not manager.global_auth or value is None:
            logger.debug('Setting global_auth to %s', value)
            manager.global_auth = value

    def set_auth(self, username, password):
        manager = get_manager_instance()
        manager.username = username
        manager.password = password

    async def _acquire_connection(self, **kwargs):
        return await get_manager_instance().acquire_connection(self.vault, **kwargs)

    async def init(self):
        self.auth = None
        try:
            async with (await self._acquire_connection()) as conn:
                # after successful login, write back config
                self.invalid_auth = False
                conn.logger.info('Successfully logged in and stored auth token')
        except InvalidAuthentification:
            self.invalid_auth = True
            raise

    async def open(self):
        if self.vault and not self.vault.config.get('vault.id'):
            raise VaultNotInitialized()
        stats = get_manager_instance().get_stats()
        if stats['closed'] == stats['total']:
            async with (await self._acquire_connection()) as conn:
                self.invalid_auth = False
                version = await conn.version()
                conn.logger.debug('Logged in to server (version %s)', version)

    async def vault_size(self, vault):
        async with (await self._acquire_connection()) as conn:
            size = await conn.vault_size(vault)
            conn.logger.debug('Vault size is: %s', format_size(size))
            return size

    async def stat(self, bundle):
        async with (await self._acquire_connection()) as conn:
            bundle.remote_crypt_hash = None
            stat_info = await conn.stat(bundle)
            if stat_info and 'content_hash' in stat_info:
                bundle.remote_crypt_hash = stat_info['content_hash'].decode()

    async def list_files(self):
        conn = await self._acquire_connection()
        queue = asyncio.Queue(8)
        task = asyncio.get_event_loop().create_task(conn.list_files(queue))

        def free_conn(result):
            conn.available.set()

        task.add_done_callback(free_conn)
        return queue

    async def changes(self, since_rev, to_rev, verbose=False):
        conn = await self._acquire_connection()
        queue = asyncio.Queue(8)
        task = asyncio.get_event_loop().create_task(conn.changes(since_rev, to_rev, queue, verbose=verbose))

        def free_conn(result):
            conn.available.set()

        task.add_done_callback(free_conn)
        return queue

    async def upload(self, bundle):
        async with (await self._acquire_connection()) as conn:
            await conn.upload(bundle)

    async def download(self, bundle):
        async with (await self._acquire_connection()) as conn:
            try:
                await conn.download(bundle)
            except UnsuccessfulResponse:
                conn.logger.error('Could not download bundle: %s', str(bundle))

    async def signup(self, username, password, firstname, surname):
        async with (await self._acquire_connection(skip_login=True)) as conn:
            return await conn.signup(username, password, firstname, surname)

    def __getattr__(self, name):
        async def myco(*args, **kwargs):
            async with (await self._acquire_connection()) as conn:
                result = await getattr(conn, name)(*args, **kwargs)
            return result
        return myco

    async def close(self):
        pass
        #await manager.close()

