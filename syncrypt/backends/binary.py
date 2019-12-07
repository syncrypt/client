import logging
import math
import ssl
import struct
from typing import Any, List, Optional, cast  # pylint: disable=unused-import

import certifi
import iso8601
import trio
from erlastic import Atom
from syncrypt import __project__, __version__
from syncrypt.exceptions import (ConnectionResetException, InvalidAuthentification, ServerError,
                                 SyncRequired, UnexpectedResponseException, UnsuccessfulResponse,
                                 VaultNotInitialized)
from syncrypt.models import Bundle, Identity, Revision, RevisionOp, Vault
from syncrypt.pipes import (ChunkedURLWriter, Limit, Once, TrioStreamReader, TrioStreamWriter,
                            URLReader, URLWriter)
from syncrypt.utils.format import format_size
from syncrypt.vendor import bert
from tenacity import (retry, retry_if_exception_type, retry_unless_exception_type,
                      stop_after_attempt, wait_exponential)

from .base import StorageBackend

try:
    from contextlib import asynccontextmanager # type: ignore
except ImportError: # on Python 3.6
    from async_generator import asynccontextmanager # type: ignore


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
    def __init__(self, connection: 'BinaryStorageConnection', logger) -> None:
        self.connection = connection
        super(BinaryStorageConnectionLoggerAdapter, self).__init__(logger, {})

    def process(self, msg, kwargs):
        if self.connection.vault and self.connection.vault.id:
            return (msg, dict(kwargs, extra={'vault_id': self.connection.vault.id}))
        else:
            return (msg, kwargs)


class BinaryStorageConnection():
    '''
    A connection slot which is instantiated by BinaryStorageManager.

    The states of a slot are: 'closed', 'opening', 'busy', 'idle'. Additionally a slot can either
    be general purpose or associated with a Vault (i.e. it is logged in to that Vault and can
    execute commands related to it).
    '''

    def __init__(self, manager: 'BinaryStorageManager') -> None:
        self.manager = manager
        self.stream = None # type: Optional[trio.abc.Stream]
        self.logger = BinaryStorageConnectionLoggerAdapter(self, logger)

        # State
        self.vault = None  # type: Optional[Vault]
        self.available = False
        self.connected = False
        self.connecting = False

    @property
    def state(self):
        if self.connected:
            if self.available:
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
        assert self.stream is not None
        pl_read = (await self.stream.receive_some(4))

        if len(pl_read) != 4:
            raise ConnectionResetException()

        pl_tuple = struct.unpack('!I', pl_read)
        packet_length = pl_tuple[0]
        assert packet_length > 0

        packet = b''
        while len(packet) < packet_length:
            buf = await self.stream.receive_some(packet_length - len(packet))
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
                if len(decoded) > 1 and decoded[1] == Atom('sync_required'):
                    raise SyncRequired()
                else:
                    raise ServerError(decoded[1:])
            else:
                raise UnsuccessfulResponse(decoded)

        return decoded

    async def read_response(self):
        decoded = await self.read_term(assert_ok=True)
        return decoded[1] if len(decoded) > 1 else None

    async def write_term(self, *term):
        '''write a BERT tuple'''
        assert self.stream is not None
        if BINARY_DEBUG:
            self.logger.debug('[WRITE] Unserialized: %s', term)
        packet = bert.encode((Atom(term[0]),) + term[1:])
        packet_length = len(packet)
        assert packet_length > 0
        if BINARY_DEBUG:
            self.logger.debug('[WRITE] Serialized: %s', packet)
        await self.stream.send_all(struct.pack('!I', packet_length) + packet)

    async def connect(self):

        if not self.connected:
            sc = None

            if not self.manager.port:
                raise ValueError('Manager has no port')

            if not self.manager.host:
                raise ValueError('Manager has no host')

            if self.manager.ssl:
                sc = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=certifi.where())
                if not self.manager.ssl_verify or self.manager.host in ('127.0.0.1', 'localhost'):
                    self.logger.warning('Continuing without verifying SSL cert')
                    sc.check_hostname = False
                    sc.verify_mode = ssl.CERT_NONE

            self.logger.debug('Connecting to server %s:%d ssl=%s...', self.manager.host,
                    int(self.manager.port), bool(sc))

            if sc:
                self.stream = await trio.open_ssl_over_tcp_stream(self.manager.host,
                        self.manager.port, ssl_context=sc)
            else:
                self.stream = await trio.open_tcp_stream(self.manager.host, self.manager.port)

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

            else:
                if self.manager.global_auth:
                    await self.write_term('vault_login', self.manager.global_auth, vault.config.id)
                else:
                    await self.write_term('vault_login', self.manager.username,
                            self.manager.password, vault.config.id)

                login_response = await self.read_term(assert_ok=False)

                if login_response[0] == Atom('ok') and login_response[1] != '':
                    auth = login_response[1].decode(vault.config.encoding)
                    with vault.config.update_context():
                        vault.config.update('remote', {
                            'auth': auth
                        })
                else:
                    await self.disconnect()
                    raise InvalidAuthentification(login_response[1])

        self.connected = True
        self.connecting = False
        self.available = True

    async def create_vault(self, identity: Identity) -> Revision:
        vault = self.vault
        if vault is None:
            raise ValueError("Invalid argument")

        revision = Revision(operation=RevisionOp.CreateVault)
        revision.vault_public_key = vault.identity.public_key.exportKey("DER")
        revision.user_public_key = identity.public_key.exportKey("DER")
        user_info = await self.user_info()
        revision.user_id = user_info['email']
        revision.sign(identity=identity)

        await self.write_term('create_vault',
                              revision.vault_public_key,
                              revision.user_public_key,
                              revision.user_fingerprint,
                              revision.signature)

        response = await self.read_term()

        vault_id = response[1].decode(vault.config.encoding)
        auth = response[2].decode(vault.config.encoding)
        server_info = rewrite_atoms_dict(response[3])

        if not vault_id:
            raise ServerError("Invalid vault ID: {0}".format(vault_id))

        if not auth:
            raise ServerError("Invalid auth token: {0}".format(auth))

        revision.vault_id = vault_id

        # assert :ok
        ret_revision = self.server_info_to_revision(server_info, vault)
        revision.revision_id = ret_revision.revision_id
        revision.created_at = ret_revision.created_at

        self.logger.info('Successfully created vault %s', vault_id)

        with vault.config.update_context():
            vault.config.update('remote', {
                'auth': auth
            })
            vault.config.update('vault', {
                'id': response[1].decode(vault.config.encoding)
            })

        return revision

    async def disconnect(self):
        logger.debug('Disconnecting %s', self)
        try:
            if self.stream:
                await self.write_term('disconnect')
        except ConnectionResetError:
            pass
        finally:
            await self.clear_connection()

    async def clear_connection(self):
        if self.stream:
            await self.stream.aclose()
            self.stream = None
        self.connected = False
        self.connecting = False
        self.vault = None
        self.available = False

    async def upload(self, bundle, identity: Identity) -> Revision:

        vault = self.vault

        if vault is None:
            raise ValueError("Invalid argument")

        self.logger.info('Uploading %s', bundle)

        assert bundle.uptodate

        metadata = await bundle.encrypted_metadata_reader().readall()
        metadata_size = len(metadata)

        while True:
            revision = Revision(operation=RevisionOp.Upload)
            revision.vault_id = vault.config.id
            revision.parent_id = vault.revision
            revision.crypt_hash = bundle.local_hash
            revision.file_hash = bundle.store_hash
            revision.file_size_crypt = bundle.file_size_crypt
            revision.revision_metadata = metadata
            revision.sign(identity=identity)

            # upload key and file
            await self.write_term('upload',
                    revision.file_hash,
                    revision.crypt_hash,
                    revision.revision_metadata,
                    revision.file_size_crypt,
                    revision.user_fingerprint,
                    revision.signature,
                    revision.parent_id
                )

            response = await self.read_term(assert_ok=False)

            if response[0] == Atom('ok'):
                break
            elif response[0] == Atom('error') and \
                    isinstance(response[1], (list, tuple)) and \
                    response[1][0] == Atom('parent_revision_outdated'):
                logger.info('Revision outdated')
                await trio.sleep(10.0)
                continue
            else:
                raise ServerError(response)

        self.logger.debug('Uploading bundle (metadata: {0} bytes, content: {1} bytes)'\
                .format(metadata_size, bundle.file_size_crypt))

        bundle.bytes_written = 0
        upload_id = None
        urls = None
        reader = vault.crypt_engine.read_encrypted_stream(bundle)

        response = response[1] if len(response) > 1 else None

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

            writer = reader >> TrioStreamWriter(self.stream)
            await writer.consume()

            if writer.bytes_written != bundle.file_size_crypt:
                self.logger.error('Uploaded size did not match: should be %d, is %d (diff %d)',
                        bundle.file_size_crypt, writer.bytes_written,
                        writer.bytes_written - bundle.file_size_crypt)
                raise Exception('Uploaded size did not match')

        # server should return the response
        response = await self.read_response()
        ret_revision = self.server_info_to_revision(rewrite_atoms_dict(response), vault)
        revision.revision_id = ret_revision.revision_id
        revision.created_at = ret_revision.created_at
        return revision

    async def remove_file(self, bundle, identity: Identity) -> Revision:

        vault = self.vault

        if vault is None:
            raise ValueError("Invalid argument")

        self.logger.info('Removing %s', bundle)

        revision = Revision(operation=RevisionOp.RemoveFile)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.file_hash = bundle.store_hash
        revision.sign(identity=identity)

        # upload key and file
        await self.write_term('remove_file',
            revision.file_hash,
            revision.user_fingerprint,
            revision.signature,
            revision.parent_id
        )

        # assert :ok
        response = await self.read_response()
        ret_revision = self.server_info_to_revision(rewrite_atoms_dict(response), vault)
        revision.revision_id = ret_revision.revision_id
        revision.created_at = ret_revision.created_at
        return revision

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

    async def set_vault_metadata(self, identity: Identity) -> Revision:

        vault = self.vault

        if vault is None:
            raise ValueError("Invalid argument")

        metadata = await vault.encrypted_metadata_reader().readall()

        self.logger.debug('Setting metadata for %s (%d bytes)', self.vault,
                len(metadata))

        revision = Revision(operation=RevisionOp.SetMetadata)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.revision_metadata = metadata
        revision.sign(identity=identity)

        # upload metadata
        await self.write_term('set_vault_metadata', metadata,
                              revision.user_fingerprint,
                              revision.parent_id, revision.signature)

        # assert :ok
        response = await self.read_response()
        ret_revision = self.server_info_to_revision(rewrite_atoms_dict(response), vault)
        revision.revision_id = ret_revision.revision_id
        revision.created_at = ret_revision.created_at
        return revision

    def server_info_to_revision(self, server_info, vault: Vault, parent_id: Optional[str]=None):
        operation = server_info['operation'].decode()
        vault_public_key = None
        user_id = None

        if operation == 'store':
            operation = RevisionOp.Upload
        elif operation == 'create_vault':
            operation = RevisionOp.CreateVault
            vault_public_key = vault.identity.export_public_key()
            user_id = server_info['metadata'].decode()
        elif operation == 'set_metadata':
            operation = RevisionOp.SetMetadata
            vault_public_key = vault.identity.export_public_key()
        elif operation == 'add_user':
            operation = RevisionOp.AddUser
            user_id = server_info['metadata'].decode()
        elif operation == 'remove_user':
            operation = RevisionOp.RemoveUser
            user_id = server_info['metadata'].decode()
        elif operation == 'add_user_vault_key':
            operation = RevisionOp.AddUserKey
            user_id = server_info['metadata'].decode()
        elif operation == 'remove_user_vault_key':
            operation = RevisionOp.RemoveUserKey
            user_id = server_info['metadata'].decode()
        else:
            raise ServerError("Unknown operation: " + operation)

        user_fingerprint = server_info['user_key_fingerprint'].decode()
        signature = server_info['signature']
        file_hash = server_info['file_hash'].decode() if server_info['file_hash'] is not None else None
        crypt_hash = server_info['content_hash'].decode() if server_info['content_hash'] is not None else None
        file_size_crypt = server_info['size']
        metadata = server_info['metadata']
        user_public_key = server_info['user_public_key']
        revision_id = server_info['id'].decode()
        created_at = \
                iso8601.parse_date(server_info['created_at'].decode())

        return Revision(
            operation=operation,
            revision_id=revision_id,
            parent_id=parent_id,
            vault_id=vault.config.id,
            created_at=created_at,
            revision_metadata=metadata,
            file_size_crypt=file_size_crypt,
            file_hash=file_hash,
            crypt_hash=crypt_hash,
            user_id=user_id,
            signature=signature,
            user_public_key=user_public_key,
            vault_public_key=vault_public_key,
            user_fingerprint=user_fingerprint
        )

    async def changes(self, since_rev, to_rev):

        if self.vault is None:
            raise ValueError("Invalid argument")

        vault = self.vault

        self.logger.info('Getting a list of changes for %s (%s to %s)',
                vault, since_rev or 'earliest', to_rev or 'latest')

        #if verbose:
        #    await self.write_term('changes_with_email', since_rev, to_rev)
        #else:
        await self.write_term('changes', since_rev, to_rev)

        previous_id = since_rev
        response = await self.read_response()

        # response is either list or stream
        if len(response) > 0 and response[0] == Atom('stream_response'):
            (_, rev_count) = response
            assert isinstance(rev_count, int)
            for _ in range(rev_count):
                server_info = await self.read_term(assert_ok=False)
                server_info = rewrite_atoms_dict(server_info)
                revision = self.server_info_to_revision(server_info, vault, previous_id)
                yield revision
                previous_id = revision.revision_id
        else:
            for server_info in response:
                server_info = rewrite_atoms_dict(server_info)
                revision = self.server_info_to_revision(server_info, vault, previous_id)
                yield revision
                previous_id = revision.revision_id

    async def list_vaults(self) -> List[Any]:
        self.logger.info('Getting a list of vaults')

        await self.write_term('list_vaults', ALL_VAULT_FIELDS)
        response = await self.read_term()

        return list(map(rewrite_atoms_dict, response[1]))

    async def list_vaults_for_identity(self, identity: Identity) -> List[Any]:
        fingerprint = identity.get_fingerprint()

        self.logger.info('Getting a list of vaults by fingerprint: %s', fingerprint)

        await self.write_term('list_vaults_by_fingerprint', str(fingerprint))
        response = await self.read_term()

        return [(rewrite_atoms_dict(r[0]), r[1]['encrypted_content'], r[2]) for r in response[1]]

    async def list_vault_users(self):

        self.logger.info('Getting a list of vault users')

        await self.write_term('list_vault_users')
        response = await self.read_term()

        return [{k: v.decode() for k, v in user.items()}
                for user in map(rewrite_atoms_dict, response[1])]

    async def add_user_vault_key(self, identity: Identity, user_id: str, user_identity: Identity,
                                 vault_key_package: bytes):

        vault = self.vault

        if vault is None:
            raise ValueError("Invalid argument")

        self.logger.debug('Uploading user vault key')

        revision = Revision(operation=RevisionOp.AddUserKey)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = user_id
        revision.user_public_key = user_identity.public_key.exportKey("DER")
        revision.sign(identity=identity)

        # upload metadata
        await self.write_term('add_user_vault_key',
                user_id,
                revision.user_public_key,
                user_identity.get_fingerprint(),
                revision.user_fingerprint,
                revision.parent_id,
                revision.signature,
                vault_key_package
        )

        # assert :ok
        response = await self.read_response()
        ret_revision = self.server_info_to_revision(rewrite_atoms_dict(response), vault)
        revision.revision_id = ret_revision.revision_id
        revision.created_at = ret_revision.created_at
        return revision

    async def remove_user_vault_key(self, identity: Identity, user_id: str,
                                    user_identity: Identity) -> Revision:

        vault = self.vault

        if vault is None:
            raise ValueError("Invalid argument")

        self.logger.debug('Removing user vault key')

        revision = Revision(operation=RevisionOp.RemoveUserKey)
        revision.vault_id = vault.config.id
        revision.parent_id = vault.revision
        revision.user_id = user_id
        revision.user_public_key = user_identity.public_key.exportKey("DER")
        revision.sign(identity=identity)

        # upload metadata
        await self.write_term('remove_user_vault_key',
                user_id,
                revision.user_public_key,
                user_identity.get_fingerprint(),
                revision.user_fingerprint,
                revision.parent_id,
                revision.signature
        )

        # assert :ok
        response = await self.read_response()
        ret_revision = self.server_info_to_revision(rewrite_atoms_dict(response), vault)
        revision.revision_id = ret_revision.revision_id
        revision.created_at = ret_revision.created_at
        return revision

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

        vault = self.vault
        assert vault is not None
        assert self.stream is not None

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
            stream_source = TrioStreamReader(self.stream) >> Limit(file_size)

        hash_ok = await vault.crypt_engine.write_encrypted_stream(
                bundle,
                stream_source,
                assert_hash=content_hash
            )

        if not hash_ok:
            # alert server of hash mismatch
            await self.write_term('invalid_content_hash', bundle.store_hash, vault.revision)


    async def vault_size(self, vault):
        self.logger.debug('Querying vault size: %s', vault.config.id)

        # download key and file
        await self.write_term('vault_size', vault.config.id)

        size = await self.read_response()
        return size

    async def list_keys(self, user: Optional[str] = None):
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

    async def upload_identity(self, identity: Identity, description: str):
        self.logger.debug('Uploading my public key to server')

        # upload public key and fingerprint
        await self.write_term('add_user_key', identity.export_public_key(),
                              identity.get_fingerprint(), description)

        response = await self.read_term()

        if response[0] == Atom('user_key_added'):
            raise UnexpectedResponseException()

    async def add_vault_user(self, user_id: str, identity: Identity) -> Revision:

        vault = self.vault

        if vault is None:
            raise ValueError("Invalid argument")

        revision = Revision(operation=RevisionOp.AddUser)
        revision.vault_id = vault.config.id
        revision.user_id = user_id
        revision.parent_id = vault.revision
        revision.sign(identity=identity)

        await self.write_term('add_vault_user',
                              revision.user_id,
                              revision.user_fingerprint,
                              revision.parent_id,
                              revision.signature)

        # assert :ok
        response = await self.read_response()
        ret_revision = self.server_info_to_revision(rewrite_atoms_dict(response), vault)
        revision.revision_id = ret_revision.revision_id
        revision.created_at = ret_revision.created_at
        return revision

    async def remove_vault_user(self, user_id: str, identity: Identity) -> Revision:
        vault = self.vault

        if vault is None:
            raise ValueError("Invalid argument")

        revision = Revision(operation=RevisionOp.RemoveUser)
        revision.vault_id = vault.config.id
        revision.user_id = user_id
        revision.parent_id = vault.revision
        revision.sign(identity=identity)

        await self.write_term('remove_vault_user',
                              revision.user_id,
                              revision.user_fingerprint,
                              revision.parent_id,
                              revision.signature)

        # assert :ok
        response = await self.read_response()
        ret_revision = self.server_info_to_revision(rewrite_atoms_dict(response), vault)
        revision.revision_id = ret_revision.revision_id
        revision.created_at = ret_revision.created_at
        return revision

    async def delete_vault(self, vault_id=None):
        '''
        Delete/wipe a vault. When vault_id is given, this will delete the vault with the given
        vault id on the server. If it is not given, this will delete the current vault for this
        connection.
        '''
        assert self.vault is not None
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


class BinaryStorageManager():
    '''
    The BinaryStorageManager will manage n connection slots of type BinaryStorageConnection.

    It will automatically open new connections or find idle connections when a new connection
    is requested through the "acquire_connection" function. It will also close connection that
    have been idle for some time.
    '''

    def __init__(self):
        self.host = None
        self.port = None # type: Optional[int]
        self.ssl = None # type: Optional[bool]
        self.ssl_verify = None # type: Optional[bool]

        # Global user auth information
        self.global_auth = None
        self.username = None
        self.password = None
        self.concurrency = None # type: Optional[int]

        self._monitor_task = None
        self.slots = [] # type: List[BinaryStorageConnection]
        self.loop = None

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
        logger.debug('Closing backend manager')
        logged = False
        if not self._monitor_task is None:
            self._monitor_task.cancel()
        for conn in self.slots:
            if conn.connected or conn.connecting:
                if not logged:
                    logger.debug('Disconnecting from server')
                    logged = True
                await conn.disconnect()
        self.slots = []
        self.loop = None

    async def monitor_connections(self):
        '''
        Monitor and close open and non-busy connections one-by-one.
        '''
        while True:
            await trio.sleep(30.0)
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
                if conn.connected and conn.available:
                    logger.debug('Closing due to idleness: %s', conn)
                    await conn.disconnect()
                    break

    #@retry(retry=retry_if_exception_type() & retry_unless_exception_type(InvalidAuthentification),
    #       stop=stop_after_attempt(3),
    #       wait=wait_exponential(multiplier=1, max=10))
    async def acquire_connection(self, vault, skip_login=False):
        'return an available connection or block until one is free'
        #if self._monitor_task is None:
        #    self._monitor_task = \
        #            asyncio.get_event_loop().create_task(self.monitor_connections())

        # Prefer slots that have the same vault as we want
        prio_slots = sorted(self.slots, key=lambda c: c.vault == vault, reverse=True)

        for conn in prio_slots:
            if conn.connected and conn.available:
                conn.available = False
                if conn.vault != vault:
                    logger.debug('Found an available connection, but we need to switch the vault to %s', vault)
                    conn.connecting = True
                    try:
                        await conn.connect()
                        if not skip_login:
                            await conn.login(vault)
                    except:
                        await conn.clear_connection()
                        raise
                elif vault:
                    logger.debug('Found an available connection for %s', vault)
                else:
                    logger.debug('Found an available connection %s', conn)
                conn.available = False
                return conn

        # Try to find an unconnected slot and open a connection
        for conn in prio_slots:
            if not conn.connected and not conn.connecting:
                conn.connecting = True
                try:
                    await conn.connect()
                    if not skip_login:
                        await conn.login(vault)
                    conn.available = False
                    logger.debug("Choosing %s", conn)
                    return conn
                except:
                    await conn.clear_connection()
                    raise
                break

        if len(self.slots) < (1 if self.concurrency is None else self.concurrency):
            # spawn a new connection
            conn = BinaryStorageConnection(self)
            await conn.connect()
            if not skip_login:
                await conn.login(vault)
            conn.available = False
            self.slots.append(conn)
            logger.debug("Created and using %s", conn)
            return conn

        logger.debug("Wait for empty slot in: %s", self.slots)

        await trio.sleep(1.0)

        # if we haven't found one, try again
        return await self.acquire_connection(vault)


def get_manager_instance() -> BinaryStorageManager:
    if not hasattr(get_manager_instance, '_manager'):
        get_manager_instance._manager = BinaryStorageManager() # type: ignore
    return get_manager_instance._manager # type: ignore


class BinaryStorageBackend(StorageBackend):
    '''
    Implements the actual backend for the vault. Each Vault will have its own BinaryStorageBackend
    object associated with it, but all will use the same manager.
    '''

    def __init__(self, vault: Vault = None, auth=None, host=None, port=None,
            concurrency=None, username=None, password=None, ssl=True,
            ssl_verify=True) -> None:

        assert isinstance(ssl, bool)
        assert isinstance(ssl_verify, bool)

        manager = get_manager_instance()

        # Global connection settings
        manager.host = host
        manager.port = int(port)
        manager.ssl = ssl
        manager.ssl_verify = ssl_verify

        # Global user auth information
        if not manager.username: manager.username = username
        if not manager.password: manager.password = password
        manager.concurrency = int(concurrency)

        # Vault specific login information
        self.vault = vault
        self.auth = auth
        self.connected = False
        self.invalid_auth = False

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

    @asynccontextmanager
    async def _acquire_connection(self, ignore_vault=False, skip_login=False):
        conn = await get_manager_instance().acquire_connection(
            None if ignore_vault else self.vault,
            skip_login=skip_login
        )
        try:
            yield conn
        except trio.Cancelled:
            logger.debug('Task has been cancelled within context, clearing connection.')
            await conn.clear_connection()
        except:
            logger.exception('Exception in connection')
            await conn.clear_connection()
            raise
        finally:
            conn.available = True

    async def init(self, identity: Identity) -> Revision:
        self.auth = None
        try:
            async with self._acquire_connection(ignore_vault=True) as conn:
                conn.vault = self.vault
                # after successful login, write back config
                revision = await conn.create_vault(identity)
                self.invalid_auth = False
                conn.logger.info('Successfully logged in and stored auth token')
                return revision
        except InvalidAuthentification:
            self.invalid_auth = True
            raise

    async def open(self):
        if self.vault and not self.vault.config.get('vault.id'):
            raise VaultNotInitialized()
        stats = get_manager_instance().get_stats()
        if stats['closed'] == stats['total']:
            async with self._acquire_connection() as conn:
                self.invalid_auth = False
                version = await conn.version()
                conn.logger.debug('Logged in to server (version %s)', version)

    async def vault_size(self, vault):
        async with self._acquire_connection() as conn:
            size = await conn.vault_size(vault)
            conn.logger.debug('Vault size is: %s', format_size(size))
            return size

    async def changes(self, since_rev, to_rev):
        async with self._acquire_connection() as conn:
            async for rev in conn.changes(since_rev, to_rev):
                yield rev

    async def upload(self, bundle, identity):
        async with self._acquire_connection() as conn:
            return (await conn.upload(bundle, identity))

    async def download(self, bundle):
        async with self._acquire_connection() as conn:
            try:
                await conn.download(bundle)
            except UnsuccessfulResponse:
                conn.logger.error('Could not download bundle: %s', str(bundle))

    async def signup(self, username, password, firstname, surname):
        async with self._acquire_connection(skip_login=True) as conn:
            return await conn.signup(username, password, firstname, surname)

    async def remove_file(self, bundle: Bundle, identity: Identity) -> Revision:
        async with self._acquire_connection() as conn:
            return await conn.remove_file(bundle, identity)

    async def set_vault_metadata(self, identity: Identity) -> Revision:
        async with self._acquire_connection() as conn:
            return await conn.set_vault_metadata(identity)

    async def upload_identity(self, identity: Identity, description: str="") -> Revision:
        async with self._acquire_connection() as conn:
            return await conn.upload_identity(identity, description)

    async def add_user_vault_key(self, identity: Identity, user_id: str,
                                 user_identity: Identity, vault_key_package: bytes) -> Revision:
        async with self._acquire_connection() as conn:
            return await conn.add_user_vault_key(identity, user_id, user_identity, vault_key_package)

    async def remove_user_vault_key(self, identity: Identity, user_id: str,
                                 user_identity: Identity) -> Revision:
        async with self._acquire_connection() as conn:
            return await conn.remove_user_vault_key(identity, user_id, user_identity)

    async def list_vaults(self):
        async with self._acquire_connection() as conn:
            return (await conn.list_vaults())

    async def list_keys(self, user: Optional[str] = None):
        async with self._acquire_connection() as conn:
            return (await conn.list_keys(user))

    async def user_info(self):
        async with self._acquire_connection() as conn:
            return (await conn.user_info())

    async def add_vault_user(self, user_id: str, identity: Identity) -> Revision:
        async with self._acquire_connection() as conn:
            return (await conn.add_vault_user(user_id, identity))

    async def list_vaults_for_identity(self, identity: Identity):
        async with self._acquire_connection() as conn:
            return (await conn.list_vaults_for_identity(identity))

    def __getattr__(self, name):
        async def myco(*args, **kwargs):
            async with self._acquire_connection() as conn:
                result = await getattr(conn, name)(*args, **kwargs)
            return result
        return myco
