# tastypie-like asyncio-aware resources
import asyncio
import itertools
import json
import logging
import os.path

import smokesignal
import trio_asyncio
from aiohttp import web
from syncrypt.models import Identity, Revision, UserVaultKey, Vault
from syncrypt.utils.format import datetime_format_iso8601
from syncrypt.exceptions import VaultException

from .auth import require_auth_token
from .responses import JSONResponse

logger = logging.getLogger(__name__)


def rev_to_json(rev: Revision):
    # Maybe Revision should get own resource?
    return {
            'operation': rev.operation,
            'user_email': rev.creator_id,
            'user_fingerprint': rev.user_fingerprint,
            'verified': True,
            'revision_id': rev.revision_id,
            'created_at': datetime_format_iso8601(rev.created_at),
            'path': rev.path.decode() if rev.path else None
            }


class Resource(object):
    version = 'v1'
    resource_name = None # type: str

    def __init__(self, app):
        self.app = app

    def add_routes(self, router):
        opts = {'version': self.version, 'name': self.resource_name}
        router.add_route('POST', '/{version}/{name}/'.format(**opts), self.dispatch_post)
        router.add_route('PUT', '/{version}/{name}/{{id}}/'.format(**opts), self.dispatch_put)
        router.add_route('PUT', '/{version}/{name}/{{id}}'.format(**opts), self.dispatch_put)
        router.add_route('GET', '/{version}/{name}/'.format(**opts), self.dispatch_list)
        router.add_route('GET', '/{version}/{name}/{{id}}/'.format(**opts), self.dispatch_get)
        router.add_route('GET', '/{version}/{name}/{{id}}'.format(**opts), self.dispatch_get)
        router.add_route('OPTIONS', '/{version}/{name}/'.format(**opts), self.dispatch_options)
        router.add_route('OPTIONS', '/{version}/{name}/{{id}}/'.format(**opts), self.dispatch_options)
        router.add_route('DELETE', '/{version}/{name}/{{id}}/'.format(**opts), self.dispatch_delete)
        router.add_route('DELETE', '/{version}/{name}/{{id}}'.format(**opts), self.dispatch_delete)

    def dehydrate(self, obj):
        'obj -> serializable dict'
        return {'resource_uri': self.get_resource_uri(obj), 'id': self.get_id(obj)}

    def get_id(self, obj):
        raise NotImplementedError

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_list(self, request):
        objs = await self.get_obj_list(request)
        return JSONResponse([self.dehydrate(obj) for obj in objs])

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_get(self, request):
        obj = await self.get_obj(request)
        return JSONResponse(self.dehydrate(obj))

    async def dispatch_options(self, request):
        return JSONResponse({})

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_delete(self, request):
        obj = await self.get_obj(request)
        await self.delete_obj(request, obj)
        return JSONResponse({}) # return 200 without data

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_put(self, request):
        obj = await self.put_obj(request)
        return JSONResponse(self.dehydrate(obj))

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_post(self, request):
        obj = await self.post_obj(request)
        return JSONResponse(self.dehydrate(obj))

    async def get_obj_list(self, request):
        raise NotImplementedError

    async def get_obj(self, request):
        raise NotImplementedError

    async def put_obj(self, request):
        raise NotImplementedError

    async def post_obj(self, request):
        raise NotImplementedError

    async def delete_obj(self, request, obj):
        raise NotImplementedError

    def get_resource_uri(self, obj):
        return "/{version}/{name}/{id}/".format(version=self.version,
                name=self.resource_name, id=self.get_id(obj))


class VaultResource(Resource):
    resource_name = 'vault'

    def add_routes(self, router):
        super(VaultResource, self).add_routes(router)
        opts = {'version': self.version, 'name': self.resource_name}
        router.add_route('GET',
                '/{version}/{name}/{{id}}/fingerprints/'.format(**opts),
                self.dispatch_fingerprints)
        router.add_route('GET',
                '/{version}/{name}/{{id}}/resync/'.format(**opts),
                self.dispatch_resync)
        router.add_route('GET',
                '/{version}/{name}/{{id}}/history/'.format(**opts),
                self.dispatch_history)
        router.add_route('GET',
                '/{version}/{name}/{{id}}/historystream/'.format(**opts),
                self.dispatch_history_stream)
        router.add_route('POST',
                '/{version}/{name}/{{id}}/export/'.format(**opts),
                self.dispatch_export)

    def get_id(self, v):
        return str(v.id)

    def dehydrate(self, v):
        dct = super(VaultResource, self).dehydrate(v)
        try:
            remote_id = v.config.id
            ignore_paths = v.config.get('vault.ignore').split(',')
            aes_key_len = v.config.aes_key_len
            rsa_key_len = v.config.rsa_key_len
            hash_algo = v.config.hash_algo
            metadata = v._metadata
            fingerprint = v.identity.get_fingerprint() \
                    if v.identity and v.identity.is_initialized() else None

        except VaultException:
            remote_id = None
            ignore_paths = []
            aes_key_len = 0
            rsa_key_len = 0
            hash_algo = ''
            fingerprint = None
            metadata = {}

        dct.update(
             folder=v.folder,
             state=v.state,
             remote_id=remote_id,
             metadata=metadata,
             ignore_paths=ignore_paths
        )

        # Annotate each obj with vault information from the model
        dct.update(
            size=v.byte_size,
            user_count=v.user_count,
            file_count=v.file_count,
            revision_count=v.revision_count,
            modification_date=v.modification_date and datetime_format_iso8601(v.modification_date),
        )

        # Compile some information about the underlying crypto system(s)
        crypt_info = {
            'aes_key_len': aes_key_len,
            'rsa_key_len': rsa_key_len,
            'key_algo': 'rsa',
            'transfer_algo': 'aes',
            'hash_algo': hash_algo,
            'fingerprint': fingerprint
        }
        dct.update(crypt_info=crypt_info)
        return dct

    async def get_obj_list(self, request):
        return self.app.vaults

    def find_vault_by_id(self, vault_id):
        'deprecated'
        return self.app.find_vault_by_id(vault_id)

    async def get_obj(self, request):
        return self.find_vault_by_id(request.match_info['id'])

    async def delete_obj(self, request, obj):
        if request.query.get('wipe') == '1':
            logger.warning('Deleting/wiping vault: %s', obj)
            await self.app.delete_vault(obj)
        else:
            logger.warning('Removing vault: %s', obj)
            await self.app.remove_vault(obj)

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_fingerprints(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)
        user_vault_keys = self.app.user_vault_keys.list_for_vault(vault)
        return JSONResponse([key.fingerprint for key in user_vault_keys])

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_resync(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)
        await self.app.resync_vault(vault)
        return JSONResponse({})

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_history(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)

        log_items = []
        for rev in self.app.revisions.list_for_vault(vault):
            log_items.append(rev_to_json(rev))

        return JSONResponse({'items': log_items})

    async def dispatch_history_stream(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)

        # limit = int(request.query.get("limit", 100))
        ws = web.WebSocketResponse()
        logger.debug("WebSocket connection opened for %s", request.path)

        await ws.prepare(request)
        MAX_ITEMS_BEFORE_DRAIN = 64
        MAX_ITEMS_LOGGING_QUEUE = 4096

        queue = asyncio.Queue(maxsize=MAX_ITEMS_LOGGING_QUEUE)  # type: asyncio.Queue
        async def writer():
            while not ws.closed:
                item = await queue.get()
                try:
                    # Send the item and also try to get up to MAX_ITEMS_BEFORE_DRAIN items from the
                    # queue before draining the connection
                    for _ in range(MAX_ITEMS_BEFORE_DRAIN):
                        await ws.send_str(
                            JSONResponse.encode_body(rev_to_json(item)).decode('utf-8')
                        )
                        item = queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass

        async def reader():
            while not ws.closed:
                await ws.receive()

        @smokesignal.on("post_apply_revision")
        def handler(*args, **kwargs):
            revision = kwargs['revision']
            revision_vault = kwargs['vault']
            if revision_vault.id == vault.id:
                queue.put_nowait(revision)

        writer_future = asyncio.ensure_future(writer())
        await reader()
        writer_future.cancel()
        smokesignal.disconnect(handler)
        logger.debug("WebSocket connection closed for %s", request.path)
        return ws

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_export(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)

        try:
            content = await request.content.read()
            request_dict = json.loads(content.decode())
        except:
            return web.Response(status=400, text='Need JSON request body.')

        if not 'path' in request_dict:
            return web.Response(status=400, text='Missing parameter "path".')

        path = request_dict['path']
        if os.path.isdir(path):
            path = os.path.join(path, '{0}.zip'.format(vault.config.id))

        await self.app.export_package(path, vault=vault)

        return JSONResponse({'status': 'ok', 'filename': path})

    async def post_obj(self, request):
        async def pull_and_watch(vault):
            await self.app.pull_vault(vault)
            # TODO No wait here!
            #await self.app.watch(vault)

        async def init_and_push(vault):
            await self.app.open_or_init(vault)
            await self.app.pull_vault(vault)
            await self.app.push_vault(vault)

        content = await request.content.read()
        request_dict = json.loads(content.decode())

        if not 'folder' in request_dict or not request_dict['folder']:
            raise ValueError("Invalid value for parameter: 'folder'")

        if 'id' in request_dict:
            vault = await self.app.clone(
                    request_dict['id'],
                    request_dict['folder'],
                    async_init=True
            )
        elif 'import_package' in request_dict:
            raise NotImplementedError()
            #vault = await self.app.import_package(
            #        request_dict['import_package'], request_dict['folder'])
            #self.app.save_vault_dir_in_config(vault)
            #asyncio.get_event_loop().create_task(pull_and_watch(vault))
        else:
            vault = await self.app.add_vault(Vault(request_dict['folder']),
                        async_init=True,
                        async_push=True
            )
        return vault

    async def put_obj(self, request):
        content = await request.content.read()
        request_dict = json.loads(content.decode())
        vault = self.find_vault_by_id(request.match_info['id'])
        if vault is None:
            raise ValueError() # this should return 404

        if 'ignore_paths' in request_dict:

            if not isinstance(request_dict['ignore_paths'], list):
                raise ValueError("ignore_paths must be a list")

            with vault.config.update_context():
                vault.config.set('vault.ignore', ','.join(request_dict['ignore_paths']))

        if 'metadata' in request_dict:
            vault._metadata = request_dict['metadata']
            await self.app.update_vault_metadata(vault)

        return vault


class FlyingVaultResource(Resource):
    """
    A Flying Vault represents a Vault that the user has access to but is not
    yet cloned to the local machine.
    """
    resource_name = 'flying-vault'

    def get_id(self, obj):
        return obj.id

    def dehydrate(self, obj):
        deh_obj = super(FlyingVaultResource, self).dehydrate(obj)
        deh_obj['metadata'] = obj.vault_metadata
        deh_obj['size'] = obj.byte_size
        deh_obj['user_count'] = obj.user_count
        deh_obj['file_count'] = obj.file_count
        deh_obj['revision_count'] = obj.revision_count
        deh_obj['modification_date'] = obj.modification_date and datetime_format_iso8601(obj.modification_date)
        deh_obj['remote_id'] = obj.id
        return deh_obj

    async def get_obj_list(self, request):
        return self.app.flying_vaults.all()

    async def get_obj(self, request):
        return self.app.flying_vaults.get(request.match_info['id'])

    async def delete_obj(self, request, obj):
        if request.query.get('wipe') == '1':
            vault_id = obj.id
            logger.warning('Deleting/wiping flying vault: %s', vault_id)
            backend = await self.app.open_backend()
            await backend.delete_vault(vault_id=vault_id)
        else:
            raise NotImplementedError


class UserResource(Resource):
    resource_name = 'user'

    def add_routes(self, router):
        opts = {'version': self.version, 'name': self.resource_name}
        router.add_route('GET', '/{version}/{name}/{{id}}/keys/'.format(**opts), self.dispatch_keys)

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_keys(self, request):
        email = request.match_info['id']
        backend = await self.app.open_backend()
        key_list = await backend.list_keys(email)
        response = JSONResponse([{
            'description': key['description'],
            'created_at': key['created_at'],
            'fingerprint': key['fingerprint']
        } for key in key_list])
        return response


class VaultUserResource(Resource):
    resource_name = 'users'

    def add_routes(self, router):
        opts = {'version': self.version, 'name': self.resource_name}
        router.add_route('POST',
                '/{version}/vault/{{vault_id}}/{name}/'.format(**opts),
                self.dispatch_post)
        router.add_route('GET',
                '/{version}/vault/{{vault_id}}/{name}/'.format(**opts),
                self.dispatch_list)
        router.add_route('GET',
                '/{version}/vault/{{vault_id}}/{name}/{{email}}/'.format(**opts),
                self.dispatch_get)
        router.add_route('DELETE',
                '/{version}/vault/{{vault_id}}/{name}/{{email}}/'.format(**opts),
                self.dispatch_delete)
        router.add_route('GET',
                '/{version}/vault/{{vault_id}}/{{name}}/{{email}}/keys/'.format(**opts),
                self.dispatch_keys)

    def get_vault(self, request):
        vault_res = VaultResource(self.app)
        vault = vault_res.find_vault_by_id(request.match_info['vault_id'])
        if vault is None:
            raise ValueError('Vault not found')
        return vault

    async def get_obj(self, request):
        return {
            'email': request.match_info['email']
        }

    def get_id(self, obj: UserVaultKey):
        return obj.user_id if hasattr(obj, 'user_id') else obj['email']

    def dehydrate(self, obj: UserVaultKey):
        return {
            'email': self.get_id(obj),
            'first_name': '', # TBD
            'last_name': '', # TBD
            'resource_uri': self.get_resource_uri(obj)
        }

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def dispatch_keys(self, request):
        vault = self.get_vault(request)
        email = request.match_info['email']
        key_list = await vault.backend.list_keys(email)
        return JSONResponse([{
            'description': key['description'],
            'created_at': key['created_at'],
            'fingerprint': key['fingerprint']
        } for key in key_list])

    async def get_obj_list(self, request):
        vault = self.get_vault(request)
        return self.app.vault_users.list_for_vault(vault)

    async def delete_obj(self, request, obj):
        vault = self.get_vault(request)
        await vault.backend.open()
        email = obj.user_id
        logger.info('Removing user "%s" from %s', email, vault)
        await vault.backend.remove_vault_user(email)

    async def post_obj(self, request):
        vault = self.get_vault(request)
        content = await request.content.read()
        data = json.loads(content.decode())
        email = data['email']
        logger.info('Adding user "%s" to %s', email, vault)
        await self.app.add_vault_user(vault, email)
        if 'fingerprints' in data:
            key_list = await vault.backend.list_keys(email)
            key_list = [key for key in key_list if key['fingerprint'] in data['fingerprints']]
            for key in key_list:
                # retrieve key and verify fingerprint
                fingerprint = key['fingerprint']
                public_key = key['public_key']
                identity = Identity.from_key(public_key, vault.config)
                assert identity.get_fingerprint() == fingerprint
                await self.app.add_user_vault_key(vault, email, identity)
        return {'email': email}


class BundleResource(Resource):
    resource_name = 'bundle'

    def add_routes(self, router):
        opts = {'version': self.version, 'name': self.resource_name}
        router.add_route('PUT', '/{version}/vault/{{vault_id}}/{name}/'.format(**opts), self.dispatch_put)
        router.add_route('GET', '/{version}/vault/{{vault_id}}/{name}/'.format(**opts), self.dispatch_list)
        router.add_route('GET', '/{version}/vault/{{vault_id}}/{name}/{{id}}'.format(**opts), self.dispatch_get)
        router.add_route('DELETE', '/{version}/vault/{{vault_id}}/{name}/{{id}}'.format(**opts), self.dispatch_delete)

    def get_resource_uri(self, obj):
        vault_res = VaultResource(self.app)
        return "/{version}/vault/{vault_id}/{name}/{id}/".format(
                version=self.version, name=self.resource_name,
                id=self.get_id(obj), vault_id=vault_res.get_id(obj.vault))

    def get_id(self, bundle):
        return bundle.store_hash

    def dehydrate(self, bundle):
        dct = super(BundleResource, self).dehydrate(bundle)
        dct.update(path=bundle.relpath)
        return dct

    async def get_obj_list(self, request):
        vault_res = VaultResource(self.app)
        vault = vault_res.find_vault_by_id(request.match_info['vault_id'])
        if vault is None:
            raise ValueError('Vault not found')
        return itertools.islice(vault.walk_disk(), 0, 20)

    async def get_obj(self, request):
        raise NotImplementedError
