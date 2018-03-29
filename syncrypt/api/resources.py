# tastypie-like asyncio-aware resources
import asyncio
import enum
import itertools
import json
import logging
import os.path

import iso8601
from aiohttp import web
from syncrypt.exceptions import VaultNotInitialized
from syncrypt.models import Identity
from syncrypt.utils.format import format_size
from tzlocal import get_localzone

from ..models.bundle import VirtualBundle
from ..pipes import Once
from .auth import require_auth_token
from .responses import JSONResponse

logger = logging.getLogger(__name__)


class Resource(object):
    version = 'v1'
    resource_name = None

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
    async def dispatch_list(self, request):
        objs = await self.get_obj_list(request)
        return JSONResponse([self.dehydrate(obj) for obj in objs])

    @require_auth_token
    async def dispatch_get(self, request):
        obj = await self.get_obj(request)
        return JSONResponse(self.dehydrate(obj))

    async def dispatch_options(self, request):
        return JSONResponse({})

    @require_auth_token
    async def dispatch_delete(self, request):
        obj = await self.get_obj(request)
        await self.delete_obj(request, obj)
        return JSONResponse({}) # return 200 without data

    @require_auth_token
    async def dispatch_put(self, request):
        obj = await self.put_obj(request)
        return JSONResponse(self.dehydrate(obj))

    @require_auth_token
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
                '/{version}/{name}/{{id}}/history/'.format(**opts),
                self.dispatch_history)
        router.add_route('POST',
                '/{version}/{name}/{{id}}/export/'.format(**opts),
                self.dispatch_export)

    def get_id(self, v):
        return str(v.id)

    def dehydrate(self, v, vault_info={}):
        dct = super(VaultResource, self).dehydrate(v)

        dct.update(folder=v.folder, state=v.state, remote_id=v.config.id,
                   metadata=v.metadata, ignore=v.config.get('vault.ignore').split(','))

        # Annotate each obj with information from the server
        vault_size = vault_info.get('byte_size', 0)
        modification_date = vault_info.get('modification_date')
        if isinstance(modification_date, bytes):
            modification_date = modification_date.decode()

        # Compile some information about the underlying crypto system(s)
        crypt_info = {
            'aes_key_len': v.config.aes_key_len,
            'rsa_key_len': v.config.rsa_key_len,
            'key_algo': 'rsa',
            'transfer_algo': 'aes',
            'hash_algo': v.config.hash_algo,
            'fingerprint': v.identity.get_fingerprint() \
                    if v.identity and v.identity.is_initialized() else None
        }

        dct.update(
            size=vault_size,
            user_count=vault_info.get('user_count', 0),
            file_count=vault_info.get('file_count', 0),
            revision_count=vault_info.get('revision_count', 0),
            modification_date=modification_date,
            crypt_info=crypt_info
        )
        return dct

    async def get_obj_list(self, request):
        return self.app.vaults

    def find_vault_by_id(self, vault_id):
        'deprecated'
        return self.app.find_vault_by_id(vault_id)

    async def get_obj(self, request):
        return self.find_vault_by_id(request.match_info['id'])

    async def delete_obj(self, request, obj):
        if request.GET.get('wipe') == '1':
            logger.warn('Deleting/wiping vault: %s', obj)
            await self.app.unwatch_vault(obj)
            await self.app.delete_vault(obj)
        else:
            logger.warn('Removing vault: %s', obj)
            await self.app.unwatch_vault(obj)
            await self.app.remove_vault(obj)

    @require_auth_token
    async def dispatch_list(self, request):
        objs = await self.get_obj_list(request)
        backend = await self.app.open_backend()

        # Make a map from vault id -> vault info
        v_info = {v['id'].decode(): v for v in (await backend.list_vaults())}

        await backend.close()
        return JSONResponse([self.dehydrate(obj, v_info.get(obj.config.get('vault.id'), {})) for obj in objs])


    async def dispatch_fingerprints(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)
        fingerprint_list = await vault.backend.list_vault_user_key_fingerprints()
        return JSONResponse(fingerprint_list)

    async def dispatch_history(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)
        local_tz = get_localzone()
        queue = await vault.backend.changes(None, None, verbose=True)
        log_items = []
        while True:
            item = await queue.get()
            if item is None:
                break
            store_hash, metadata, server_info = item
            bundle = VirtualBundle(None, vault, store_hash=store_hash)
            await bundle.write_encrypted_metadata(Once(metadata))
            rev_id = server_info['id'].decode(vault.config.encoding)
            created_at = server_info['created_at'].decode(vault.config.encoding)
            operation = server_info['operation'].decode(vault.config.encoding)
            user_email = server_info['email'].decode(vault.config.encoding)
            log_items.append({
                'operation': operation,
                'user_email': user_email,
                'created_at': created_at,
                'path': bundle.relpath
            })
        return JSONResponse({'items': log_items})

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

        async def push_and_watch(vault):
            await self.app.push_vault(vault)
            # TODO No wait here!
            #await self.app.watch(vault)

        async def init_and_push(vault):
            await self.app.open_or_init(vault)
            await self.app.push_vault(vault)

        content = await request.content.read()
        request_dict = json.loads(content.decode())

        if 'id' in request_dict:
            vault = await self.app.clone(request_dict['id'], request_dict['folder'])
            asyncio.get_event_loop().create_task(pull_and_watch(vault))
        elif 'import_package' in request_dict:
            vault = await self.app.import_package(
                    request_dict['import_package'], request_dict['folder'])
            asyncio.get_event_loop().create_task(pull_and_watch(vault))
        else:
            vault = self.app.add_vault_by_path(request_dict['folder'])
            asyncio.get_event_loop().create_task(init_and_push(vault))
        return vault

    async def put_obj(self, request):
        content = await request.content.read()
        request_dict = json.loads(content.decode())
        vault = self.find_vault_by_id(request.match_info['id'])
        if vault is None:
            raise ValueError() # this should return 404
        if 'metadata' in request_dict:
            vault.metadata = request_dict['metadata']
            try:
                await vault.backend.open()
                await vault.backend.set_vault_metadata()
            except VaultNotInitialized:
                logger.warn('Could not sync metadata to server right now, as the vault is not ' +
                            'initialized yet. However, metadata has been stored locally and ' +
                            'will be synced when the vault is initialized.')
        return vault


class FlyingVaultResource(Resource):
    """
    A Flying Vault represents a Vault that the user has access to but is not
    yet cloned to the local machine.
    """
    resource_name = 'flying-vault'

    def get_id(self, obj):
        return obj['id']

    def dehydrate(self, obj):
        deh_obj = super(FlyingVaultResource, self).dehydrate(obj)
        deh_obj['metadata'] = obj.get('metadata', {})
        deh_obj['size'] = obj.get('byte_size')
        deh_obj['user_count'] = obj.get('user_count')
        deh_obj['file_count'] = obj.get('file_count')
        deh_obj['revision_count'] = obj.get('revision_count')
        deh_obj['modification_date'] = obj.get('modification_date')
        deh_obj['remote_id'] = obj.get('id')
        ignored = set(obj.keys()) - set(deh_obj.keys())
        if len(ignored) > 0:
            logger.debug('Ignored vault keys: %s', ignored)
        return deh_obj

    async def get_obj_list(self, request):
        vaults = []
        backend = await self.app.open_backend()

        # Make a map from vault id -> vault info
        v_info = {v['id'].decode(): v for v in (await backend.list_vaults())}

        my_fingerprint = self.app.identity.get_fingerprint()

        for (vault, user_vault_key, encrypted_metadata) in \
                (await backend.list_vaults_by_fingerprint(my_fingerprint)):

            await asyncio.sleep(0.001)

            vault_id = vault['id'].decode('utf-8')

            logger.debug("Received vault: %s (with%s metadata)", vault_id, '' if encrypted_metadata else 'out')

            if encrypted_metadata:
                metadata = await self.app._decrypt_metadata(encrypted_metadata, user_vault_key)
            else:
                metadata = None

            vault_info = v_info.get(vault_id, {})
            vault_size = vault_info.get('byte_size', 0)
            modification_date = vault_info.get('modification_date')
            if isinstance(modification_date, bytes):
                modification_date = modification_date.decode()
            vaults.append(dict(vault, id=vault_id, metadata=metadata,
                size=vault_size,
                user_count=vault_info.get('user_count', 0),
                file_count=vault_info.get('file_count', 0),
                revision_count=vault_info.get('revision_count', 0),
                modification_date=modification_date
            ))

        await backend.close()
        return vaults


class UserResource(Resource):
    resource_name = 'user'

    def add_routes(self, router):
        opts = {'version': self.version, 'name': self.resource_name}
        router.add_route('GET', '/{version}/{name}/{{id}}/keys/'.format(**opts), self.dispatch_keys)

    @require_auth_token
    async def dispatch_keys(self, request):
        email = request.match_info['id']
        backend = await self.app.open_backend()
        key_list = await backend.list_keys(email)
        response = JSONResponse([{
            'description': key['description'],
            'created_at': key['created_at'],
            'fingerprint': key['fingerprint']
        } for key in key_list])
        await backend.close()
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
        return {'email': request.match_info['email']}

    def get_id(self, obj):
        return obj['email']

    def dehydrate(self, obj):
        return dict(obj, resource_uri=self.get_resource_uri(obj))

    @require_auth_token
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
        await vault.backend.open()
        return (await vault.backend.list_vault_users())

    async def delete_obj(self, request, obj):
        vault = self.get_vault(request)
        await vault.backend.open()
        email = obj['email']
        logger.info('Removing user "%s" from %s', email, vault)
        await vault.backend.remove_vault_user(email)

    async def post_obj(self, request):
        vault = self.get_vault(request)
        content = await request.content.read()
        data = json.loads(content.decode())
        email = data['email']
        await vault.backend.open()
        logger.info('Adding user "%s" to %s', email, vault)
        await vault.backend.add_vault_user(email)
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

