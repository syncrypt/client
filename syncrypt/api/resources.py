# tastypie-like asyncio-aware resources
import asyncio
import enum
import itertools
import json
import logging
import os.path

import iso8601
from aiohttp import web
from tzlocal import get_localzone
from datetime import timezone

from syncrypt.exceptions import VaultNotInitialized
from syncrypt.models import Identity
from syncrypt.utils.format import format_size

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

    def dehydrate(self, v):
        dct = super(VaultResource, self).dehydrate(v)

        dct.update(folder=v.folder, state=v.state, remote_id=v.config.id,
                   metadata=v._metadata, ignore=v.config.get('vault.ignore').split(','))

        # Annotate each obj with vault information from the model
        dct.update(
            size=v.byte_size,
            user_count=v.user_count,
            file_count=v.file_count,
            revision_count=v.revision_count,
            modification_date=v.modification_date,
        )

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
        if request.GET.get('wipe') == '1':
            logger.warn('Deleting/wiping vault: %s', obj)
            await self.app.unwatch_vault(obj)
            await self.app.delete_vault(obj)
        else:
            logger.warn('Removing vault: %s', obj)
            await self.app.unwatch_vault(obj)
            await self.app.remove_vault(obj)

    @require_auth_token
    async def dispatch_list(self, request, force_refresh=True):
        if request.query.get('force_refresh', '0') == '1':
            await self.app.refresh_vault_info()

        return await super(VaultResource, self).dispatch_list(request)

    async def dispatch_fingerprints(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)
        fingerprint_list = await vault.backend.list_vault_user_key_fingerprints()
        return JSONResponse(fingerprint_list)

    async def dispatch_history(self, request):
        vault_id = request.match_info['id']
        vault = self.find_vault_by_id(vault_id)

        log_items = []
        local_tz = get_localzone()
        for rev in self.app.revisions.list_for_vault(vault):
            log_items.append({
                'operation': rev.operation,
                'user_email': rev.user_email,
                'created_at': rev.created_at.replace(tzinfo=timezone.utc)\
                                            .astimezone(local_tz)\
                                            .strftime('%x %X'),
                'path': rev.path
            })

        # Not sure if this is the best place to trigger update
        asyncio.get_event_loop().create_task(
            self.app.revisions.update_for_vault(vault)
        )

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
            self.app.save_vault_dir_in_config(vault)
            asyncio.get_event_loop().create_task(pull_and_watch(vault))
        elif 'import_package' in request_dict:
            vault = await self.app.import_package(
                    request_dict['import_package'], request_dict['folder'])
            self.app.save_vault_dir_in_config(vault)
            asyncio.get_event_loop().create_task(pull_and_watch(vault))
        else:
            vault = self.app.add_vault_by_path(request_dict['folder'])
            self.app.save_vault_dir_in_config(vault)
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
        return obj.id

    def dehydrate(self, obj):
        deh_obj = super(FlyingVaultResource, self).dehydrate(obj)
        deh_obj['metadata'] = obj.vault_metadata
        deh_obj['size'] = obj.byte_size
        deh_obj['user_count'] = obj.user_count
        deh_obj['file_count'] = obj.file_count
        deh_obj['revision_count'] = obj.revision_count
        deh_obj['modification_date'] = obj.modification_date
        deh_obj['remote_id'] = obj.id
        return deh_obj

    async def get_obj_list(self, request):
        # TODO: schedule update task at most once
        asyncio.get_event_loop().create_task(
            self.app.flying_vaults.update()
        )
        return self.app.flying_vaults.all()

    async def get_obj(self, request):
        return self.app.flying_vaults.get(request.match_info['id'])

    async def delete_obj(self, request, obj):
        if request.GET.get('wipe') == '1':
            vault_id = obj.id
            logger.warn('Deleting/wiping flying vault: %s', vault_id)
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
        return await vault.backend.list_vault_users()

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
