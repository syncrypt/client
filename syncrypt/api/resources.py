# tastypie-like asyncio-aware resources
import json
import logging
import os.path
import itertools

import asyncio
from aiohttp import web
from .auth import require_auth_token
from syncrypt.utils.format import format_size

logger = logging.getLogger(__name__)


class JSONResponse(web.Response):
    def __init__(self, obj, **kwargs):
        super(JSONResponse, self).__init__(
                body=json.dumps(obj).encode('utf-8'),
                content_type='application_json',
                **kwargs)


class Resource(object):
    version = 'v1'

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
        router.add_route('DELETE', '/{version}/{name}/{{id}}/'.format(**opts), self.dispatch_delete)
        router.add_route('DELETE', '/{version}/{name}/{{id}}'.format(**opts), self.dispatch_delete)

    def dehydrate(self, obj):
        'obj -> serializable dict'
        return {'resource_uri': self.get_resource_uri(obj), 'id': self.get_id(obj)}

    def get_id(self, obj):
        raise NotImplementedError

    @asyncio.coroutine
    @require_auth_token
    def dispatch_list(self, request):
        objs = yield from self.get_obj_list(request)
        return JSONResponse([self.dehydrate(obj) for obj in objs])

    @asyncio.coroutine
    @require_auth_token
    def dispatch_get(self, request):
        obj = yield from self.get_obj(request)
        return JSONResponse(self.dehydrate(obj))

    @asyncio.coroutine
    @require_auth_token
    def dispatch_delete(self, request):
        obj = yield from self.get_obj(request)
        yield from self.delete_obj(request, obj)
        return JSONResponse({}) # return 200 without data

    @asyncio.coroutine
    @require_auth_token
    def dispatch_put(self, request):
        obj = yield from self.put_obj(request)
        return JSONResponse(self.dehydrate(obj))

    @asyncio.coroutine
    @require_auth_token
    def dispatch_post(self, request):
        obj = yield from self.post_obj(request)
        return JSONResponse(self.dehydrate(obj))

    @asyncio.coroutine
    def get_obj_list(self, request):
        raise NotImplementedError

    @asyncio.coroutine
    def get_obj(self, request):
        raise NotImplementedError

    @asyncio.coroutine
    def put_obj(self, request):
        raise NotImplementedError

    @asyncio.coroutine
    def delete_obj(self, request, obj):
        raise NotImplementedError

    def get_resource_uri(self, obj):
        return "/{version}/{name}/{id}/".format(version=self.version,
                name=self.resource_name, id=self.get_id(obj))

class VaultResource(Resource):
    resource_name = 'vault'

    def get_id(self, v):
        return str(v.config.get('vault.id'))

    def dehydrate(self, v, vault_info={}):
        dct = super(VaultResource, self).dehydrate(v)
        dct.update(folder=v.folder, status='ready', state=v.state, metadata=v.metadata)
        # Annotate each obj with information from the server
        vault_size = format_size(vault_info.get('byte_size', 0))
        dct.update(
            size=vault_size,
            user_count=vault_info.get('user_count', 0),
            file_count=vault_info.get('file_count', 0),
            revision_count=vault_info.get('revision_count', 0)
        )
        return dct

    @asyncio.coroutine
    def get_obj_list(self, request):
        return self.app.vaults

    def find_vault_by_id(self, vault_id):
        for v in self.app.vaults:
            if self.get_id(v) == vault_id:
                return v

    @asyncio.coroutine
    def get_obj(self, request):
        return self.find_vault_by_id(request.match_info['id'])

    @asyncio.coroutine
    def delete_obj(self, request, obj):
        if request.GET.get('wipe') == '1':
            logger.warn('Deleting/wiping vault: %s', obj)
            yield from self.app.unwatch_vault(obj)
            yield from self.app.delete_vault(obj)
        else:
            logger.warn('Removing vault: %s', obj)
            yield from self.app.unwatch_vault(obj)
            yield from self.app.remove_vault(obj)

    @asyncio.coroutine
    def dispatch_list(self, request):
        objs = yield from self.get_obj_list(request)
        backend = yield from self.app.open_backend()

        # Make a map from vault id -> vault info
        v_info = {v['id'].decode(): v for v in (yield from backend.list_vaults())}

        yield from backend.close()
        return JSONResponse([self.dehydrate(obj, v_info.get(obj.config.get('vault.id'), {})) for obj in objs])

    @asyncio.coroutine
    def post_obj(self, request):
        content = yield from request.content.read()
        request_dict = json.loads(content.decode())
        if 'id' in request_dict:
            vault = yield from self.app.clone(request_dict['id'], request_dict['folder'])

            @asyncio.coroutine
            def pull_and_watch(vault):
                yield from self.app.pull_vault(vault)
                yield from self.app.watch(vault)
            asyncio.get_event_loop().create_task(pull_and_watch(vault))
        else:
            vault = self.app.add_vault_by_path(request_dict['folder'])
            yield from self.app.open_or_init(vault)

            @asyncio.coroutine
            def push_and_watch(vault):
                yield from self.app.push_vault(vault)
                yield from self.app.watch(vault)
            asyncio.get_event_loop().create_task(push_and_watch(vault))
        return vault

    @asyncio.coroutine
    def put_obj(self, request):
        content = yield from request.content.read()
        request_dict = json.loads(content.decode())
        vault = self.find_vault_by_id(request.match_info['id'])
        if vault is None:
            raise ValueError() # this should return 404
        if 'metadata' in request_dict:
            vault.metadata = request_dict['metadata']
            yield from vault.backend.open()
            yield from vault.backend.set_vault_metadata()
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
        deh_obj['size'] = format_size(obj.get('byte_size'))
        deh_obj['user_count'] = obj.get('user_count')
        deh_obj['file_count'] = obj.get('file_count')
        deh_obj['revision_count'] = obj.get('revision_count')
        ignored = set(obj.keys()) - set(deh_obj.keys())
        if len(ignored) > 0:
            logger.debug('Ignored vault keys: %s', ignored)
        return deh_obj

    @asyncio.coroutine
    def get_obj_list(self, request):
        vaults = []
        backend = yield from self.app.open_backend()

        # Make a map from vault id -> vault info
        v_info = {v['id'].decode(): v for v in (yield from backend.list_vaults())}

        my_fingerprint = self.app.identity.get_fingerprint()

        for (vault, user_vault_key, encrypted_metadata) in \
                (yield from backend.list_vaults_by_fingerprint(my_fingerprint)):

            vault_id = vault['id'].decode('utf-8')

            logger.debug("Received vault: %s (with%s metadata)", vault_id, '' if encrypted_metadata else 'out')

            if encrypted_metadata:
                metadata = yield from self.app._decrypt_metadata(encrypted_metadata, user_vault_key)
            else:
                metadata = None

            vault_info = v_info.get(vault_id, {})
            vault_size = format_size(vault_info.get('byte_size', 0))
            vaults.append(dict(vault, id=vault_id, metadata=metadata,
                size=vault_size,
                user_count=vault_info.get('user_count', 0),
                file_count=vault_info.get('file_count', 0),
                revision_count=vault_info.get('revision_count', 0)))

        yield from backend.close()
        return vaults

    @asyncio.coroutine
    def get_obj(self, request):
        return find_vault_by_id(request.match_info['id'])

class UserResource(Resource):
    resource_name = 'user'

    def add_routes(self, router):
        opts = {'version': self.version, 'name': self.resource_name}
        router.add_route('GET', '/{version}/{name}/{{id}}/keys/'.format(**opts), self.dispatch_keys)

    @asyncio.coroutine
    @require_auth_token
    def dispatch_keys(self, request):
        email = request.match_info['id']
        backend = yield from self.app.open_backend()
        key_list = yield from backend.list_keys(email)
        response = JSONResponse([{
            'description': key['description'],
            'created_at': key['created_at'],
            'fingerprint': key['fingerprint']
        } for key in key_list])
        yield from backend.close()
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

    @asyncio.coroutine
    def get_obj(self, request):
        return {'email': request.match_info['email']}

    def get_id(self, obj):
        return obj['email']

    def dehydrate(self, obj):
        return dict(obj, resource_uri=self.get_resource_uri(obj))

    @asyncio.coroutine
    @require_auth_token
    def dispatch_keys(self, request):
        vault = self.get_vault(request)
        email = request.match_info['email']
        key_list = yield from vault.backend.list_keys(email)
        return JSONResponse([{
            'description': key['description'],
            'created_at': key['created_at'],
            'fingerprint': key['fingerprint']
        } for key in key_list])

    @asyncio.coroutine
    def get_obj_list(self, request):
        vault = self.get_vault(request)
        yield from vault.backend.open()
        return (yield from vault.backend.list_vault_users())

    @asyncio.coroutine
    def delete_obj(self, request, obj):
        vault = self.get_vault(request)
        yield from vault.backend.open()
        email = obj['email']
        logger.info('Removing user "%s" from %s', email, vault)
        yield from vault.backend.remove_vault_user(email)

    @asyncio.coroutine
    def post_obj(self, request):
        vault = self.get_vault(request)
        content = yield from request.content.read()
        data = json.loads(content.decode())
        email = data['email']
        yield from vault.backend.open()
        logger.info('Adding user "%s" to %s', email, vault)
        yield from vault.backend.add_vault_user(email)
        if 'fingerprints' in data:
            key_list = yield from vault.backend.list_keys(email)
            key_list = [key for key in key_list if key['fingerprint'] in data['fingerprints']]
            for key in key_list:
                # retrieve key and verify fingerprint
                fingerprint = key['fingerprint']
                public_key = key['public_key']
                yield from self.app.add_user_vault_key(vault, email, fingerprint, public_key)

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

    @asyncio.coroutine
    def get_obj_list(self, request):
        vault_res = VaultResource(self.app)
        vault = vault_res.find_vault_by_id(request.match_info['vault_id'])
        if vault is None:
            raise ValueError('Vault not found')
        return itertools.islice(vault.walk_disk(), 0, 20)

    @asyncio.coroutine
    def get_obj(self, request):
        raise NotImplementedError

