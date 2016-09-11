# tastypie-like asyncio-aware resources
import hashlib
import json
import logging
import os.path
import itertools

import asyncio
from aiohttp import web

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
        router.add_route('PUT', '/{version}/{name}/{{id}}'.format(**opts), self.dispatch_put)
        router.add_route('GET', '/{version}/{name}/'.format(**opts), self.dispatch_list)
        router.add_route('GET', '/{version}/{name}/{{id}}'.format(**opts), self.dispatch_get)
        router.add_route('DELETE', '/{version}/{name}/{{id}}'.format(**opts), self.dispatch_delete)

    def dehydrate(self, obj):
        'obj -> serializable dict'
        return {'resource_uri': self.get_resource_uri(obj), 'id': self.get_id(obj)}

    def get_id(self, obj):
        raise NotImplementedError

    @asyncio.coroutine
    def dispatch_list(self, request):
        objs = yield from self.get_obj_list(request)
        return JSONResponse([self.dehydrate(obj) for obj in objs])

    @asyncio.coroutine
    def dispatch_get(self, request):
        obj = yield from self.get_obj(request)
        return JSONResponse(self.dehydrate(obj))

    @asyncio.coroutine
    def dispatch_delete(self, request):
        obj = yield from self.get_obj(request)
        yield from self.delete_obj(obj)
        return JSONResponse({}) # return 200 without data

    @asyncio.coroutine
    def dispatch_put(self, request):
        obj = yield from self.put_obj(request)
        return JSONResponse(self.dehydrate(obj))

    @asyncio.coroutine
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
    def delete_obj(self, obj):
        raise NotImplementedError

    def get_resource_uri(self, obj):
        return "/{version}/{name}/{id}/".format(version=self.version,
                name=self.resource_name, id=self.get_id(obj))

class VaultResource(Resource):
    resource_name = 'vault'

    def add_routes(self, router):
        super(VaultResource, self).add_routes(router)
        opts = {'version': self.version, 'name': self.resource_name}

    def get_id(self, v):
        hash = hashlib.new('md5')
        hash.update(os.path.abspath(v.folder.encode()))
        return hash.hexdigest()

    def dehydrate(self, v):
        dct = super(VaultResource, self).dehydrate(v)
        dct.update(folder=v.folder, status='ready', user_count=1, state=v.state, metadata=v.metadata)
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
        return find_vault_by_id(request.match_info['id'])

    @asyncio.coroutine
    def delete_obj(self, obj):
        self.app.remove_vault(obj)

    @asyncio.coroutine
    def post_obj(self, request):
        content = yield from request.content.read()
        request_dict = json.loads(content.decode())
        vault = self.app.add_vault_by_path(request_dict['folder'])
        task = asyncio.get_event_loop().create_task(self.app.open_or_init(vault))
        #def cb(_task):
        #    if task.exception():
        #        logger.warn("%s", task.exception())
        #task.add_done_callback(cb)
        return vault

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
                '/{version}/vault/{{vault_id}}/{name}/{{email}}'.format(**opts),
                self.dispatch_get)
        router.add_route('DELETE',
                '/{version}/vault/{{vault_id}}/{name}/{{email}}'.format(**opts),
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

    def get_id(self, obj):
        return obj['email']

    def dehydrate(self, obj):
        return dict(obj, resource_uri=self.get_resource_uri(obj))

    @asyncio.coroutine
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
    def post_obj(self, request):
        vault = self.get_vault(request)
        content = yield from request.content.read()
        data = json.loads(content.decode())
        email = data['email']
        yield from vault.backend.open()
        logger.info('Adding user "%s" to %s', email, vault)
        yield from vault.backend.add_vault_user(email)
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

    @asyncio.coroutine
    def delete_obj(self, obj):
        self.app.remove_vault(obj)

    @asyncio.coroutine
    def put_obj(self, request):
        vault_path = (yield from request.content.read()).decode()
        vault = self.app.add_vault_by_path(vault_path)
        task = asyncio.get_event_loop().create_task(self.app.open_or_init(vault))
        #def cb(_task):
        #    if task.exception():
        #        logger.warn("%s", task.exception())
        #task.add_done_callback(cb)
        return vault
