# tastypie-like asyncio-aware resources
import hashlib
import json
import logging
import os.path

import asyncio
from aiohttp import web


class JSONResponse(web.Response):
    def __init__(self, obj):
        super(JSONResponse, self).__init__(body=json.dumps(obj).encode('utf-8'),
                content_type='application_json')


class Resource(object):
    version = 'v1'

    def add_routes(self, router):
        opts = {'version': self.version, 'name': self.resource_name}
        router.add_route('PUT', '/{version}/{name}/'.format(**opts), self.dispatch_put)
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
        return "/{version}/{name}/{id}".format(version=self.version,
                name=self.resource_name, id=self.get_id(obj))

class VaultResource(Resource):
    resource_name = 'vault'

    def __init__(self, app):
        self.app = app
        super(VaultResource, self).__init__()

    def get_id(self, v):
        hash = hashlib.new('md5')
        hash.update(os.path.abspath(v.folder.encode()))
        return hash.hexdigest()

    def dehydrate(self, v):
        dct = super(VaultResource, self).dehydrate(v)
        dct.update(folder=v.folder, status='ready', user_count=1, state=v.state)
        return dct

    @asyncio.coroutine
    def get_obj_list(self, request):
        return self.app.vaults

    @asyncio.coroutine
    def get_obj(self, request):
        for v in self.app.vaults:
            if self.get_id(v) == request.match_info['id']:
                return v

    @asyncio.coroutine
    def delete_obj(self, obj):
        self.app.remove_vault(obj)

    @asyncio.coroutine
    def put_obj(self, request):
        vault_path = (yield from request.content.read()).decode()
        vault = self.app.add_vault_by_path(vault_path)
        task = asyncio.get_event_loop().create_task(self.app.open_or_init(vault))
        def cb(_task):
            if task.exception():
                logger.warn("%s", task.exception())
        task.add_done_callback(cb)
        return vault
