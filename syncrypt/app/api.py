from aiohttp import web
import json
import asyncio
import logging

logger = logging.getLogger(__name__)

class JSONResponse(web.Response):
    def __init__(self, obj):
        super(JSONResponse, self).__init__(body=json.dumps(obj).encode('utf-8'),
                content_type='application_json')

class SyncryptAPI(object):
    def __init__(self, app):
        self.app = app
        self.server = None

    @asyncio.coroutine
    def list_vaults(self, request):
        return JSONResponse([{'folder': v.folder, 'name': v.folder} for v in self.app.vaults])

    @asyncio.coroutine
    def get_stats(self, request):
        return JSONResponse(self.app.stats)

    @asyncio.coroutine
    def get_config(self, request):
        return JSONResponse(self.app.config.as_dict())

    @asyncio.coroutine
    def start(self):
        loop = asyncio.get_event_loop()
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/vaults', self.list_vaults)
        app.router.add_route('GET', '/stats', self.get_stats)
        app.router.add_route('GET', '/config', self.get_config)
        self.handler = app.make_handler()
        self.server = yield from loop.create_server(self.handler,
                self.app.config.api['host'], self.app.config.api['port'])
        logger.info("REST API Server started at http://{0.api[host]}:{0.api[port]}"\
                .format(self.app.config))


    @asyncio.coroutine
    def stop(self):
        if self.server:
            logger.info("Shutting down REST API Server")
            self.server.close()
            yield from self.server.wait_closed()
            yield from self.handler.finish_connections(1.0)
