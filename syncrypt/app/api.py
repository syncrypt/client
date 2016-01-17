from aiohttp import web
import json
import asyncio
import logging

logger = logging.getLogger(__name__)

class SyncryptAPI(object):
    def __init__(self, app):
        self.app = app
        self.server = None

    @asyncio.coroutine
    def list_vaults(self, request):
        vaults = [{'folder': v.folder, 'name': v.folder} for v in self.app.vaults]
        return web.Response(body=json.dumps(vaults).encode('utf-8'), content_type='application_json')

    @asyncio.coroutine
    def stats(self, request):
        return web.Response(body=json.dumps(self.app.stats).encode('utf-8'), content_type='application_json')

    @asyncio.coroutine
    def start(self):
        loop = asyncio.get_event_loop()
        app = web.Application(loop=loop)
        app.router.add_route('GET', '/vaults', self.list_vaults)
        app.router.add_route('GET', '/stats', self.stats)
        self.handler = app.make_handler()
        self.server = yield from loop.create_server(self.handler, '127.0.0.1', 28080)
        logger.info("REST API Server started at http://127.0.0.1:28080")

    @asyncio.coroutine
    def stop(self):
        if self.server:
            logger.info("Shutting down REST API Server")
            self.server.close()
            yield from self.server.wait_closed()
            yield from self.handler.finish_connections(1.0)
