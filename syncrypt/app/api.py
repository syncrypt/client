from aiohttp import web
import json
import asyncio
import logging

from .resources import VaultResource, JSONResponse

logger = logging.getLogger(__name__)

class SyncryptAPI(object):
    def __init__(self, app):
        self.app = app
        self.server = None

    @asyncio.coroutine
    def get_stats(self, request):
        return JSONResponse({
            'stats': self.app.stats,
            'states': self.app.get_vault_states()
        })

    @asyncio.coroutine
    def get_push(self, request):
        task = asyncio.get_event_loop().create_task(self.app.push())
        def cb(_task):
            if task.exception():
                logger.warn("%s", task.exception())
        task.add_done_callback(cb)
        return JSONResponse({})

    @asyncio.coroutine
    def get_pull(self, request):
        task = asyncio.get_event_loop().create_task(self.app.pull())
        def cb(_task):
            if task.exception():
                logger.warn("%s", task.exception())
        task.add_done_callback(cb)
        return JSONResponse({})

    @asyncio.coroutine
    def get_config(self, request):
        return JSONResponse(self.app.config.as_dict())

    @asyncio.coroutine
    def start(self):
        loop = asyncio.get_event_loop()
        self.web_app = web.Application(loop=loop)

        VaultResource(self.app).add_routes(self.web_app.router)

        self.web_app.router.add_route('GET', '/v1/stats', self.get_stats)
        self.web_app.router.add_route('GET', '/v1/pull', self.get_pull)
        self.web_app.router.add_route('GET', '/v1/push', self.get_push)
        self.web_app.router.add_route('GET', '/v1/config', self.get_config)

        self.handler = self.web_app.make_handler()
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
