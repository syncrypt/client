import json
import logging

import asyncio
from aiohttp import web
from syncrypt.app.auth import AuthenticationProvider
from syncrypt.backends.base import StorageBackendInvalidAuth

from .resources import (BundleResource, JSONResponse, VaultResource,
                        VaultUserResource, UserResource, FlyingVaultResource)


class DummyAuthenticationProvider(AuthenticationProvider):

    def __init__(self, username, password):
        self._username = username
        self._password = password

    @asyncio.coroutine
    def get_auth(self, backend):
        logger.info('Logging in with %s', self._username)
        return self._username, self._password



logger = logging.getLogger(__name__)

class SyncryptAPI():
    def __init__(self, app):
        self.app = app
        self.server = None

    @asyncio.coroutine
    def get_stats(self, request):
        vault_resource = VaultResource(self.app)
        vault_states = {vault_resource.get_resource_uri(v): v.state for v in self.app.vaults}
        return JSONResponse({
            'stats': self.app.stats,
            'states': vault_states
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
    def post_auth_login(self, request):
        content = yield from request.content.read()
        credentials = json.loads(content.decode())
        logger.info('Login requested with email: %s', credentials['email'])
        try:
            backend = yield from self.app.open_backend(always_ask_for_creds=True,
                    auth_provider=DummyAuthenticationProvider(
                        credentials['email'], credentials['password']),
                    num_tries=1)
            logger.info('Successfully logged in and stored auth token.')
            yield from backend.close()
            yield from self.app.upload_identity()
            return JSONResponse({
                'status': 'ok'
            })
        except StorageBackendInvalidAuth:
            return JSONResponse({
                'status': 'error',
                'text': 'Invalid authentification'
            }, status=500)

    @asyncio.coroutine
    def get_auth_check(self, request):
        logger.info('Login check')
        cfg = self.app.config
        backend = cfg.backend_cls(**cfg.backend_kwargs)
        connected = False
        try:
            yield from backend.open()
            yield from backend.close()
            connected = True
        except StorageBackendInvalidAuth:
            pass
        return JSONResponse({
                'status': 'ok',
                'connected': connected
            })

    @asyncio.coroutine
    def get_auth_logout(self, request):
        '''
        Logging out the user simply works by removing the global auth
        token.
        '''
        cfg = self.app.config
        with cfg.update_context():
            cfg.update('remote', {'auth': ''})
        return JSONResponse({'status': 'ok'})

    @asyncio.coroutine
    def get_user_info(self, request):
        '''
        Logging out the user simply works by removing the global auth
        token.
        '''
        backend = yield from self.app.open_backend()
        user_info = yield from backend.user_info()
        yield from backend.close()
        return JSONResponse(user_info)

    @asyncio.coroutine
    def start(self):
        loop = asyncio.get_event_loop()
        self.web_app = web.Application(loop=loop)

        VaultResource(self.app).add_routes(self.web_app.router)
        BundleResource(self.app).add_routes(self.web_app.router)
        UserResource(self.app).add_routes(self.web_app.router)
        VaultUserResource(self.app).add_routes(self.web_app.router)
        FlyingVaultResource(self.app).add_routes(self.web_app.router)

        self.web_app.router.add_route('POST', '/v1/auth/login/', self.post_auth_login)
        self.web_app.router.add_route('GET', '/v1/auth/check/', self.get_auth_check)
        self.web_app.router.add_route('GET', '/v1/auth/logout/', self.get_auth_logout)
        self.web_app.router.add_route('GET', '/v1/auth/user/', self.get_user_info)

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
