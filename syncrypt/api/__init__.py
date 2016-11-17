import json
import logging

import asyncio
from aiohttp import web
import syncrypt
from syncrypt.app.auth import CredentialsAuthenticationProvider
from syncrypt.backends.base import StorageBackendInvalidAuth

from .resources import (BundleResource, JSONResponse, VaultResource,
                        VaultUserResource, UserResource, FlyingVaultResource)
from .auth import generate_api_auth_token, require_auth_token
from ..utils.updates import is_update_available

logger = logging.getLogger(__name__)

class SyncryptAPI():
    def __init__(self, app):
        self.app = app
        self.server = None

        if not self.app.config.get('api.auth_token'):
            logger.info('Generating API auth token...')
            with self.app.config.update_context():
                self.app.config.set('api.auth_token', generate_api_auth_token())

    @asyncio.coroutine
    @require_auth_token
    def get_stats(self, request):
        vault_resource = VaultResource(self.app)
        vault_states = {vault_resource.get_resource_uri(v): v.state for v in self.app.vaults}
        return JSONResponse({
            'stats': self.app.stats,
            'states': vault_states
        })

    @asyncio.coroutine
    @require_auth_token
    def get_push(self, request):
        task = asyncio.get_event_loop().create_task(self.app.push())
        def cb(_task):
            if task.exception():
                logger.warn("%s", task.exception())
        task.add_done_callback(cb)
        return JSONResponse({})

    @asyncio.coroutine
    @require_auth_token
    def get_pull(self, request):
        task = asyncio.get_event_loop().create_task(self.app.pull())
        def cb(_task):
            if task.exception():
                logger.warn("%s", task.exception())
        task.add_done_callback(cb)
        return JSONResponse({})

    @asyncio.coroutine
    @require_auth_token
    def get_config(self, request):
        return JSONResponse(self.app.config.as_dict())

    @asyncio.coroutine
    @require_auth_token
    def post_auth_login(self, request):
        content = yield from request.content.read()
        credentials = json.loads(content.decode())
        logger.info('Login requested with email: %s', credentials['email'])
        try:
            backend = yield from self.app.open_backend(always_ask_for_creds=True,
                    auth_provider=CredentialsAuthenticationProvider(
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
    @require_auth_token
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
    @require_auth_token
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
    @require_auth_token
    def get_version(self, request):
        can_update, available = yield from is_update_available()
        return JSONResponse({
            'update_available': can_update,
            'available_version': available,
            'installed_version': syncrypt.__version__
        })

    @asyncio.coroutine
    @require_auth_token
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
    @require_auth_token
    def post_user_feedback(self, request):
        '''
        Send user feedback
        '''
        content = yield from request.content.read()
        params = json.loads(content.decode())
        feedback_text = params['feedback_text']
        logger.info('Sending user feedback: %d bytes', len(feedback_text))
        backend = yield from self.app.open_backend()
        user_info = yield from backend.user_feedback(feedback_text.encode('utf-8'))
        yield from backend.close()
        return JSONResponse({'status': 'ok'})

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
        self.web_app.router.add_route('POST', '/v1/feedback/', self.post_user_feedback)
        self.web_app.router.add_route('GET', '/v1/version/', self.get_version)

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
