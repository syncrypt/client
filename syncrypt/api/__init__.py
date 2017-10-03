import asyncio
import json
import logging

import smokesignal
from aiohttp import web

import syncrypt
from syncrypt.app.auth import CredentialsAuthenticationProvider
from syncrypt.backends.base import StorageBackendInvalidAuth
from syncrypt.backends.binary import get_manager_instance

from ..utils.updates import is_update_available
from .auth import generate_api_auth_token, require_auth_token
from .client import APIClient
from .resources import (BundleResource, FlyingVaultResource, JSONResponse,
                        UserResource, VaultResource, VaultUserResource)

logger = logging.getLogger(__name__)


class SyncryptAPI():
    def __init__(self, app):
        self.app = app
        self.web_app = None
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
            'user_key_state': self.app.identity.state,
            'states': vault_states,
            'slots': get_manager_instance().get_stats()
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

        cfg = self.app.config.as_dict()

        # prepare certain config values for json
        # These guards/conversions should be done transparently in
        # Config class
        cfg['gui']['is_first_launch'] = cfg['gui']['is_first_launch'] in ('1',)

        return JSONResponse(cfg)

    @asyncio.coroutine
    @require_auth_token
    def patch_config(self, request):

        content = yield from request.content.read()
        params = json.loads(content.decode())

        with self.app.config.update_context():
            for obj_key, obj in params.items():
                for key, value in obj.items():
                    setting = '{0}.{1}'.format(obj_key, key)
                    logger.debug('Setting %s.%s to %s', obj_key, key, value)

                    # These guards/conversions should be done transparently in
                    # Config class
                    if setting == 'gui.is_first_launch':
                        value = '1' if value else '0'

                    self.app.config.set(setting, value)

        return (yield from self.get_config(request))

        cfg = self.app.config.as_dict()

        # prepare certain config values for json
        cfg['gui']['is_first_launch'] = cfg['gui']['is_first_launch'] in ('1', 'yes')

        return JSONResponse(cfg)

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
            }, status=401)

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
        Log out the user and remove global_auth information
        '''
        cfg = self.app.config
        backend = yield from self.app.open_backend()
        backend.global_auth = None
        backend.set_auth(None, None)
        yield from get_manager_instance().close()
        with cfg.update_context():
            cfg.update('remote', {'auth': ''})
        return JSONResponse({'status': 'ok'})

    @asyncio.coroutine
    @require_auth_token
    def get_shutdown(self, request):
        '''
        Shut the daemon down
        '''
        @asyncio.coroutine
        def do_shutdown():
            yield from asyncio.sleep(0.4)
            yield from self.app.shutdown()
        task = asyncio.get_event_loop().create_task(do_shutdown())
        return JSONResponse({'status': 'ok'})

    @asyncio.coroutine
    @require_auth_token
    def get_restart(self, request):
        '''
        Restart the daemon
        '''
        @asyncio.coroutine
        def do_restart():
            yield from asyncio.sleep(0.4)
            yield from self.app.restart()
        task = asyncio.get_event_loop().create_task(do_restart())
        return JSONResponse({'status': 'ok'})

    @asyncio.coroutine
    @require_auth_token
    def get_version(self, request):
        if int(request.GET.get('check_for_update', 1)):
            can_update, available = yield from is_update_available()
            return JSONResponse({
                'update_available': can_update,
                'available_version': available,
                'installed_version': syncrypt.__version__
            })
        else:
            return JSONResponse({
                'installed_version': syncrypt.__version__
            })

    @asyncio.coroutine
    @require_auth_token
    def get_user_info(self, request):
        '''
        Return information about the currently logged in user (First name, Last name, ...)
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

    def initialize(self):
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
        self.web_app.router.add_route('GET', '/v1/shutdown/', self.get_shutdown)
        self.web_app.router.add_route('GET', '/v1/restart/', self.get_restart)

        #self.web_app.router.add_route('GET', '/v1/log/', self.stream_log)
        self.web_app.router.add_route('GET', '/v1/stats/', self.get_stats)
        self.web_app.router.add_route('GET', '/v1/config/', self.get_config)
        self.web_app.router.add_route('PATCH', '/v1/config/', self.patch_config)
        self.web_app.router.add_route('GET', '/v1/pull', self.get_pull)
        self.web_app.router.add_route('GET', '/v1/push', self.get_push)

        # The following routes are deprecated and will be removed shortly
        self.web_app.router.add_route('GET', '/v1/stats', self.get_stats)
        self.web_app.router.add_route('GET', '/v1/config', self.get_config)

        smokesignal.emit('post_api_initialize', app=self.app, api=self)

    @asyncio.coroutine
    def start(self):
        if self.web_app is None:
            raise RuntimeError('Start requested without initialization')

        loop = asyncio.get_event_loop()

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
