import asyncio
import json
import logging
import math
import os.path

import smokesignal
import trio
import trio_asyncio
from aiohttp import web
from aiohttp.abc import AbstractAccessLogger

import syncrypt
from syncrypt.auth import CredentialsAuthenticationProvider
from syncrypt.backends.binary import get_manager_instance

from ..exceptions import InvalidAuthentification, SyncryptBaseException
from ..utils.updates import is_update_available
from .auth import generate_api_auth_token, require_auth_token, require_identity
from .client import APIClient
from .resources import (BundleResource, FlyingVaultResource, UserResource, VaultResource,
                        VaultUserResource)
from .responses import JSONResponse

logger = logging.getLogger(__name__)


class AccessLogger(AbstractAccessLogger):

    def log(self, request, response, time):
        self.logger.debug(
            ('API "{request.method} {request.path_qs} '
            'HTTP/{request.version.major}.{request.version.minor}" '
            '{response.status} '
            '{response.body_length} '
            '{time:.3f}s').format(request=request, response=response, time=time)
        )


class SyncryptAPI():
    def __init__(self, app):
        self.app = app
        self.web_app = None  # Optional[web.Application]
        self.server = None
        self.shutdown = trio.Event()
        self.dead = trio.Event()

        if not self.app.config.get('api.auth_token'):
            logger.info('Generating API auth token...')
            with self.app.config.update_context():
                self.app.config.set('api.auth_token', generate_api_auth_token())

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_stats(self, request):
        VaultResource(self.app)
        return JSONResponse({
            'stats': self.app.stats,
            'identity_state': self.app.identity.state,
            'user_key_state': self.app.identity.state, # deprecated
            'slots': get_manager_instance().get_stats()
        })

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_push(self, request):
        task = asyncio.get_event_loop().create_task(self.app.push())
        def cb(_task):
            if task.exception():
                logger.warning("%s", task.exception())
        task.add_done_callback(cb)
        return JSONResponse({})

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_pull(self, request):
        task = asyncio.get_event_loop().create_task(self.app.pull())
        def cb(_task):
            if task.exception():
                logger.warning("%s", task.exception())
        task.add_done_callback(cb)
        return JSONResponse({})

    def app_config_response(self):
        cfg = self.app.config.as_dict()

        # prepare certain config values for json
        # These guards/conversions should be done transparently in
        # Config class
        cfg['gui']['is_first_launch'] = cfg['gui']['is_first_launch'] in ('1', 'yes')

        return JSONResponse(cfg)

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_config(self, request):
        return self.app_config_response()

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def patch_config(self, request):

        content = await request.content.read()
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

        return self.app_config_response()

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def post_auth_login(self, request):
        content = await request.content.read()
        credentials = json.loads(content.decode())
        logger.info('Login requested with email: %s', credentials['email'])
        backend = await self.app.open_backend(always_ask_for_creds=True,
                auth_provider=CredentialsAuthenticationProvider(
                    credentials['email'], credentials['password']),
                num_tries=1)
        logger.info('Successfully logged in and stored auth token.')
        await self.app.upload_identity()
        return JSONResponse({
            'status': 'ok'
        })

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def post_auth_signup(self, request):
        content = await request.content.read()
        credentials = json.loads(content.decode())
        logger.info('Signup requested with email: %s', credentials['email'])
        await self.app.signup(credentials['email'], credentials['password'],
                              credentials['first_name'], credentials['last_name'])
        return JSONResponse({
            'status': 'ok'
        })

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_auth_check(self, request):
        logger.info('Login check')
        cfg = self.app.config
        backend = cfg.backend_cls(**cfg.backend_kwargs)
        connected = False
        try:
            await backend.open()
            connected = True
        except InvalidAuthentification:
            pass
        return JSONResponse({
                'status': 'ok',
                'connected': connected
            })

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_auth_logout(self, request):
        '''
        Log out the user and remove global_auth information
        '''
        cfg = self.app.config
        backend = await self.app.open_backend()
        backend.global_auth = None
        backend.set_auth(None, None)
        await get_manager_instance().close()
        with cfg.update_context():
            cfg.update('remote', {'auth': ''})
        return JSONResponse({'status': 'ok'})

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_shutdown(self, request):
        '''
        Shut the daemon down
        '''
        async def do_shutdown():
            await asyncio.sleep(0.4)
            await self.app.shutdown()
        asyncio.get_event_loop().create_task(do_shutdown())
        return JSONResponse({'status': 'ok'})

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_restart(self, request):
        '''
        Restart the daemon
        '''
        async def do_restart():
            await asyncio.sleep(0.4)
            await self.app.restart()
        asyncio.get_event_loop().create_task(do_restart())
        return JSONResponse({'status': 'ok'})

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_version(self, request):
        if int(request.query.get('check_for_update', 0)):
            can_update, available = await is_update_available()
            return JSONResponse({
                'update_available': can_update,
                'available_version': available,
                'installed_version': syncrypt.__version__
            })
        else:
            return JSONResponse({
                'installed_version': syncrypt.__version__
            })

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_user_info(self, request):
        '''
        Return information about the currently logged in user (First name, Last name, ...)
        '''
        backend = await self.app.open_backend()
        user_info = await backend.user_info()
        return JSONResponse(user_info)

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def post_user_feedback(self, request):
        '''
        Send user feedback
        '''
        content = await request.content.read()
        params = json.loads(content.decode())
        feedback_text = params['feedback_text']
        logger.info('Sending user feedback: %d bytes', len(feedback_text))
        backend = await self.app.open_backend()
        await backend.user_feedback(feedback_text.encode('utf-8'))
        return JSONResponse({'status': 'ok'})

    @require_auth_token
    @trio_asyncio.trio_as_aio
    async def get_identity_generate(self, request):
        await self.app.identity.generate_keys()
        return JSONResponse({'status': 'ok'})

    @require_auth_token
    @require_identity
    @trio_asyncio.trio_as_aio
    async def post_identity_export(self, request):
        try:
            content = await request.content.read()
            request_dict = json.loads(content.decode())
        except:
            return web.Response(status=400, text='Need JSON request body.')

        if not 'path' in request_dict:
            return web.Response(status=400, text='Missing parameter "path".')

        path = request_dict['path']
        if os.path.isdir(path):
            path = os.path.join(path, 'SyncryptKey.zip')

        await self.app.export_user_key(path)

        return JSONResponse({'status': 'ok', 'filename': path})

    @require_auth_token
    async def post_identity_import(self, request):
        try:
            content = await request.content.read()
            request_dict = json.loads(content.decode())
        except:
            return web.Response(status=400, text='Need JSON request body.')

        if not 'path' in request_dict:
            return web.Response(status=400, text='Missing parameter "path".')

        path = request_dict['path']

        await self.app.import_user_key(path)

        return JSONResponse({'status': 'ok'})

    def exception_response(self, exc):
        return web.Response(
            status = exc.status if hasattr(exc, 'status') else 500,
            body = json.dumps({
                'status': 'error',
                'reason': str(exc),
                'code': str(exc.__class__.__name__)
            }).encode('utf-8'),
            content_type='application/json'
        )

    @web.middleware
    async def error_middleware(self, request, handler):
        try:
            response = await handler(request)
            return response
        except web.HTTPException as ex:
            if ex.status == 404:
                return self.exception_response(ex)
            raise
        except SyncryptBaseException as ex:
            return self.exception_response(ex)
        except Exception as ex:
            logger.exception("The following exception occurred")
            return self.exception_response(ex)

    def initialize(self):
        self.web_app = web.Application(middlewares=[self.error_middleware])

        VaultResource(self.app).add_routes(self.web_app.router)
        BundleResource(self.app).add_routes(self.web_app.router)
        UserResource(self.app).add_routes(self.web_app.router)
        VaultUserResource(self.app).add_routes(self.web_app.router)
        FlyingVaultResource(self.app).add_routes(self.web_app.router)

        self.web_app.router.add_route('POST', '/v1/auth/signup/', self.post_auth_signup)
        self.web_app.router.add_route('POST', '/v1/auth/login/', self.post_auth_login)
        self.web_app.router.add_route('GET', '/v1/auth/check/', self.get_auth_check)
        self.web_app.router.add_route('GET', '/v1/auth/logout/', self.get_auth_logout)
        self.web_app.router.add_route('GET', '/v1/auth/user/', self.get_user_info)
        self.web_app.router.add_route('POST', '/v1/feedback/', self.post_user_feedback)

        self.web_app.router.add_route('GET', '/v1/identity/generate/', self.get_identity_generate)
        self.web_app.router.add_route('POST', '/v1/identity/export/', self.post_identity_export)
        self.web_app.router.add_route('POST', '/v1/identity/import/', self.post_identity_import)
        # Following is deprecated; only for backward compat
        self.web_app.router.add_route('POST', '/v1/user_key_export/', self.post_identity_export)

        self.web_app.router.add_route('GET', '/v1/version/', self.get_version)
        self.web_app.router.add_route('GET', '/v1/shutdown/', self.get_shutdown)
        self.web_app.router.add_route('GET', '/v1/restart/', self.get_restart)

        self.web_app.router.add_route('OPTIONS', '/v1/version/', self.dispatch_options)
        self.web_app.router.add_route('OPTIONS', '/v1/shutdown/', self.dispatch_options)
        self.web_app.router.add_route('OPTIONS', '/v1/restart/', self.dispatch_options)

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

    async def dispatch_options(self, request):
        return JSONResponse({})

    async def start(self, task_status=trio.TASK_STATUS_IGNORED):

        async with trio_asyncio.open_loop():

            self.initialize()
            assert self.web_app is not None

            runner = web.AppRunner(self.web_app)
            await trio_asyncio.aio_as_trio(runner.setup)
            site = web.TCPSite(runner,
                self.app.config.api['host'],
                self.app.config.api['port']
            )
            await trio_asyncio.aio_as_trio(site.start)
            logger.info("REST API Server started at http://{0.api[host]}:{0.api[port]}"\
                    .format(self.app.config))

            if task_status:
                task_status.started()

            try:
                await self.shutdown.wait()

                # Default safe API shutdown
                await trio_asyncio.aio_as_trio(site.stop)
            except:
                # Emergency API shutdown to free the API port
                await site.stop()
                raise

        self.dead.set()

    async def stop(self):
        logger.info("Shutting down REST API Server")
        self.shutdown.set()
        await self.dead.wait()
