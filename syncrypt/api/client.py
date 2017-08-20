import json
import asyncio
import aiohttp
from .auth import AUTH_TOKEN_HEADER


class APIClient:
    def __init__(self, app_config):
        self.host = app_config.get('api.host')
        self.port = app_config.get('api.port')
        self.auth_token = app_config.get('api.auth_token')

    def login(self, **kwargs):
        return self.post('/v1/auth/login/', data=json.dumps(kwargs))

    def logout(self, **kwargs):
        return self.get('/v1/auth/logout/')

    def __getattr__(self, http_method):
        @asyncio.coroutine
        def api_call(request_uri, *args, **kwargs):

            # Add auth token to headers
            kwargs['headers'] = dict(kwargs.get('headers', {}), **{AUTH_TOKEN_HEADER: self.auth_token})

            # Build URL
            url = 'http://{host}:{port}{uri}'.format(host=self.host, port=self.port, uri=request_uri)

            return getattr(aiohttp, http_method)(url, *args, **kwargs)
        return api_call
