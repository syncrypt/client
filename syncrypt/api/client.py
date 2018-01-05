import json
import asyncio
import aiohttp
from .auth import AUTH_TOKEN_HEADER


class APIClient:
    def __init__(self, app_config):
        self.host = app_config.get('api.host')
        self.port = app_config.get('api.port')
        self.auth_token = app_config.get('api.auth_token')
        self._session = None

    def login(self, **kwargs):
        return self.post('/v1/auth/login/', data=json.dumps(kwargs))

    def logout(self, **kwargs):
        return self.get('/v1/auth/logout/')

    async def close(self):
        await self._session.close()

    @property
    def session(self):
        if not self._session:
            self._session = aiohttp.ClientSession()
        return self._session

    def __getattr__(self, http_method):
        async def api_call(request_uri, *args, raise_for_status=True, **kwargs):

            # Add auth token to headers
            kwargs['headers'] = dict(kwargs.get('headers', {}), **{AUTH_TOKEN_HEADER: self.auth_token})

            # Build URL
            url = 'http://{host}:{port}{uri}'.format(host=self.host, port=self.port, uri=request_uri)

            ctx = await getattr(self.session, http_method)(url, *args, **kwargs)
            if raise_for_status:
                ctx.raise_for_status()
            return ctx
        return api_call

