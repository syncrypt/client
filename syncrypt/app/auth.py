import asyncio

class AuthenticationProvider():

    @asyncio.coroutine
    def get_auth(self, backend):
        raise NotImplementedError

class CredentialsAuthenticationProvider(AuthenticationProvider):

    def __init__(self, username, password):
        self._username = username
        self._password = password

    @asyncio.coroutine
    def get_auth(self, backend):
        return self._username, self._password

