import asyncio

class AuthenticationProvider():

    @asyncio.coroutine
    def get_auth(self, backend):
        raise NotImplementedError


class DummyAuthenticationProvider(AuthenticationProvider):

    def __init__(self, username, password):
        self.username = username
        self.password = password

    @asyncio.coroutine
    def get_auth(self, backend):
        return self.username, self.password
