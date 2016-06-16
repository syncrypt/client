from syncrypt.app.auth import AuthenticationProvider
import asyncio
from getpass import getpass

class CLIAuthenticationProvider(AuthenticationProvider):

    @asyncio.coroutine
    def get_auth(self, backend):
        username = None
        while not username:
            username = input('Email for {}: '.format(backend.host))
        password = getpass()
        return username, password
