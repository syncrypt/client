import asyncio

class StorageBackendException(Exception):
    pass

class StorageBackendInvalidAuth(StorageBackendException):
    pass

class StorageBackend(object):
    def __init__(self, vault):
        self.vault = vault

    def version(self):
        raise NotImplementedError()

    @asyncio.coroutine
    def open(self):
        raise NotImplementedError()

    @asyncio.coroutine
    def upload(self, bundle):
        raise NotImplementedError()

    @asyncio.coroutine
    def download(self, bundle):
        raise NotImplementedError()

    @asyncio.coroutine
    def stat(self, bundle):
        raise NotImplementedError()

    @asyncio.coroutine
    def wipe(self):
        raise NotImplementedError()
