class StorageBackend(object):

    def __init__(self, vault):
        self.vault = vault
        self.connected = False
        self.invalid_auth = False

    def version(self):
        raise NotImplementedError()

    async def open(self):
        raise NotImplementedError()

    async def upload(self, bundle):
        raise NotImplementedError()

    async def download(self, bundle):
        raise NotImplementedError()

    async def stat(self, bundle):
        raise NotImplementedError()
