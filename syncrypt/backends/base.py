from syncrypt.models import Vault

class StorageBackend(object):
    vault: Vault

    def __init__(self, vault):
        self.vault = vault
        self.connected = False
        self.invalid_auth = False

    def version(self):
        raise NotImplementedError()

    async def open(self):
        raise NotImplementedError()

    async def init(self):
        raise NotImplementedError()

    async def upload(self, bundle):
        raise NotImplementedError()

    async def download(self, bundle):
        raise NotImplementedError()

    async def stat(self, bundle):
        raise NotImplementedError()

    async def upload_identity(self, identity, description=""):
        pass

    async def user_info(self):
        raise NotImplementedError

    async def add_user_vault_key(self, vault, email, identity):
        pass

    async def changes(self, since_rev, to_rev, verbose=False):
        raise NotImplementedError
