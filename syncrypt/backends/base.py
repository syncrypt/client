class StorageBackend(object):
    def __init__(self, vault):
        self.vault = vault

    def version(self):
        raise NotImplementedError()

    def open(self):
        raise NotImplementedError()

    def upload(self, bundle):
        raise NotImplementedError()

    def stat(self, bundle):
        raise NotImplementedError()
