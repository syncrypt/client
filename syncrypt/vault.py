import os
import os.path
import sys
from pprint import pprint

from .bundle import Bundle

class Vault(object):
    def __init__(self, folder):
        self.folder = folder
        assert os.path.exists(folder)

    def walk(self):
        'a generator of all bundles in this vault'
        for (dir, dunno, files) in os.walk(self.folder):
            for f in files:
                if f.endswith('.encrypted') or f.endswith('.key'):
                    continue
                abspath = os.path.join(dir, f)
                yield Bundle(abspath, vault=self)
