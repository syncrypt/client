import os
import os.path
import shutil
import unittest
import pytest

import aiofiles
import asyncio
import asynctest
from syncrypt.pipes import URLReader, Hash, Count
from .base import VaultTestCase

__all__ = ('URLReaderTests',)

class URLReaderTests(asynctest.TestCase):

    @pytest.mark.external_resources
    @asyncio.coroutine
    def test_url_10mb(self):
        url = 'http://ipv4.download.thinkbroadband.com:81/10MB.zip'
        stream = URLReader(url) >> Count()
        hashed = stream >> Hash('sha1')
        yield from hashed.consume()

        self.assertEqual(stream.count, 10485760)
        self.assertEqual(hashed.hash, 'f3b8eebe058415b752bec735652a30104fe666ba')

    @pytest.mark.external_resources
    @asyncio.coroutine
    def test_url_1mb(self):
        url = 'http://www.speedtestx.de/testfiles/data_1mb.test'
        stream = URLReader(url) >> Hash('sha256')
        counted = stream >> Count()
        yield from counted.consume()

        self.assertEqual(counted.count, 1048576)
        self.assertEqual(stream.hash,
            '9f5a9086cf5ade0d0eeea626861e29f42dfd840691259e6742aa1446fc466057')
