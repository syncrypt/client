import os
import os.path
import shutil
import unittest
import pytest

import aiofiles
import asyncio
import asynctest
from syncrypt.pipes import URLReader, Hash
from .base import VaultTestCase

__all__ = ('URLReaderTests',)

class URLReaderTests(asynctest.TestCase):

    @pytest.mark.external_resources
    @asyncio.coroutine
    def test_url_10mb(self):
        url = 'http://ipv4.download.thinkbroadband.com:81/10MB.zip'
        stream = URLReader(url) >> Hash('sha1')
        yield from stream.consume()

        self.assertEqual(stream.count, 10311344)

