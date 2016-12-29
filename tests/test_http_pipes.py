import os
import os.path
import shutil
import unittest
import pytest
import json

import aiofiles
import asyncio
import asynctest
from syncrypt.pipes import URLReader, Hash, Count, Once, Repeat, URLWriter, StdoutWriter, Buffered
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

    @pytest.mark.external_resources
    @asyncio.coroutine
    def test_url_put(self):
        times = 3 # repeat test data this many times
        url = 'https://httpbin.org/put'
        data = b'Ifooqu1oong3phie2iHeefohb0eej1oo'\
               b'x2iJei7aijawae9jah7Xa7ai7aaFa7za'\
               b'e4ieVu9kooY3Ohngavae0hie6ahkee1a'\
               b'cej6koofeiwaeWahmoo9ogh0aeshaeme'
        data_pipe = Once(data) >> Repeat(times) >> Buffered(50)
        writer = data_pipe >> URLWriter(url)
        returned_content = yield from writer.readall()

        # The httpbin API will return a JSON object with the data.
        obj = json.loads(returned_content.decode('utf-8'))

        self.assertEqual(obj['data'].encode('utf-8'), data * times)


