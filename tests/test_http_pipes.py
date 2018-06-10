import asyncio
import json
import math
import os
import os.path
import shutil
import unittest

import aiofiles
import asynctest
import pytest

from syncrypt.pipes import (Buffered, BufferedFree, ChunkedURLWriter, Count, Hash, Once, Repeat,
                            StdoutWriter, URLReader, URLWriter)

from .base import VaultTestCase


class URLReaderTests(asynctest.TestCase):

    @pytest.mark.external_resources
    async def test_url_10mb(self):
        url = 'http://ipv4.download.thinkbroadband.com:81/10MB.zip'
        stream = URLReader(url) >> Count()
        hashed = stream >> Hash('sha1')
        await hashed.consume()

        self.assertEqual(stream.count, 10485760)
        self.assertEqual(hashed.hash, 'f3b8eebe058415b752bec735652a30104fe666ba')

    @pytest.mark.external_resources
    async def test_url_1mb(self):
        url = 'http://speedtest.ftp.otenet.gr/files/test1Mb.db'
        stream = URLReader(url) >> Hash('sha256')
        counted = stream >> Count()
        await counted.consume()

        self.assertEqual(counted.count, 1048576)
        self.assertEqual(stream.hash,
            '30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58')

    @pytest.mark.external_resources
    async def test_url_put(self):
        times = 3 # repeat test data this many times
        url = 'https://httpbin.org/put'
        data = b'Ifooqu1oong3phie2iHeefohb0eej1oo'\
               b'x2iJei7aijawae9jah7Xa7ai7aaFa7za'\
               b'e4ieVu9kooY3Ohngavae0hie6ahkee1a'\
               b'cej6koofeiwaeWahmoo9ogh0aeshaeme'
        data_pipe = Once(data) >> Repeat(times) >> Buffered(50)
        writer = data_pipe >> URLWriter(url, len(data) * times)
        returned_content = await writer.readall()

        self.assertEqual(writer.bytes_written, len(data) * times)

        # The httpbin API will return a JSON object with the data.
        obj = json.loads(returned_content.decode('utf-8'))

        self.assertEqual(obj['data'].encode('utf-8'), data * times)

    @pytest.mark.external_resources
    async def test_url_put_chunked(self):
        data = b'Ifooqu1oong3phie2iHeefohb0eej1oo'\
               b'x2iJei7aijawae9jah7Xa7ai7aaFa7za'\
               b'e4ieVu9kooY3Ohngavae0hie6ahkee1a'\
               b'cej6koofeiwaeWahmoo9ogh0aeshaeme'
        times = 10 # repeat test data this many times
        chunksize = 112
        chunks = math.ceil((len(data) * times * 1.0) / chunksize)
        urls = ['https://httpbin.org/put?chunk={0}'.format(c) for c in range(chunks)]
        data_pipe = Once(data) >> Repeat(times)

        writer = data_pipe >> ChunkedURLWriter(urls, chunksize=chunksize,
                                    total_size=len(data)*10)

        complete_data = ''
        while True:
            returned_content = (await writer.read())
            if len(returned_content) == 0:
                break
            # The httpbin API will return a JSON object with the data.
            obj = json.loads(returned_content.decode('utf-8'))
            complete_data += obj['data']
        await writer.close()

        self.assertEqual(writer.bytes_written, len(data) * times)

        self.assertEqual(complete_data.encode('utf-8'), data * times)
