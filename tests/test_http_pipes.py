import asyncio
import json
import math
import os
import os.path
import shutil
import unittest

import pytest

from syncrypt.pipes import (Buffered, BufferedFree, ChunkedURLWriter, Count, Hash, Once, Repeat,
                            StdoutWriter, URLReader, URLWriter)

from .base import asyncio_loop


@pytest.mark.external_resources
async def test_url_1mb(asyncio_loop):
    url = 'http://speedtest.ftp.otenet.gr/files/test1Mb.db'
    stream = URLReader(url) >> Hash('sha256')
    counted = stream >> Count()
    await counted.consume()

    assert counted.count == 1048576
    assert stream.hash == \
            '30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58'


@pytest.mark.external_resources
async def test_url_put(asyncio_loop):
    times = 3 # repeat test data this many times
    url = 'https://httpbin.org/put'
    data = b'Ifooqu1oong3phie2iHeefohb0eej1oo'\
           b'x2iJei7aijawae9jah7Xa7ai7aaFa7za'\
           b'e4ieVu9kooY3Ohngavae0hie6ahkee1a'\
           b'cej6koofeiwaeWahmoo9ogh0aeshaeme'
    data_pipe = Once(data) >> Repeat(times) >> Buffered(50)
    writer = data_pipe >> URLWriter(url, len(data) * times)
    returned_content = await writer.readall()

    assert writer.bytes_written == len(data) * times

    # The httpbin API will return a JSON object with the data.
    obj = json.loads(returned_content.decode('utf-8'))

    assert obj['data'].encode('utf-8') == data * times


@pytest.mark.external_resources
async def test_url_put_chunked(asyncio_loop):
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

    assert writer.bytes_written == len(data) * times

    assert complete_data.encode('utf-8') == data * times
