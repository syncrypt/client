import asyncio
import os
import os.path
import shutil
import unittest

from syncrypt.pipes import (Buffered, Count, FileReader, Limit, Once, Repeat, SnappyCompress,
                            SnappyDecompress, StreamReader)

__all__ = ("PipesTests",)


async def test_once():
    stream = Once(b"0123456789abcdef")
    contents = await stream.read()
    assert contents == b"0123456789abcdef"
    contents = await stream.read()
    assert contents == b""


async def test_plain():
    stream = Once(b"0123456789abcdef")
    repeated = stream >> Repeat(3)

    contents = b""
    while True:
        buf = await repeated.read()
        if len(buf) == 0:
            break
        contents += buf

    assert contents == b"0123456789abcdef0123456789abcdef0123456789abcdef"

async def test_buffered():
    stream = Once(b"ac")
    buffered = stream >> Repeat(24) >> Buffered(1024)

    contents = await buffered.read()
    assert contents == b"ac" * 24

async def test_buffered_2():
    stream = Once(b"ab")
    buffered = stream >> Repeat(24) >> Buffered(6)

    for i in range(8):
        contents = await buffered.read()
        assert contents == b"ab" * 3

    contents = await buffered.read()
    assert contents == b""

async def test_filereader():
    stream = FileReader("tests/testbinaryvault/README.md")
    contents = await stream.read()
    await stream.close()
    assert len(contents) == 640

async def test_count():
    counter = FileReader("tests/testbinaryvault/README.md") >> Count()
    await counter.consume()
    assert counter.count == 640

async def test_count_2():
    stream = Once(b"abcdefgh")
    counter = stream >> Repeat(241) >> Buffered(100) >> Count()
    await counter.consume()
    assert counter.count == 241 * 8

async def test_compression():
    compressed = FileReader("tests/testbinaryvault/README.md") >> SnappyCompress()
    contents = await compressed.read()
    await compressed.close()
    assert len(contents) < 640
    compressed = Once(contents) >> SnappyDecompress()
    contents = await compressed.read()
    await compressed.close()
    assert len(contents) == 640

async def test_compression_2():
    compressed = FileReader(
        "tests/testbinaryvault/random200k"
    ) >> SnappyCompress() >> Buffered(
        521
    ) >> SnappyDecompress()
    length = 0
    while True:
        contents = await compressed.read()
        if len(contents) == 0:
            break
        length += len(contents)
    await compressed.close()
    assert length == 200 * 1024

async def test_limit():
    for limit in (0, 1, 10, 141, 1241, 2000):
        limited = FileReader("tests/testbinaryvault/random12k") >> Limit(limit)
        length = 0
        while True:
            contents = await limited.read()
            if len(contents) == 0:
                break
            length += len(contents)
        await limited.close()
        assert length == limit
