import os
import os.path
import shutil
import unittest

import aiofiles
import asyncio
import asynctest
from syncrypt.pipes import (Buffered, FileReader, Limit, Once, Repeat, Count,
                            SnappyCompress, SnappyDecompress, StreamReader)
from .base import VaultTestCase

__all__ = ('PipesTests', 'VaultPipeTests')

class PipesTests(asynctest.TestCase):

    @asynctest.ignore_loop
    def test_once(self):
        stream = Once(b'0123456789abcdef')
        contents = yield from stream.read()
        self.assertEqual(contents, b'0123456789abcdef')
        contents = yield from stream.read()
        self.assertEqual(contents, b'')

    @asynctest.ignore_loop
    def test_plain(self):
        stream = Once(b'0123456789abcdef')
        repeated = stream >> Repeat(3)

        contents = b''
        while True:
            buf = yield from repeated.read()
            if len(buf) == 0:
                break
            contents += buf

        self.assertEqual(contents,
                b'0123456789abcdef0123456789abcdef0123456789abcdef')

    @asynctest.ignore_loop
    def test_buffered(self):
        stream = Once(b'ac')
        buffered = stream >> Repeat(24) >> Buffered(1024)

        contents = yield from buffered.read()
        self.assertEqual(contents, b'ac' * 24)

    @asynctest.ignore_loop
    def test_buffered_2(self):
        stream = Once(b'ab')
        buffered = stream >> Repeat(24) >> Buffered(6)

        for i in range(8):
            contents = yield from buffered.read()
            self.assertEqual(contents, b'ab' * 3)

        contents = yield from buffered.read()
        self.assertEqual(contents, b'')

    @asynctest.ignore_loop
    def test_filereader(self):
        stream = FileReader('tests/testbinaryvault/README.md')
        contents = yield from stream.read()
        yield from stream.close()
        self.assertEqual(len(contents), 640)

    @asynctest.ignore_loop
    def test_count(self):
        counter = FileReader('tests/testbinaryvault/README.md') >> Count()
        yield from counter.consume()
        self.assertEqual(counter.count, 640)

    @asynctest.ignore_loop
    def test_count_2(self):
        stream = Once(b'abcdefgh')
        counter = stream >> Repeat(241) >> Buffered(100) >> Count()
        yield from counter.consume()
        self.assertEqual(counter.count, 241*8)

    @asynctest.ignore_loop
    def test_compression(self):
        compressed = FileReader('tests/testbinaryvault/README.md') >> SnappyCompress()
        contents = yield from compressed.read()
        yield from compressed.close()
        self.assertLess(len(contents), 640)
        compressed = Once(contents) >> SnappyDecompress()
        contents = yield from compressed.read()
        yield from compressed.close()
        self.assertEqual(len(contents), 640)

    @asynctest.ignore_loop
    def test_compression_2(self):
        compressed = FileReader('tests/testbinaryvault/random200k') \
                >> SnappyCompress() \
                >> Buffered(521) \
                >> SnappyDecompress()
        length = 0
        while True:
            contents = yield from compressed.read()
            if len(contents) == 0:
                break
            length += len(contents)
        yield from compressed.close()
        self.assertEqual(length, 200*1024)

    @asynctest.ignore_loop
    def test_limit(self):
        for limit in (0, 1, 10, 141, 1241, 2000):
            limited = FileReader('tests/testbinaryvault/random12k') \
                    >> Limit(limit)
            length = 0
            while True:
                contents = yield from limited.read()
                if len(contents) == 0:
                    break
                length += len(contents)
            yield from limited.close()
            self.assertEqual(length, limit)

class VaultPipeTests(VaultTestCase):

    @asynctest.ignore_loop
    def test_rsa_pipe_pkcs1_v15(self):
        bundle = self.vault.bundle_for('hello.txt')
        for i in (2, 10, 1242):
            input = b'a' * i + b'b' * int(i / 2)
            pipe = Once(input) \
                >> EncryptRSA(bundle.vault.identity.public_key)
            intermediate = yield from pipe.readall()
            pipe = Once(intermediate) \
                >> DecryptRSA(bundle.vault.identity.private_key)
            output = yield from pipe.readall()
            self.assertEqual(input, output)

    @asynctest.ignore_loop
    def test_rsa_pipe_pkcs1_oaep(self):
        bundle = self.vault.bundle_for('hello.txt')
        for i in (2, 10, 1242):
            input = b'a' * i + b'b' * int(i / 2)
            pipe = Once(input) \
                >> EncryptRSA_PKCS1_OAEP(bundle.vault.identity.public_key)
            intermediate = yield from pipe.readall()
            pipe = Once(intermediate) \
                >> DecryptRSA_PKCS1_OAEP(bundle.vault.identity.private_key)
            output = yield from pipe.readall()
            self.assertEqual(input, output)

if __name__ == '__main__':
    unittest.main()
