import unittest
import os.path
import shutil
import os

import asyncio
import asynctest

from syncrypt.pipes import Once, Repeat, Buffered

__all__ = ('PipesTests',)

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

if __name__ == '__main__':
    unittest.main()
