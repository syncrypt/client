import snappy

from .base import Pipe

class SnappyCompress(Pipe):
    def __init__(self):
        self.compressor = snappy.StreamCompressor()

    async def read(self, count=-1):
        contents = await self.input.read(count)
        return self.compressor.add_chunk(contents, compress=True)

class SnappyDecompress(Pipe):
    def __init__(self):
        self.decompressor = snappy.StreamDecompressor()

    async def read(self, count=-1):
        data = b''
        while True:
            contents = await self.input.read(count)
            if len(contents) == 0:
                self._eof = True
                return contents
            data += self.decompressor.decompress(contents)
            if len(data) > 0:
                return data
