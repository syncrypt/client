import asyncio
import os
import sys

from syncrypt.pipes import (Buffered, Count, EncryptAES, FileReader, Hash, Limit, Once, PadAES,
                            Repeat, SnappyCompress, SnappyDecompress, StreamReader)

if __name__ == '__main__':
    path = sys.argv[1]

    key = os.urandom(32)

    hashing_reader = FileReader(path) \
                >> Hash('sha256')

    counting_reader = hashing_reader \
                >> SnappyCompress() \
                >> Buffered(16 * 10 * 1024) \
                >> PadAES() \
                >> Count()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(counting_reader.consume())

    encrypted_counter = FileReader(path) \
                >> SnappyCompress() \
                >> Buffered(16 * 10 * 1024) \
                >> EncryptAES(key) \
                >> Count()

    loop.run_until_complete(encrypted_counter.consume())
    loop.close()
    print(counting_reader.count + 16) # iv
    print(encrypted_counter.count)
    diff = counting_reader.count + 16 - encrypted_counter.count
    print(diff)
    assert diff == 0
    print("OK")
