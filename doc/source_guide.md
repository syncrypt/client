A guide through the Syncrypt Desktop source code
================================================

This is a quick writeup of the Syncrypt Desktop internals, so that you
can quickly get a grip how it works. It is not complicated. We will start
from the inner core machinery and work ourselves outwards.

Pipes
-----

At the heart of the Syncrypt Desktop client is a tiny abstraction dubbed
*Pipes*. Pipes can be seen operators or functions on streams and operate
asyncronusly thanks to the asyncio framework from Python 3.

There are Pipes for various functions, for example IO (reading and writing
files), cryptographic functions (symmetric and asymmetric encryption and
decryption), compression, and other things like buffering.

Pipes can be chained together using the ``>>`` operator. In the following
example, the contents of a file will be compressed and a hash will be
calculated from the compressed content.

    hash_pipe = FileReader('my_file.txt') >> SnappyCompress() >> Hash('sha256')
    hash_pipe.consume()

You can explore all available Pipes in the directory ``syncrypt/pipes/``.

Bundles
-------

To see these Pipes in action, you can take a look at the ``Bundle`` class.
A Bundle basically describes a file with meta information.

...

Vaults
------

...
