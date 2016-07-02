A guide through the Syncrypt client source code
===============================================

This is a quick writeup of the Syncrypt client internals, so that you
can quickly get a grip on how it works. It is not complicated. We will start
from the inner core machinery and work ourselves outwards.

Before digging through the source code, make sure that you've read the
general information about the [Syncrypt encryption](encryption.md).


Pipes
-----

At the heart of the Syncrypt client is a tiny abstraction dubbed
*Pipes*. Pipes can be seen as operators or functions on streams and operate
asynchronously thanks to the asyncio framework from Python 3.

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
A Bundle basically describes a file with additional information, like the file
size and the content hash.

A Bundle has the functions ``read_encrypted_stream`` and
``write_encrypted_stream``, which will return a Pipe and consume a Pipe,
respectively. Equipped with our Pipes toolkit, we can now easily reason
about how an encrypted stream is constructed:

    def read_encrypted_stream(self):
        return FileReader(self.path) \
                >> SnappyCompress() \
                >> Buffered(self.vault.config.enc_buf_size) \
                >> PadAES() \
                >> EncryptAES(self.key)


Vaults
------

The Vault class represents a single folder and has functionality to manage its
config, identity and bundles.


Storage backend
---------------

Currently there only exists a single storage backend implementation.
This can be found in the file ``backends/binary.py`` and is the implementation
of the binary Syncrypt client/server communication protocol. We won't go into
details here as they can be discovered by reading the source code, but the
basic principle of this communication protocol is that the client sends a
serialized command and the server response with a serialized response as well.

The serialization format that is currently used is [BERT (Binary ERlang Term)](http://bert-rpc.org/).

Note that you can turn on the ``BINARY_DEBUG`` flag in order to see the whole
serialized and unserialized communication if you are interested.

SyncryptApp
-----------

Finally, the SyncryptApp object is the outer shell of the Syncrypt client.
It basically calls the backend and ties together the different models.

