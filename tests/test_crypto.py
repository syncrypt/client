import os
import os.path
import shutil
import unittest

from syncrypt.managers import BundleManager
from syncrypt.pipes import (Buffered, Count, DecryptRSA, DecryptRSA_PKCS1_OAEP, EncryptRSA,
                            EncryptRSA_PKCS1_OAEP, FileReader, Limit, Once, Repeat, SnappyCompress,
                            SnappyDecompress, StreamReader)

from .base import *


async def test_rsa_pipe_pkcs1_v15(local_vault, local_app):
    vault = local_vault
    bundle = BundleManager(local_app).get_bundle_for_relpath('hello.txt', local_vault)
    for i in (2, 10, 1242):
        input = b'a' * i + b'b' * int(i / 2)
        pipe = Once(input) \
            >> EncryptRSA(bundle.vault.identity.public_key)
        intermediate = await pipe.readall()
        pipe = Once(intermediate) \
            >> DecryptRSA(bundle.vault.identity.private_key)
        output = await pipe.readall()
        assert input == output


async def test_rsa_pipe_pkcs1_oaep(local_vault, local_app):
    vault = local_vault
    bundle = BundleManager(local_app).get_bundle_for_relpath('hello.txt', local_vault)
    for i in (2, 10, 1242):
        input = b'a' * i + b'b' * int(i / 2)
        pipe = Once(input) \
            >> EncryptRSA_PKCS1_OAEP(bundle.vault.identity.public_key)
        intermediate = await pipe.readall()
        pipe = Once(intermediate) \
            >> DecryptRSA_PKCS1_OAEP(bundle.vault.identity.private_key)
        output = await pipe.readall()
        assert input == output
