# Syncrypt platform independent desktop client

Currently requires Python 3.

Setup in virtualenv:

    virtualenv .
    bin/pip install -e .

Pull current directory:

    bin/python scripts/syncrypt-client.py pull

Push current directory:

    bin/python scripts/syncrypt-client.py push

Watch current directory:

    bin/python scripts/syncrypt-client.py watch

Alternate directory can be specified with ``-d``:

    bin/python scripts/syncrypt-client.py -d ~/myfolder watch

