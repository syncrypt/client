# Syncrypt platform independent desktop client

Currently requires Python 3.

Setup in virtualenv:

    virtualenv .
    bin/pip install -e .

Pull current directory:

    bin/syncrypt pull

Push current directory:

    bin/syncrypt push

Watch current directory:

    bin/syncrypt watch

Alternate directory can be specified with ``-d``:

    bin/syncrypt -d ~/myfolder watch

