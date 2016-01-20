# Syncrypt platform independent desktop client

Currently requires Python 3.

Install globally:

    pip install .

Setup in virtualenv for development:

    virtualenv .
    bin/pip install -e .

## Syncrypt GUI

*tbd*

## Syncrypt Daemon

The ``syncrypt_daemon`` is a daemon script for UNIX-like systems. It provides
a HTTP API through which it can be queried and commanded to take action.

Run the daemon:

     syncrypt_daemon start/stop/restart

Query statistics:

     curl http://127.0.0.1:28080/stats

Query all vaults:

     curl http://127.0.0.1:28080/vaults

Add a vault:

     curl http://127.0.0.1:28080/vaults/add?path=/path/to/the/folder

## Syncrypt CLI

``syncrypt`` is a low level tool to run core functionality directly from
the command line. It is intended as a debug tool and must not run at the same
time as the daemon.

Init current directory (will ask for username and password):

    syncrypt init

Pull or push current directory:

    syncrypt pull/push

Watch current directory (this is like a daemon running the foreground as it
also provides the HTTP interface):

    syncrypt watch

Alternate directories can be specified with ``-d``:

    syncrypt -d ~/myfolder watch

Debug logging can be activated via ``-l DEBUG``.

## Tests

Run tests:

    bin/pip install -e '.[test]'
    bin/python tests/test_all.py
