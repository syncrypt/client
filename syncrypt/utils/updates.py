import asyncio
import ssl
from distutils.version import LooseVersion

import aiohttp
import certifi

import syncrypt

# The endpoint should return something along the lines of:
# { "darwin": "x.y.z", "linux": "x.y.z", "win": "x.y.z" }
CURRENT_ENDPOINT = 'https://alpha.syncrypt.space/releases/current.json'

@asyncio.coroutine
def retrieve_available_version(platform_id):
    sslcontext = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl_context=sslcontext)
    with aiohttp.ClientSession(connector=conn) as c:
        r = yield from c.get(CURRENT_ENDPOINT)
        content = yield from r.json()
        return content[platform_id]

def is_update_available():
    'returns tuple (is_available, available_version)'
    import platform
    avail = yield from retrieve_available_version(platform.system().lower())
    return (LooseVersion(syncrypt.__version__) < LooseVersion(avail), avail)
