import asyncio
import ssl
from distutils.version import LooseVersion  # pylint: disable=import-error,no-name-in-module

import aiohttp
import certifi

import syncrypt

# The endpoint should return something along the lines of:
# { "darwin": "x.y.z", "linux": "x.y.z", "win": "x.y.z" }
CURRENT_ENDPOINT = 'https://alpha.syncrypt.space/releases/current.json'


async def retrieve_available_version(platform_id):
    sslcontext = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl_context=sslcontext)
    with aiohttp.ClientSession(connector=conn) as c:
        r = await c.get(CURRENT_ENDPOINT)
        content = await r.json()
        return content[platform_id]


async def is_update_available():
    'returns tuple (is_available, available_version)'
    import platform
    avail = await retrieve_available_version(platform.system().lower())
    return (LooseVersion(syncrypt.__version__) < LooseVersion(avail), avail)
