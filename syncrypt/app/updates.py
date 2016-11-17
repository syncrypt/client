import asyncio
import aiohttp
import syncrypt
from distutils.version import LooseVersion

# The endpoint should return something along the lines of:
# { "darwin": "x.y.z", "linux": "x.y.z", "win": "x.y.z" }
CURRENT_ENDPOINT = 'https://alpha.syncrypt.space/releases/current.json'

@asyncio.coroutine
def retrieve_available_version(platform_id):
    with aiohttp.ClientSession() as c:
        r = yield from c.get(CURRENT_ENDPOINT)
        content = yield from r.json()
        return content[platform_id]

def is_update_available():
    'returns tuple (is_available, available_version)'
    import platform
    avail = yield from retrieve_available_version(platform.system().lower())
    return (LooseVersion(syncrypt.__version__) < LooseVersion(avail), avail)
