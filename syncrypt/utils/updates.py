import json
import ssl
from distutils.version import LooseVersion  # pylint: disable=import-error,no-name-in-module

import certifi

import syncrypt
from syncrypt.pipes import URLReader

# The endpoint should return something along the lines of:
# { "darwin": "x.y.z", "linux": "x.y.z", "win": "x.y.z" }
CURRENT_ENDPOINT = 'https://alpha.syncrypt.space/releases/current.json'


async def retrieve_available_version(platform_id):
    content = await URLReader(CURRENT_ENDPOINT).readall()
    return json.loads(content)[platform_id]


async def is_update_available():
    'returns tuple (is_available, available_version)'
    import platform
    avail = await retrieve_available_version(platform.system().lower())
    return (LooseVersion(syncrypt.__version__) < LooseVersion(avail), avail)
