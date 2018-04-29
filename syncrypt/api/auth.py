import string
import random

import aiohttp.web

AUTH_TOKEN_HEADER = 'X-AuthToken'

def random_string(length=6, chars=string.ascii_lowercase + \
                                string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(length))

def generate_api_auth_token():
    return random_string(32)

def require_auth_token(f):
    def inner(resource, request, *args, **kwargs):
        req_token = request.headers.get(AUTH_TOKEN_HEADER, '')
        auth_token = resource.app.config.get('api.auth_token')

        if not auth_token or (req_token == auth_token):
            return f(resource, request, *args, **kwargs)
        else:
            raise aiohttp.web.HTTPForbidden()
    return inner

def require_identity(f):
    '''
    An API resource with this decorator requires that the identity is initialized, i.e. that the
    user keys have been generated.
    '''
    def inner(resource, request, *args, **kwargs):
        resource.app.identity.assert_initialized()
        return f(resource, request, *args, **kwargs)
    return inner
