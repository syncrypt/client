import json

from aiohttp import web


class JSONResponse(web.Response):
    def __init__(self, obj, **kwargs):
        super(JSONResponse, self).__init__(
                body=json.dumps(obj).encode('utf-8'),
                content_type='application_json',
                **kwargs)
