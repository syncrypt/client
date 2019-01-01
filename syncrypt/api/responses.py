import enum
import json

from aiohttp import web


class EnumEncoder(json.JSONEncoder):

    def default(self, obj):  # pylint: disable=method-hidden
        if isinstance(obj, enum.Enum):
            return obj.value

        return json.JSONEncoder.default(self, obj)


class JSONResponse(web.Response):
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
        "Access-Control-Allow-Headers": "X-Authtoken, Content-Type, Origin, Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers",
    }

    @staticmethod
    def encode_body(obj):
        return json.dumps(obj, cls=EnumEncoder).encode("utf-8")

    def __init__(self, obj, **kwargs):
        super(JSONResponse, self).__init__(
            body=JSONResponse.encode_body(obj),
            content_type="application/json",
            headers=self.cors_headers,
            **kwargs
        )
