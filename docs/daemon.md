# Syncrypt Daemon

The Syncrypt Daemon is the part of Syncrypt that runs in the background and
manages all file transfer and encryption.

## API

[![OpenAPI validity](http://online.swagger.io/validator?url=https://raw.githubusercontent.com/syncrypt/client/master/swagger.yaml)](https://generator.swagger.io/?url=https://raw.githubusercontent.com/syncrypt/client/master/swagger.yaml)

The Syncrypt Daemon features a local HTTP API, over which all communication
with the Desktop GUI happens. If you want to integrate Syncrypt features into
your application, you can also use the HTTP API.

Follow [this link](https://generator.swagger.io/?url=https://raw.githubusercontent.com/syncrypt/client/master/swagger.yaml)
for a description of available API calls. In order to make API calls, click on "Authorize" and enter
the Daemon auth token, which you can find in ``~/.config/syncrypt/config``.
