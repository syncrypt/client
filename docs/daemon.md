# Syncrypt Daemon

The Syncrypt Daemon is the part of Syncrypt that runs in the background and
manages all file transfer and encryption.

## API

The Syncrypt Daemon features an local HTTP API, over which all communication
with the Desktop GUI happens. If you want to integrate Syncrypt features into
your application, you can also use the HTTP API.

Follow [this link](https://generator.swagger.io/?url=https://raw.githubusercontent.com/syncrypt/client/reliability/swagger.yaml)
for a description of available API calls. In order to make API calls, click on "Authorize" and enter
the Daemon auth token, which you can find in ``~/.config/syncrypt/config``.

