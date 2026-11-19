# Server instructions

## Requirements

The server requires Python 3.10 or newer. Install Python using the appropriate
installer for your operating system or your Linux distribution's package
manager.

## Install and start

From the repository root, install the server dependency and start the server:

```bash
cd server
python -m pip install -r requirements.txt
python server.py
```

By default, the server listens on port `7443` on all network interfaces and
stores its database and TLS certificate in `server/chat-data/`. Keep this
directory: it contains the accounts, messages, and certificate. Removing or
replacing it resets the server identity and data.

The server prints its SHA-256 certificate fingerprint when it starts. Share
that fingerprint with users over a trusted channel so they can verify the
server on their first connection.

To require an invite code for new registrations, start the server with:

```bash
python server.py --invite-code YOUR_INVITE_CODE
```

## Network access

If clients connect from another computer, allow inbound TCP traffic on port
`7443` through the server machine's firewall. For connections over the
internet, the server must also be reachable at a public hostname or IP address;
configure router port forwarding if the server is behind a router. Do not
expose the port unless you intend to let others reach the service.

The bundled Bash client is configured to connect to `77.172.104.230:7443`.
If the server uses a different address or port, update `SERVER_HOST` and
`SERVER_PORT` in `chat.sh` to match.

## Optional server settings

```text
--host ADDRESS       Listen address (default: 0.0.0.0)
--port PORT          Listen port (default: 7443)
--data DIRECTORY     Database and certificate directory (default: chat-data)
--invite-code CODE   Require this code to register accounts
```

See [server/PROTOCOL.md](server/PROTOCOL.md) for protocol details.