# BASHFUL | E2E 
### end-to-end encrypted chats, right in your terminal. 
<div>
    <img src="https://skillicons.dev/icons?i=arch,bash,github,obsidian"/>
</div>
Bashful is a CLI-based chat service that is being built to give you another way of communication via the terminal on both windows and linux.
The initial idea stemmed from whatsapp being dookie right now with all the tracking and AI use, so bashful was made. 

## DEPENDENCIES
if run on for example arch linux, everything is already pre-installed. </br>
for windows, please install the latest version of [nmap](https://nmap.org/download), and some sort of bash supported terminal (git bash is recommended) 

## Connecting

Bashful uses a client/server setup: start the server on one computer, then run
the Bash client on any computer that can reach it. Messages are encrypted by
the client before being sent to the server.

## Requirements

The server needs Python 3.10 or newer. The client needs Bash 4 or newer,
OpenSSL 3.x, and common Unix command-line utilities.

- On Windows, use Git Bash for the client and install Python for the server.
  Check `openssl version` in Git Bash; it must report OpenSSL 3.x.
- On Linux, install Bash, OpenSSL 3.x, and Python 3.10+ using your
  distribution's package manager.

## Start the server

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

If clients connect from another computer, allow inbound TCP traffic on port
`7443` through the server machine's firewall. For connections over the
internet, the server must also be reachable at a public hostname or IP address;
configure router port forwarding if the server is behind a router. Do not
expose the port unless you intend to let others reach the service.

Optional server settings:

```text
--host ADDRESS       Listen address (default: 0.0.0.0)
--port PORT          Listen port (default: 7443)
--data DIRECTORY     Database and certificate directory (default: chat-data)
--invite-code CODE   Require this code to register accounts
```

## Connect with the Bashful client

On the client computer, open a terminal in the repository and run:

```bash
./chat.sh SERVER_HOST
```

For example, on the same computer as the server:

```bash
./chat.sh localhost
```

Or, from another computer on the network:

```bash
./chat.sh 192.168.1.25
```

Use the server's reachable hostname or IP address. If you changed the port,
include it as `HOST:PORT`, for example `./chat.sh chat.example.com:7443`.
IPv6 addresses must be bracketed, for example
`./chat.sh [2001:db8::1]:7443`.

The first time you connect to a server, the client displays the certificate's
SHA-256 fingerprint and asks whether to trust it. Compare it with the
fingerprint printed in the server terminal using a trusted channel before
answering `y`. The client remembers the pinned certificate for that server.
If the server certificate changes unexpectedly, stop and verify the change
with the server operator before trusting it again.

The client then asks for a username and password. Choose **register** to make a
new account, or **login** to use an existing account. Usernames are 1–32
letters, digits, underscores, or hyphens. If the server requires invitations,
enter the invite code when prompted during registration. Keep your password:
there is no password reset or account recovery.

Once connected, type `help` to see client commands. For example:

```text
dm USER MESSAGE
history
rooms
quit
```

The client keeps local account keys and certificate pins under
`$HOME/.e2e-chat` by default. Keep this directory private. You can choose a
different local data directory with `--data-dir` and prefill the username with
`--username`:

```bash
./chat.sh --username alice --data-dir "$HOME/.bashful" chat.example.com
```

See [server/PROTOCOL.md](server/PROTOCOL.md) for protocol details and
server-operation guidance.
