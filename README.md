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
the client before being sent to the server. See
[server_instructions.md](server_instructions.md) for server setup and operation.

## Client requirements

The client needs Bash 4 or newer, OpenSSL 3.x, and common Unix command-line
utilities.

- On Windows, use Git Bash and check that `openssl version` reports OpenSSL 3.x.
- On Linux, install Bash, OpenSSL 3.x, and common Unix command-line utilities
  using your distribution's package manager.

## Connect with the Bashful client

The client uses the central server configured in `chat.sh` at
`77.172.104.230:7443`. From the repository, start the interactive menu:

```bash
./chat.sh
```

Choose **Connect to the central server**. You can also start a connection
directly from the command line:

```bash
./chat.sh --username alice
```

To change the central endpoint, update `SERVER_HOST` and `SERVER_PORT` in
`chat.sh`.

The first time you connect to the central server, the client displays the
certificate's SHA-256 fingerprint and asks whether to trust it. Compare it
with the fingerprint printed in the server terminal using a trusted channel
before answering `y`. The client remembers the pinned certificate for that
server.
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
./chat.sh --username alice --data-dir "$HOME/.bashful"
```

See [server/PROTOCOL.md](server/PROTOCOL.md) for protocol details.
