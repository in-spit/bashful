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
utilities. No Python client dependency is required.

- On Windows, use Git Bash and check that `openssl version` reports OpenSSL 3.x.
- On Linux, install Bash, OpenSSL 3.x, and common Unix command-line utilities
  using your distribution's package manager.

## Install the client

The client contains its server endpoint as encrypted data and decrypts it at
startup. Choose the instructions for the terminal you use.

### Linux

From the repository, install the `bashful` command for your Linux user:

```bash
bash install.sh
```

The installer creates `~/.local/bin/bashful` without requiring root access.
If it reports that `~/.local/bin` is not in your `PATH`, add this line to
your shell startup file (such as `~/.bashrc`) and open a new terminal:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then start the client from any directory with:

```bash
bashful
```

The installed launcher points to this checkout, so keep the repository in
place; rerun `bash install.sh` after moving it.

### Windows (Git Bash)

Open Git Bash in the repository and run the client directly:

```bash
bash chat.sh
```

To use `bashful` instead, run `bash install.sh` from Git Bash. If the installer
says `~/.local/bin` is not in your `PATH`, add
`export PATH="$HOME/.local/bin:$PATH"` to `~/.bashrc` in Git Bash, then open a
new Git Bash terminal. This command is available in Git Bash; it does not add
`bashful` to PowerShell or Command Prompt.

## Using the client

After signing in, select a previous chat by number or choose **New chat** and
enter a registered username. In a conversation, type a message and press Enter
to send it; use `/back` to return to the chat list. Use **Commands** for room
management, trust controls, and other client commands.

Messages are queued by the server while the recipient is offline and delivered
when they reconnect. Encrypted direct and room-message history is also retained
on the server so it can sync to other devices using the same account. New
messages are synced; history already stored only on a device is not uploaded.
Use `/delete NUMBER` or `/clear` in a conversation to delete history from your
account on all devices. The other participants keep their own copies.
The server stores a password-derived verifier and an encrypted private-key
backup, not your plaintext password or message contents.

You can prefill the username and choose a local data directory from the
command line:

```bash
bashful --username alice
```

If you are starting the script directly in Git Bash, you can pass the same
options after `chat.sh`, for example `bash chat.sh --username alice`.

this part used to be a way to connect to different servers, we dont do that anymore

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

The client keeps local account keys and certificate pins under
`$HOME/.e2e-chat` by default. Keep this directory private. You can choose a
different local data directory with `--data-dir` and prefill the username with
`--username`:

```bash
bashful --username alice --data-dir "$HOME/.bashful"
```

See [server/PROTOCOL.md](server/PROTOCOL.md) for server setup and protocol details.
