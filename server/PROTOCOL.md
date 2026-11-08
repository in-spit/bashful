# Chat server protocol (v1)

The server is a relay, an account store and an offline mailbox. It never sees message plaintext, private keys or passwords. Everything a client encrypts (`env`, `blob`) is an opaque string to the server, so the crypto scheme is the client's choice. Section 11 describes the scheme the reference Python client uses, but nothing in the server depends on it.

Everything in this document was checked against the running server, including the bash snippets in sections 2 and 12 (tested on Linux with OpenSSL 3.0; not yet on Windows Git Bash).

## 1. Running the server

```
pip install -r requirements.txt
python server.py [--host 0.0.0.0] [--port 7443] [--data chat-data] [--invite-code CODE]
```

- Needs Python 3.10+ and the `cryptography` package.
- On first start it creates `cert.pem`, `key.pem` and `server.db` in the data directory. Deleting the directory resets everything, including accounts and the certificate.
- It prints the certificate fingerprint on startup, as SHA-256 in groups of four hex digits. Give that to your users so they can verify the first connection.
- `--invite-code CODE` makes `register` require that code. Without it anyone who can reach the port can register.
- It logs registrations, logins and disconnects. It never logs message content.
- On Windows, allow `python` through the firewall (private networks) or nobody else can connect.

## 2. Connecting

**Address format:** `host` or `host:port`. The default port is 7443. The server itself only has a host and a port; the optional `:port` is a client convention.

**Transport:** TCP with TLS 1.2 or newer. The certificate is self-signed (EC P-256), so there is no CA to validate it. Clients pin it: on the first connection show the fingerprint and ask the user, then trust only that exact certificate afterwards.

The fingerprint is the lowercase hex SHA-256 of the DER-encoded certificate.

**Bash has no TLS of its own, so use `openssl s_client`.** Pinning with OpenSSL itself: save the certificate once, then use it as the only trust anchor. A different certificate makes the connection fail with exit status 1.

```bash
openssl s_client -connect "$host:$port" </dev/null 2>/dev/null | openssl x509 > "$pin_file"
openssl x509 -in "$pin_file" -outform DER | openssl dgst -sha256 -hex | sed 's/^.*= *//'

coproc TLS { exec openssl s_client -quiet -connect "$host:$port" \
               -CAfile "$pin_file" -verify_return_error 2>/dev/null; }
exec 3<&"${TLS[0]}" 4>&"${TLS[1]}"
IFS= read -r -t 5 hello <&3
printf '%s\n' '{"t":"ping","id":1}' >&4
```

Notes:

- `-quiet` implies `-ign_eof`, so closing your stdin does not close the connection. Kill the process (`$TLS_PID`) to disconnect.
- If the first `read` returns end-of-file, the pin check failed or the server is unreachable.
- Bash warns (`coproc ... still exists`) if you start a second coproc. You only need one connection per client.

## 3. Framing

- One JSON object per line, UTF-8, ending in `\n`. Both directions.
- Maximum line length is 262144 bytes (256 KiB). A longer line closes the connection.
- Client lines may be formatted any way JSON allows. Server frames are compact JSON with no spaces.
- Server frames always start with `"t"`. When a request had an `id`, the reply ends with that same `id`. Key order is currently stable, but use a real JSON parser if you have one.
- Hex values (`auth`, `enc`, `sig`, `mid`) must be lowercase. `openssl enc -P` prints uppercase, so lowercase it (`${var,,}`).
- Apart from `invite`, every value a client sends is hex, base64, digits or `[a-z0-9_-]` by design. So bash can build requests with `printf` and no JSON escaping, as long as the client keeps to those character sets (the server does not enforce base64 for `env` and `blob`, only length). An `invite` code can contain anything, so escape `"` and `\` in it.

## 4. Session lifecycle

1. After the TLS handshake the server immediately sends `{"t":"hello","v":1,"invite":false}`. `invite` is `true` when registration needs a code.
2. Before logging in you may only send `register`, `login` and `ping`. Anything else returns `auth_required`.
3. A connection that stays idle for 120 s before logging in is closed.
4. After logging in, 300 s of silence closes the connection. Send `{"t":"ping"}` at least every 60 s. The reply is `{"t":"pong"}`.
5. Only one live session per user. A second login kicks the first, which receives `{"t":"err","code":"kicked","msg":"..."}` and is closed.
6. A client whose connection stops draining for 15 s is dropped.

## 5. Accounts and authentication

The goal is that the server never learns the password or the private keys:

1. The client derives two independent 32-byte secrets from the password: `auth` (sent to the server) and a blob key (never sent).
2. The client generates its identity keypairs and encrypts the private halves with the blob key. That ciphertext is the `blob`.
3. `register` sends `auth`, the two public keys and the `blob`. The server stores `SHA-256("e2echat1-verifier|" + auth)`, the public keys and the blob.
4. `login` sends `auth`. On success the server returns the public keys and the `blob`, so logging in on a new machine needs only username and password.

What the server enforces: usernames, format of `auth`/`enc`/`sig` (64 lowercase hex characters each), `blob` (1 to 4096 characters), and password verification by comparing verifiers. It cannot check how you derived `auth` or what is in the blob.

- Usernames: 1 to 32 characters from `a-z 0-9 _ -`. Input is case-insensitive and stored lowercase. Derive anything from the lowercased name.
- Wrong password and unknown user return the same `bad_credentials` error.
- Throttling: 8 failed logins within 10 minutes, counted per source IP and separately per username, then `throttled` until the oldest failures age out (even the correct password is refused meanwhile). Registration attempts, successful or not, are limited to 20 per hour per IP.
- There is no password change or recovery: forget the password and the identity blob is unreadable.

## 6. Requests and replies

Every request is `{"t": <command>, "id": <optional int or string>, ...}`. Every request gets exactly one reply: `{"t":"ok",...}` or `{"t":"err","code":"...","msg":"..."}`, carrying `id` back if you sent one. If you omit `id` you still get a reply (for example after `ack`) and have to read and discard it.

**Pushed frames can arrive between your request and its reply**, so read frames in a loop and match replies by `id`. Frames without a matching `id` (`msg`, `event`) are pushes.

| Command | Request fields | Success reply | Errors |
|---|---|---|---|
| `register` | `user`, `auth`, `enc`, `sig`, `blob`, `invite` (only if the server asks) | `{"t":"ok","user":"alice"}`, and you are now logged in | `invite_required`, `bad_name`, `bad_request`, `exists`, `throttled`, `already_logged_in` |
| `login` | `user`, `auth` | `{"t":"ok","user","enc","sig","blob"}`, then pending messages follow | `bad_credentials`, `throttled`, `already_logged_in` |
| `ping` | none | `{"t":"pong"}` | none |
| `keys` | `user` | `{"t":"ok","user","enc","sig"}` | `no_such_user`, `bad_name` |
| `send` | `to`, `mid`, `ts`, `env` | `{"t":"ok"}` | `no_such_user`, `mailbox_full`, `bad_request`, `bad_name` |
| `ack` | `ids` (list of up to 500 `mbid` integers) | `{"t":"ok"}` | `bad_request` |
| `rooms` | none | `{"t":"ok","rooms":[{"room","admin","version"},...]}` | none |
| `room_create` | `room` | `{"t":"ok","room","version":1}` | `exists`, `limit`, `bad_name` |
| `room_add` | `room`, `user` | `{"t":"ok","room","version"}` | `no_such_room`, `not_admin`, `no_such_user`, `already_member`, `room_full` |
| `room_kick` | `room`, `user` | `{"t":"ok","room","version"}` | `no_such_room`, `not_admin`, `not_member`, `bad_request` (kicking yourself) |
| `room_leave` | `room` | `{"t":"ok","room"}` | `no_such_room` |
| `room_info` | `room` | `{"t":"ok","room","admin","version","members":[{"user","enc","sig"},...]}` | `no_such_room` |
| `room_send` | `room`, `version`, `mid`, `ts`, `envs` (object: username to `env`) | `{"t":"ok"}` | `no_such_room`, `stale`, `bad_recipients`, `mailbox_full`, `bad_request` |

Field rules:

- `mid`: 32 lowercase hex characters, chosen by the sender (use `openssl rand -hex 16`). It identifies a message for de-duplication.
- `ts`: integer Unix seconds, chosen by the sender. The server passes it through and does not check it.
- `env`: non-empty string, at most 65536 characters. Opaque to the server (base64 in practice).
- `room`: same rules as usernames. Room names are global and case-insensitive.
- `room_send` must contain exactly one envelope for every current member except yourself, no more and no fewer, and `version` must equal the room's current version. Otherwise you get `bad_recipients`, or `stale` with the current number in `"version"`. On `stale`: call `room_info` again, re-encrypt for the new member list, retry.
- Members of a room are the only people who can see it. Non-members get `no_such_room` for every room command, whether or not the room exists.
- `room_info` returns the members' public keys, so you do not need a `keys` call per member.

Reply examples:

```
{"t":"ok","user":"pal","enc":"06d9...","sig":"8519...","id":2}
{"t":"err","code":"no_such_room","msg":"no such room","id":"x1"}
{"t":"err","code":"stale","msg":"the member list changed, refresh it and try again","version":2,"id":7}
```

## 7. Frames the server pushes

```
{"t":"hello","v":1,"invite":false}

{"t":"msg","mbid":3,"kind":"dm","from":"pal","room":"","mid":"84ec...","ts":1793000876,"env":"q+zk..."}
{"t":"msg","mbid":9,"kind":"room","from":"pal","room":"lab","mid":"5f1e...","ts":1793000900,"env":"..."}

{"t":"event","mbid":4,"kind":"member_added","room":"lab","user":"pal","by":"bashy","version":2,"admin":"bashy"}
{"t":"event","mbid":6,"kind":"member_removed","room":"lab","user":"pal","by":"bashy","reason":"kicked","version":3,"admin":"bashy"}

{"t":"err","code":"kicked","msg":"you logged in from somewhere else"}
```

- `msg`: `kind` is `dm` or `room`. `room` is `""` for direct messages. `from` is set by the server from the sender's session, but the server could lie, so verify the sender's signature (see section 11).
- `event`: `user` is who was affected, `by` is who did it, `version` is the room version after the change, `admin` is the room admin after the change, and `reason` (only on `member_removed`) is `kicked` or `left`.
  - `member_added` goes to every member after the change, including the person added and the admin who did it.
  - `member_removed` by kick goes to the remaining members and the kicked user. By leaving it goes to the remaining members only.
  - If the admin leaves, the member who joined earliest becomes admin. If the last member leaves, the room is deleted.
- `mbid` is the mailbox id used for `ack`. It increases across the whole server, so your own ids have gaps.

## 8. Delivery and history

- **Store and forward.** `send` and `room_send` put one row in each recipient's mailbox, whether or not they are online. Online recipients get it pushed immediately.
- **At-least-once.** A row stays in the mailbox until its recipient sends `ack` with its `mbid`. Without an ack it is pushed again on every future login. After a login the server first sends everything unacked, oldest first (so possibly many frames right after the `ok`).
- **Always ack**, including for events, duplicates and messages you could not decrypt or verify (otherwise they come back forever). Exception: if you deliberately hold a message (for example, an unknown sender waiting for the user to trust them), do not ack it yet.
- **De-duplicate** on `(from, mid)`, because a crash between displaying and acking causes a redelivery.
- **No history.** After an ack the server keeps nothing. There is no sent-items copy for the sender, no message log and no way to fetch old messages. Clients that want history must store it locally.
- **`ok` to a `send` means "queued in the recipient's mailbox"**, not "delivered" or "read". There are no read receipts or typing indicators.
- **No expiry.** Unacked mailbox rows are kept indefinitely, up to 5000 rows per user (messages and events together). After that, senders get `mailbox_full`.
- **Room messages are fan-out.** The server stores a separate row per recipient. The member list is managed by the server, and a malicious server could add someone to it, so clients should show join and leave events to their users.
- **Ordering** is by `mbid` per recipient. Nothing orders messages from different senders beyond that.
- **Rate limits:** none on sending messages. The limits that exist are listed in section 10.

## 9. Error codes

| Code | Meaning |
|---|---|
| `bad_request` | Malformed frame, unknown command, or a field with the wrong type, size or format |
| `bad_name` | Username or room name fails `^[a-z0-9_-]{1,32}$` after lowercasing |
| `auth_required` | Command needs a logged-in session |
| `already_logged_in` | `register` or `login` on a session that is already logged in |
| `invite_required` | Server needs an invite code and it was missing or wrong |
| `exists` | Username or room name taken |
| `bad_credentials` | Wrong username or password |
| `throttled` | Too many failed logins or registrations |
| `no_such_user` | Recipient or target does not exist |
| `no_such_room` | Room does not exist, or you are not a member |
| `not_admin` | Only the room admin may do this |
| `not_member` | Target is not in the room |
| `already_member` | Target is already in the room |
| `room_full` | Room already has 50 members |
| `limit` | You already administer 20 rooms |
| `mailbox_full` | A recipient has 5000 unacked items |
| `stale` | Room membership changed; reply includes the current `version` |
| `bad_recipients` | `room_send` envelopes do not match the members exactly |
| `kicked` | Pushed to a session replaced by a newer login (not a reply) |
| `internal` | Server bug; the details are in the server log |

## 10. Limits

| What | Limit |
|---|---|
| Line length | 262144 bytes |
| `env` | 65536 characters |
| `blob` | 4096 characters |
| `invite` | 128 characters |
| Username, room name | 1 to 32 characters of `a-z 0-9 _ -` |
| Members per room | 50 |
| Rooms you can administer | 20 |
| Unacked items per mailbox | 5000 |
| `ids` per `ack` | 500 |
| Failed logins before `throttled` | 8 per 10 minutes, per IP and per username |
| Registrations | 20 per hour per IP |
| Idle timeouts | 120 s before login, 300 s after |

## 11. What the reference Python client puts in the opaque fields

The server ignores all of this. Follow it only if you want your client to interoperate with `client.py`; otherwise choose your own, as long as the clients that talk to each other agree.

**Password handling**

- `salt = SHA-256("e2echat1-salt|" + username)`.
- `scrypt(password, salt, N=2^15, r=8, p=1, length=64)`. The first 32 bytes are `auth` (sent as hex). The last 32 bytes are the blob key.

**Identity** (two keypairs per account)

- X25519 for encryption and Ed25519 for signing. `enc` and `sig` are the raw 32-byte public keys as lowercase hex.
- `blob = base64(nonce[12] + AES-256-GCM(blob key, x25519_private[32] + ed25519_private[32], aad = "identity|" + username))`.

**Message envelope** (used for every `env`; room messages use one envelope per recipient)

- Generate a fresh X25519 key pair for each envelope. `shared = X25519(ephemeral private, recipient enc public)`.
- `key = HKDF-SHA256(shared, salt = ephemeral_public + recipient_enc_public, info = "e2echat1-msg", length = 32)`.
- `aad = JSON [kind, sender, recipient, room, mid, ts]`, compact, where `kind` is `"dm"` or `"room"`, `room` is `""` for DMs, and `recipient` is the individual receiver even in rooms.
- `ciphertext = AES-256-GCM(key, random 12-byte nonce, plaintext, aad)`.
- `signature = Ed25519(sender signing key, "e2echat1-sig\0" + aad + ephemeral_public + nonce + ciphertext)`.
- `env = base64(0x01 + ephemeral_public[32] + nonce[12] + signature[64] + ciphertext)`.
- Receiver verifies the signature with the sender's pinned `sig` key, then decrypts.

**Trust.** Clients pin each contact's `enc` and `sig` on first contact, after the user checks a fingerprint over another channel, and refuse to send if they later change. The server cannot be trusted to hand out the right keys, so this is what stops it from impersonating people.

## 12. Notes for a bash client

- **JSON in bash.** Git Bash does not ship `jq`. Build requests with `printf` (safe given the character sets in section 3) and read server frames with `sed`, for example `sed -n 's/.*"mbid":\([0-9]*\).*/\1/p'`. Server strings never contain quotes or backslashes today.
- **One reader loop.** Because pushes can arrive at any time (right after `login`, between a request and its reply), a single background reader that handles `msg` and `event` frames and passes replies to the foreground by `id` works better than reading a reply immediately after each send. `chat.sh` already uses this shape.
- **A password KDF without the password on a command line.** `openssl enc ... -pass env:PW -P` prints a key derived by PBKDF2 and never puts the password in `ps`. Different salts give unrelated keys:

  ```bash
  salt=$(printf 'e2echat-auth|%s' "$user" | openssl dgst -sha256 -hex | sed 's/^.*= *//' | cut -c1-16)
  auth=$(PW="$password" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 \
           -pass env:PW -S "$salt" -P | sed -n 's/^key=//p')
  auth=${auth,,}
  ```

  The salt for `-S` is 8 bytes (16 hex characters); a longer one is silently truncated with a warning. Use a second salt, for example `e2echat-enc|user`, for the key that encrypts the identity blob. 600000 iterations took about 1.1 s per derivation on the test machine, so a login costs two of those.
- **No AES-GCM in `openssl enc`.** It only does unauthenticated modes, so a bash envelope needs encrypt-then-MAC (AES-256-CBC plus HMAC-SHA256, as `chat.sh` does). X25519 key agreement works with `openssl pkeyutl -derive`. For signatures, Ed25519 signing is `openssl pkeyutl -sign -rawin` on OpenSSL 3.x, which I have not tested here.
- **Charset reminder.** `enc`/`sig` must be exactly 64 lowercase hex characters, so a 32-byte raw key encoded with `od -An -tx1 | tr -d ' \n'` fits. Base64 for `blob`/`env` must be on one line (`tr -d '\n'`).
