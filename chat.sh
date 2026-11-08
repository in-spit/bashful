#!/usr/bin/env bash
# Bash client for the Bashful store-and-forward server.
# Requires Bash 4+, OpenSSL 3+, and standard Unix text/file utilities.

set -u
umask 077

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() {
  local status=2
  [[ ${1:-} == 0 ]] && status=0
  cat >&2 <<'EOF'
Usage: ./chat.sh [--data-dir DIR] [--username USER] HOST[:PORT]
Default server port: 7443

Commands:
  dm USER MESSAGE
  history [USER|room:ROOM]
  trust USER | untrust USER
  rooms | room-create NAME | room-add NAME USER | room-kick NAME USER
  room-leave NAME | room-info NAME | room-send NAME MESSAGE
  help | quit
EOF
  exit "$status"
}

for command in openssl sed awk od base64 dd mktemp tail tr wc grep date timeout cat; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
(( BASH_VERSINFO[0] >= 4 )) || die "Bash 4 or newer is required"
OPENSSL_VERSION=$(openssl version | awk '{print $2}')
[[ $OPENSSL_VERSION =~ ^3\. ]] || die "OpenSSL 3.x is required for Ed25519 signing"

DATA_DIR=${CHAT_HOME:-$HOME/.e2e-chat}
USERNAME=""
while (( $# )); do
  case $1 in
    --data-dir) (( $# >= 2 )) || usage; DATA_DIR=$2; shift 2 ;;
    --username|-u) (( $# >= 2 )) || usage; USERNAME=$2; shift 2 ;;
    --help|-h) usage 0 ;;
    --*) usage ;;
    *) SERVER_ADDRESS=$1; shift; break ;;
  esac
done
[[ -n ${SERVER_ADDRESS:-} && $# == 0 ]] || usage

if [[ $SERVER_ADDRESS == \[* ]]; then
  [[ $SERVER_ADDRESS =~ ^\[([^]]+)\](:([0-9]+))?$ ]] || die "invalid server address"
  SERVER_HOST=${BASH_REMATCH[1]}
  SERVER_PORT=${BASH_REMATCH[3]:-7443}
else
  if [[ $SERVER_ADDRESS == *:* ]]; then
    [[ $SERVER_ADDRESS != *:*:* ]] || die "write IPv6 addresses as [address]:port"
    SERVER_HOST=${SERVER_ADDRESS%:*}
    SERVER_PORT=${SERVER_ADDRESS##*:}
  else
    SERVER_HOST=$SERVER_ADDRESS
    SERVER_PORT=7443
  fi
fi
[[ -n $SERVER_HOST && $SERVER_PORT =~ ^[0-9]+$ ]] || die "invalid server address"
(( SERVER_PORT >= 1 && SERVER_PORT <= 65535 )) || die "port must be between 1 and 65535"

T=$(mktemp -d) || die "could not create temporary directory"
TLS_PID=""
cleanup() {
  trap - EXIT INT TERM
  [[ -n $TLS_PID ]] && kill "$TLS_PID" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap '' PIPE

mkdir -p "$DATA_DIR/pins" || die "could not create $DATA_DIR/pins"
chmod 700 "$DATA_DIR" "$DATA_DIR/pins" 2>/dev/null || :
PIN_FILE=$DATA_DIR/pins/$(printf '%s:%s' "$SERVER_HOST" "$SERVER_PORT" | openssl dgst -sha256 | sed 's/^.*= *//').pem

sha256() { openssl dgst -sha256 "$1" | sed 's/^.*= *//'; }
sha256_stdin() { openssl dgst -sha256 | sed 's/^.*= *//'; }
hmac_file() {
  openssl dgst -sha256 -mac HMAC -macopt "hexkey:$2" "$1" | sed 's/^.*= *//'
}
hex_bin() {
  local value=$1 escaped="" i
  for ((i=0; i<${#value}; i+=2)); do escaped+="\\x${value:i:2}"; done
  printf '%b' "$escaped"
}
raw_pub() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null \
    | tail -c 32 | od -An -tx1 | tr -d ' \n'
}
valid_user() { [[ ${1,,} =~ ^[a-z0-9_-]{1,32}$ ]]; }
json_string() {
  local value=${1//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}
json_field() {
  local key=$1 frame=$2
  sed -n "s/.*\"$key\":\"\\([^\"]*\\)\".*/\\1/p" <<<"$frame"
}
json_number() {
  local key=$1 frame=$2
  sed -n "s/.*\"$key\":\\([0-9][0-9]*\\).*/\\1/p" <<<"$frame"
}
json_id() { json_number id "$1"; }

pin_server() {
  [[ -f $PIN_FILE ]] && return
  printf 'Fetching server certificate... '
  timeout 12 openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" \
    -servername "$SERVER_HOST" -showcerts </dev/null 2>"$T/cert.err" \
    | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
    | awk 'BEGIN{n=0} /-----BEGIN CERTIFICATE-----/{n++} n==1{print}' > "$T/server.pem"
  [[ -s $T/server.pem ]] || die "could not retrieve the server certificate ($(tr '\n' ' ' < "$T/cert.err"))"
  local der fp grouped answer
  der=$T/server.der
  openssl x509 -in "$T/server.pem" -outform DER -out "$der" 2>/dev/null \
    || die "server did not present a valid certificate"
  fp=$(sha256 "$der")
  grouped=""
  local i
  for ((i=0; i<${#fp}; i+=4)); do grouped+="${fp:i:4} "; done
  grouped=${grouped% }
  printf '\nServer certificate SHA-256 fingerprint:\n%s\n' "$grouped"
  echo "Compare this with the fingerprint printed by the server operator."
  read -r -p "Trust and pin this certificate? [y/N] " answer || die "no input"
  [[ $answer == [yY]* ]] || die "server certificate not trusted"
  install -m 600 "$T/server.pem" "$PIN_FILE" 2>/dev/null || cp "$T/server.pem" "$PIN_FILE"
  chmod 600 "$PIN_FILE" 2>/dev/null || :
}

pin_server
coproc TLS { exec openssl s_client -quiet -connect "$SERVER_HOST:$SERVER_PORT" \
  -servername "$SERVER_HOST" -CAfile "$PIN_FILE" -verify_return_error 2>/dev/null; }
exec 3<&"${TLS[0]}" 4>&"${TLS[1]}" || die "could not start TLS connection"

FRAME=""
NET_BUFFER=""
READ_STATUS=0
read_frame() {
  local timeout=${1:-90}
  local part=""
  FRAME=""
  if IFS= read -r -t "$timeout" part <&3; then
    FRAME=$NET_BUFFER$part
    NET_BUFFER=""
    READ_STATUS=0
  else
    READ_STATUS=$?
    NET_BUFFER+=$part
    (( ${#NET_BUFFER} <= 262144 )) || die "server frame exceeds 256 KiB"
    return 1
  fi
  (( ${#FRAME} <= 262144 )) || die "server frame exceeds 256 KiB"
  [[ $FRAME == \{* ]] || die "server sent an invalid frame"
}
read_frame 15 || die "server disconnected during TLS handshake"
[[ $(json_field t "$FRAME") == hello && $(json_number v "$FRAME") == 1 ]] \
  || die "server does not speak protocol version 1"
NEEDS_INVITE=$(sed -n 's/.*"invite":\(true\|false\).*/\1/p' <<<"$FRAME")

NEXT_ID=0
LAST_FRAME=""
LAST_ERROR=""
LAST_REPLY=""

ack_mailbox() {
  printf '{"t":"ack","ids":[%s]}\n' "$1" >&4 \
    || die "connection lost while acknowledging a message"
}

save_history() {
  local direction=$1 peer=$2 kind=$3 room=$4 ts=$5 mid=$6 text=$7 encoded
  encoded=$(printf '%s' "$text" | base64 | tr -d '\r\n')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ts" "$direction" "$peer" "$kind" "$room" "$mid" "$encoded" >> "$PROFILE/history"
}

make_aad() {
  printf '["%s","%s","%s","%s","%s",%s]' "$1" "$2" "$3" "$4" "$5" "$6"
}

dh_hex() {
  local private_pem=$1 peer_hex=$2 der=$T/peer.der
  { printf '%b' '\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00'; hex_bin "$peer_hex"; } > "$der"
  openssl pkeyutl -derive -inkey "$private_pem" -peerkey "$der" -peerform DER 2>/dev/null \
    | od -An -tx1 | tr -d ' \n'
}

derive_msg_keys() {
  local shared=$1 context=$2
  ENC_KEY=$(printf '%s|enc|%s' "$shared" "$context" | sha256_stdin)
  MAC_KEY=$(printf '%s|mac|%s' "$shared" "$context" | sha256_stdin)
}

make_envelope() {
  local kind=$1 sender=$2 recipient=$3 room=$4 mid=$5 ts=$6 text=$7 recipient_enc=$8
  local eph=$T/eph.pem eph_pub shared aad iv cipher sig message mac
  openssl genpkey -algorithm X25519 -out "$eph" 2>/dev/null || die "X25519 key generation failed"
  eph_pub=$(raw_pub "$eph")
  shared=$(dh_hex "$eph" "$recipient_enc")
  [[ $shared =~ ^[0-9a-f]{64}$ && -n ${shared//0/} ]] || die "X25519 key agreement failed"
  derive_msg_keys "$shared" "$eph_pub|$recipient_enc"
  aad=$(make_aad "$kind" "$sender" "$recipient" "$room" "$mid" "$ts")
  iv=$(openssl rand -hex 16) || die "could not generate message IV"
  printf '%s' "$text" > "$T/plain"
  openssl enc -aes-256-cbc -K "$ENC_KEY" -iv "$iv" -in "$T/plain" -out "$T/cipher" 2>/dev/null \
    || die "message encryption failed"
  mac_input=$T/mac-input
  { printf '%s' "$aad"; hex_bin "$eph_pub"; hex_bin "$iv"; cat "$T/cipher"; } > "$mac_input"
  mac=$(hmac_file "$mac_input" "$MAC_KEY")
  { printf 'bashful-envelope-v1\0%s' "$aad"; hex_bin "$eph_pub"; hex_bin "$iv"; hex_bin "$mac"; cat "$T/cipher"; } > "$T/sign-input"
  openssl pkeyutl -sign -rawin -inkey "$SIGN_KEY" -in "$T/sign-input" -out "$T/signature" 2>/dev/null \
    || die "Ed25519 signing failed"
  {
    printf '\001'
    hex_bin "$eph_pub"; hex_bin "$iv"; hex_bin "$mac"
    cat "$T/signature" "$T/cipher"
  } > "$T/envelope"
  base64 < "$T/envelope" | tr -d '\r\n'
}

open_envelope() {
  local envelope=$1 kind=$2 sender=$3 recipient=$4 room=$5 mid=$6 ts=$7
  local sender_sig=$8
  printf '%s' "$envelope" | base64 -d > "$T/envelope" 2>/dev/null || return 1
  local size
  size=$(wc -c < "$T/envelope")
  (( size >= 1+32+16+32+64+16 )) || return 1
  [[ $(od -An -tu1 -N1 "$T/envelope" | tr -d ' ') == 1 ]] || return 1
  dd if="$T/envelope" of="$T/eph-pub" bs=1 skip=1 count=32 2>/dev/null
  dd if="$T/envelope" of="$T/iv" bs=1 skip=33 count=16 2>/dev/null
  dd if="$T/envelope" of="$T/claimed-mac" bs=1 skip=49 count=32 2>/dev/null
  dd if="$T/envelope" of="$T/signature" bs=1 skip=81 count=64 2>/dev/null
  dd if="$T/envelope" of="$T/cipher" bs=1 skip=145 2>/dev/null
  local eph_hex iv_hex mac_hex shared aad actual_mac
  eph_hex=$(od -An -tx1 "$T/eph-pub" | tr -d ' \n')
  iv_hex=$(od -An -tx1 "$T/iv" | tr -d ' \n')
  mac_hex=$(od -An -tx1 "$T/claimed-mac" | tr -d ' \n')
  shared=$(dh_hex "$ENC_KEYFILE" "$eph_hex") || return 1
  [[ $shared =~ ^[0-9a-f]{64}$ && -n ${shared//0/} ]] || return 1
  derive_msg_keys "$shared" "$eph_hex|$MY_ENC"
  aad=$(make_aad "$kind" "$sender" "$recipient" "$room" "$mid" "$ts")
  { printf '%s' "$aad"; cat "$T/eph-pub" "$T/iv" "$T/cipher"; } > "$T/mac-input"
  actual_mac=$(hmac_file "$T/mac-input" "$MAC_KEY") || return 1
  [[ $actual_mac == "$mac_hex" ]] || return 1
  {
    printf 'bashful-envelope-v1\0%s' "$aad"
    cat "$T/eph-pub" "$T/iv" "$T/claimed-mac" "$T/cipher"
  } > "$T/sign-input"
  { printf '%b' '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; hex_bin "$sender_sig"; } > "$T/sig-public.der"
  openssl pkeyutl -verify -pubin -inkey "$T/sig-public.der" -keyform DER \
    -rawin -in "$T/sign-input" -sigfile "$T/signature" >/dev/null 2>&1 || return 1
  openssl enc -d -aes-256-cbc -K "$ENC_KEY" -iv "$iv_hex" \
    -in "$T/cipher" -out "$T/plain" 2>/dev/null || return 1
  cat "$T/plain"
}

contact_keys() {
  local user=${1,,} response enc sig known_enc known_sig answer
  valid_user "$user" || { echo "invalid username"; return 1; }
  request keys "\"user\":\"$user\"" || { echo "$LAST_ERROR"; return 1; }
  response=$LAST_REPLY
  enc=$(json_field enc "$response")
  sig=$(json_field sig "$response")
  [[ $enc =~ ^[0-9a-f]{64}$ && $sig =~ ^[0-9a-f]{64}$ ]] || { echo "server returned invalid contact keys"; return 1; }
  if [[ -f $PROFILE/contacts ]]; then
    read -r known_enc known_sig < <(awk -v u="$user" '$1==u {print $2, $3; exit}' "$PROFILE/contacts" 2>/dev/null || :)
  fi
  if [[ -n ${known_enc:-} && -n ${known_sig:-} ]]; then
    [[ $known_enc == "$enc" && $known_sig == "$sig" ]] || {
      echo "Key changed for $user. Use 'untrust $user' only after verifying the new fingerprint out of band."
      return 1
    }
    CONTACT_ENC=$enc CONTACT_SIG=$sig
    return 0
  fi
  printf 'First contact with %s. Identity fingerprint: ' "$user"
  { hex_bin "$enc"; hex_bin "$sig"; } | sha256_stdin | {
    read -r answer
    local i
    for ((i=0; i<${#answer}; i+=4)); do printf '%s ' "${answer:i:4}"; done
    echo
  }
  read -r -p "Compare it out of band, then trust? [y/N] " answer || return 1
  [[ $answer == [yY]* ]] || return 1
  printf '%s %s %s\n' "$user" "$enc" "$sig" >> "$PROFILE/contacts"
  CONTACT_ENC=$enc CONTACT_SIG=$sig
}

process_message() {
  local frame=$1 mbid kind sender room mid ts env known_enc known_sig plain
  mbid=$(json_number mbid "$frame")
  kind=$(json_field kind "$frame")
  sender=$(json_field from "$frame")
  room=$(json_field room "$frame")
  mid=$(json_field mid "$frame")
  ts=$(json_number ts "$frame")
  env=$(json_field env "$frame")
  [[ $mbid =~ ^[0-9]+$ ]] || return
  if [[ -f $PROFILE/history ]] && awk -F '\t' -v s="$sender" -v m="$mid" '$2=="received" && $3==s && $6==m {found=1} END{exit !found}' "$PROFILE/history"; then
    ack_mailbox "$mbid"
    return
  fi
  read -r known_enc known_sig < <(awk -v u="$sender" '$1==u {print $2, $3; exit}' "$PROFILE/contacts" 2>/dev/null || :)
  if [[ ! ${known_enc:-} =~ ^[0-9a-f]{64}$ || ! ${known_sig:-} =~ ^[0-9a-f]{64}$ ]]; then
    printf '\n[untrusted] Held message from %s (not acknowledged). Verify with: trust %s\n' "$sender" "$sender"
    printf '%s\n' "$frame" >> "$PROFILE/held"
    return
  fi
  if plain=$(open_envelope "$env" "$kind" "$sender" "$USERNAME" "$room" "$mid" "$ts" "$known_sig"); then
    save_history received "$sender" "$kind" "$room" "$ts" "$mid" "$plain"
    if [[ $kind == room ]]; then
      printf '\n[room:%s] %s: ' "$room" "$sender"
    else
      printf '\n[%s] %s: ' "$sender" "$sender"
    fi
    printf '%s' "$plain" | cat -v
    echo
  else
    echo "[warning] could not verify/decrypt message from $sender; discarding" >&2
  fi
  ack_mailbox "$mbid"
}

process_event() {
  local frame=$1 mbid kind room user by
  mbid=$(json_number mbid "$frame")
  kind=$(json_field kind "$frame")
  room=$(json_field room "$frame")
  user=$(json_field user "$frame")
  by=$(json_field by "$frame")
  printf '\n[event] %s: %s in %s (by %s)\n' "$kind" "$user" "$room" "$by"
  [[ $mbid =~ ^[0-9]+$ ]] && ack_mailbox "$mbid"
}

handle_push() {
  local frame=$1 type code
  type=$(json_field t "$frame")
  case $type in
    msg) process_message "$frame" ;;
    event) process_event "$frame" ;;
    err)
      code=$(json_field code "$frame")
      if [[ $code == kicked ]]; then die "this account was logged in from another session"; fi
      printf '\n[server error] %s\n' "$frame" >&2 ;;
    *) : ;;
  esac
}

request() {
  local command=$1 fields=${2:-} frame id response_type
  ((NEXT_ID++))
  id=$NEXT_ID
  if [[ -n $fields ]]; then
    printf '{"t":"%s","id":%s,%s}\n' "$command" "$id" "$fields" >&4 \
      || { LAST_ERROR="connection lost"; return 1; }
  else
    printf '{"t":"%s","id":%s}\n' "$command" "$id" >&4 \
      || { LAST_ERROR="connection lost"; return 1; }
  fi
  while read_frame 90; do
    frame=$FRAME
    response_type=$(json_field t "$frame")
    if [[ $(json_id "$frame") == "$id" ]]; then
      LAST_FRAME=$frame
      if [[ $response_type == err ]]; then
        LAST_ERROR="$(json_field code "$frame"): $(json_field msg "$frame")"
        return 1
      fi
      LAST_ERROR=""
      LAST_REPLY=$frame
      return 0
    fi
    case $response_type in
      msg|event) handle_push "$frame" ;;
      err)
        [[ $(json_field code "$frame") == kicked ]] && die "this account was logged in from another session"
        ;;
      *) : ;;
    esac
  done
  LAST_ERROR="server disconnected or timed out"
  return 1
}

load_account() {
  local action answer password password2 auth_salt blob_salt auth_key blob_key
  local blob_enc_key blob_mac_key enc sig blob response invite_value
  [[ -n $USERNAME ]] || { read -r -p "Username: " USERNAME || die "no input"; }
  USERNAME=${USERNAME,,}
  valid_user "$USERNAME" || die "username must be 1-32 letters, digits, _ or -"
  PROFILE=$DATA_DIR/$USERNAME
  mkdir -p "$PROFILE" || die "could not create account directory"
  chmod 700 "$PROFILE" 2>/dev/null || :
  read -r -p "Log in or register? [l/r] " action || die "no input"
  read -r -s -p "Password: " password || die "no input"
  echo
  auth_salt=$(printf 'e2echat-auth|%s' "$USERNAME" | sha256_stdin | cut -c1-16)
  blob_salt=$(printf 'e2echat-blob|%s' "$USERNAME" | sha256_stdin | cut -c1-16)
  auth_key=$(CHAT_PW=$password openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 \
    -pass env:CHAT_PW -S "$auth_salt" -P 2>/dev/null | sed -n 's/^key=//p' | tr 'A-F' 'a-f')
  blob_key=$(CHAT_PW=$password openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 \
    -pass env:CHAT_PW -S "$blob_salt" -P 2>/dev/null | sed -n 's/^key=//p' | tr 'A-F' 'a-f')
  [[ $auth_key =~ ^[0-9a-f]{64}$ && $blob_key =~ ^[0-9a-f]{64}$ ]] || die "password key derivation failed"
  blob_enc_key=$(printf '%s|identity-encryption' "$blob_key" | sha256_stdin)
  blob_mac_key=$(printf '%s|identity-authentication' "$blob_key" | sha256_stdin)
  if [[ $action == [rR]* ]]; then
    read -r -s -p "Repeat password: " password2 || die "no input"
    echo
    [[ $password == "$password2" ]] || die "passwords do not match"
    (( ${#password} >= 8 )) || die "password must be at least 8 characters"
    unset password
    unset password2
    openssl genpkey -algorithm X25519 -out "$T/enc.pem" 2>/dev/null || die "X25519 key generation failed"
    openssl genpkey -algorithm Ed25519 -out "$T/sig.pem" 2>/dev/null || die "Ed25519 key generation failed"
    enc=$(raw_pub "$T/enc.pem")
    sig=$(raw_pub "$T/sig.pem")
    printf 'enc\n' > "$T/private"
    cat "$T/enc.pem" >> "$T/private"
    printf '\nsig\n' >> "$T/private"
    cat "$T/sig.pem" >> "$T/private"
    local iv
    iv=$(openssl rand -hex 16)
    openssl enc -aes-256-cbc -K "$blob_enc_key" -iv "$iv" -in "$T/private" -out "$T/private.enc" 2>/dev/null \
      || die "could not encrypt identity"
    local blob_mac
    { hex_bin "$iv"; cat "$T/private.enc"; } > "$T/blob.auth"
    blob_mac=$(hmac_file "$T/blob.auth" "$blob_mac_key")
    { cat "$T/blob.auth"; hex_bin "$blob_mac"; } > "$T/blob"
    blob=$(base64 < "$T/blob" | tr -d '\r\n')
    local fields
    fields="\"user\":\"$USERNAME\",\"auth\":\"$auth_key\",\"enc\":\"$enc\",\"sig\":\"$sig\",\"blob\":\"$blob\""
    if [[ $NEEDS_INVITE == true ]]; then
      read -r -p "Invite code: " invite_value || die "no input"
      fields+=",\"invite\":\"$(json_string "$invite_value")\""
    fi
    request register "$fields" || die "$LAST_ERROR"
    echo "Registered and logged in as $USERNAME."
  elif [[ $action == [lL]* ]]; then
    unset password
    request login "\"user\":\"$USERNAME\",\"auth\":\"$auth_key\"" || die "$LAST_ERROR"
    response=$LAST_REPLY
    blob=$(json_field blob "$response")
    enc=$(json_field enc "$response")
    sig=$(json_field sig "$response")
    printf '%s' "$blob" | base64 -d > "$T/blob" 2>/dev/null || die "server returned invalid identity blob"
    local blob_size received_mac expected_mac
    blob_size=$(wc -c < "$T/blob")
    (( blob_size >= 64 )) || die "identity blob is truncated"
    dd if="$T/blob" of="$T/blob.auth" bs=1 count=$((blob_size-32)) 2>/dev/null
    dd if="$T/blob" of="$T/received-mac" bs=1 skip=$((blob_size-32)) count=32 2>/dev/null
    received_mac=$(od -An -tx1 "$T/received-mac" | tr -d ' \n')
    expected_mac=$(hmac_file "$T/blob.auth" "$blob_mac_key")
    [[ $received_mac == "$expected_mac" ]] || die "password did not unlock the stored identity"
    dd if="$T/blob.auth" of="$T/blob.iv" bs=1 count=16 2>/dev/null
    dd if="$T/blob.auth" of="$T/private.enc" bs=1 skip=16 2>/dev/null
    iv=$(od -An -tx1 "$T/blob.iv" | tr -d ' \n')
    openssl enc -d -aes-256-cbc -K "$blob_enc_key" -iv "$iv" -in "$T/private.enc" -out "$T/private" 2>/dev/null \
      || die "could not decrypt identity"
    awk 'BEGIN{s=0} /^enc$/{s=1;next} /^sig$/{s=2;next} s==1{print > e} s==2{print > g}' \
      e="$T/enc.pem" g="$T/sig.pem" "$T/private"
    [[ $(raw_pub "$T/enc.pem") == "$enc" && $(raw_pub "$T/sig.pem") == "$sig" ]] \
      || die "identity keys do not match the account"
    echo "Logged in as $USERNAME."
  else
    die "choose l to log in or r to register"
  fi
  ENC_KEYFILE=$T/enc.pem
  SIGN_KEY=$T/sig.pem
  MY_ENC=$(raw_pub "$ENC_KEYFILE")
}

load_account

send_dm() {
  local user=${1,,} text=$2 enc response mid ts env
  valid_user "$user" || { echo "invalid username"; return 1; }
  contact_keys "$user" || return 1
  enc=$CONTACT_ENC
  mid=$(openssl rand -hex 16) || return 1
  ts=$(date +%s)
  env=$(make_envelope dm "$USERNAME" "$user" "" "$mid" "$ts" "$text" "$enc") || return 1
  (( ${#env} <= 65536 )) || { echo "message is too long"; return 1; }
  request send "\"to\":\"$user\",\"mid\":\"$mid\",\"ts\":$ts,\"env\":\"$env\"" \
    || { echo "$LAST_ERROR"; return 1; }
  save_history sent "$user" dm "" "$ts" "$mid" "$text"
  echo "Queued for $user (queued does not mean delivered or read)."
}

room_members() {
  local room=$1 response
  request room_info "\"room\":\"$room\"" || { echo "$LAST_ERROR"; return 1; }
  response=$LAST_REPLY
  LAST_ROOM_INFO=$response
}

send_room() {
  local room=${1,,} text=$2 response version mid ts member user enc sig envs="" first=1
  valid_user "$room" || { echo "invalid room name"; return 1; }
  local attempt
  for attempt in 1 2 3; do
    room_members "$room" || return 1
    response=$LAST_ROOM_INFO
    version=$(json_number version "$response")
    [[ $version =~ ^[0-9]+$ ]] || { echo "invalid room information"; return 1; }
    mid=$(openssl rand -hex 16)
    ts=$(date +%s)
    printf '%s' "$response" | sed 's/},{/}\n{/g' | grep '"user"' > "$T/members"
    while IFS= read -r member; do
      user=$(json_field user "$member")
      [[ $user == "$USERNAME" ]] && continue
      enc=$(json_field enc "$member")
      sig=$(json_field sig "$member")
      [[ $enc =~ ^[0-9a-f]{64}$ && $sig =~ ^[0-9a-f]{64}$ ]] || { echo "invalid room member keys"; return 1; }
      if ! known=$(awk -v u="$user" '$1==u {print $2, $3; exit}' "$PROFILE/contacts"); then known=""; fi
      local old_enc old_sig
      read -r old_enc old_sig <<<"$known"
      if [[ $old_enc != "$enc" || $old_sig != "$sig" ]]; then
        echo "Trust each room member first with: trust USER"
        return 1
      fi
      env=$(make_envelope room "$USERNAME" "$user" "$room" "$mid" "$ts" "$text" "$enc") || return 1
      (( first )) || envs+=','
      envs+="\"$user\":\"$env\""
      first=0
    done < "$T/members"
    if request room_send "\"room\":\"$room\",\"version\":$version,\"mid\":\"$mid\",\"ts\":$ts,\"envs\":{$envs}"; then
      save_history sent "$room" room "$room" "$ts" "$mid" "$text"
      echo "Queued room message for $room."
      return 0
    fi
    [[ $LAST_ERROR == stale:* && $attempt -lt 3 ]] || { echo "$LAST_ERROR"; return 1; }
  done
  echo "Room membership kept changing; retry."
}

history() {
  local target=${1:-}
  [[ -f $PROFILE/history ]] || { echo "No saved messages."; return; }
  awk -F '\t' -v u="${target,,}" '
    u=="" || ($3==u) || ($4=="room" && u=="room:"$5) {
      cmd="printf %s "$7" | base64 -d"
      cmd | getline text
      close(cmd)
      when=strftime("%Y-%m-%d %H:%M:%S",$1)
      who=($2=="sent" ? "you" : $3)
      label=($4=="room" ? "room:"$5 : $3)
      printf "%s [%s] %s: %s\n",when,label,who,text
    }' "$PROFILE/history" | cat -v
}

run_command() {
  local input=$1 command rest user room reply
  command=${input%% *}
  rest=${input#"$command"}
  rest=${rest# }
  case ${command,,} in
    "") ;;
    quit|exit) EXIT_REQUESTED=1 ;;
    help)
      echo "dm USER MESSAGE | history [USER|room:ROOM] | trust USER | untrust USER"
      echo "rooms | room-create NAME | room-add NAME USER | room-kick NAME USER"
      echo "room-leave NAME | room-info NAME | room-send NAME MESSAGE | quit" ;;
    dm|room-send)
      user=${rest%% *}
      [[ $rest == *' '* ]] || { echo "usage: $command USER MESSAGE"; return; }
      local text=${rest#* }
      if [[ ${command,,} == dm ]]; then send_dm "$user" "$text"; else send_room "$user" "$text"; fi ;;
    history) history "$rest" ;;
    trust)
      user=${rest,,}
      if contact_keys "$user"; then
        echo "Trusted $user."
        if [[ -f $PROFILE/held ]]; then
          : > "$T/held"
          while IFS= read -r reply; do
            if [[ $(json_field from "$reply") == "$user" ]]; then
              process_message "$reply"
            else
              printf '%s\n' "$reply" >> "$T/held"
            fi
          done < "$PROFILE/held"
          mv "$T/held" "$PROFILE/held"
        fi
      fi ;;
    untrust)
      user=${rest,,}
      [[ -f $PROFILE/contacts ]] && awk -v u="$user" '$1!=u' "$PROFILE/contacts" > "$T/contacts"
      [[ -f $T/contacts ]] && mv "$T/contacts" "$PROFILE/contacts" || : > "$PROFILE/contacts"
      echo "Removed trust for $user; verify any replacement key out of band." ;;
    rooms)
      request rooms || { echo "$LAST_ERROR"; return; }
      reply=$LAST_REPLY
      printf '%s\n' "$reply" | sed 's/},{/}\n{/g' | grep '"room"' |
        sed -E 's/.*"room":"([^"]+)".*"admin":"([^"]+)".*"version":([0-9]+).*/\1 (admin \2, version \3)/' ;;
    room-create)
      room=${rest,,}; valid_user "$room" || { echo "invalid room name"; return; }
      request room_create "\"room\":\"$room\"" && echo "Created $room." || echo "$LAST_ERROR" ;;
    room-add|room-kick)
      read -r room user <<<"$rest"; room=${room,,}; user=${user,,}
      valid_user "$room" && valid_user "$user" || { echo "usage: $command ROOM USER"; return; }
      local action
      [[ ${command,,} == room-add ]] && action=room_add || action=room_kick
      request "$action" "\"room\":\"$room\",\"user\":\"$user\"" && echo "Updated $room." || echo "$LAST_ERROR" ;;
    room-leave|room-info)
      room=${rest,,}; valid_user "$room" || { echo "invalid room name"; return; }
      if [[ ${command,,} == room-leave ]]; then
        request room_leave "\"room\":\"$room\"" && echo "Left $room." || echo "$LAST_ERROR"
      else
        room_members "$room" || return
        printf '%s\n' "$LAST_ROOM_INFO" | sed 's/},{/}\n{/g' | grep '"user"' |
          sed -E 's/.*"user":"([^"]+)".*"enc":"([^"]+)".*"sig":"([^"]+)".*/\1: \2 \3/'
      fi ;;
    *) echo "unknown command: $command (type help)" ;;
  esac
}

EXIT_REQUESTED=0
LAST_PING=$(date +%s)
PENDING_INPUT=""
echo "Connected as $USERNAME. Type help for commands."
while (( ! EXIT_REQUESTED )); do
  now=$(date +%s)
  if (( now - LAST_PING >= 60 )); then
    request ping || die "$LAST_ERROR"
    LAST_PING=$now
  fi
  # Read pushes while waiting at the prompt so offline-delivered mail is handled.
  if read_frame 0.2; then
    handle_push "$FRAME"
    continue
  elif (( READ_STATUS <= 128 )); then
    die "server disconnected"
  fi
  INPUT=""
  if read -r -e -i "$PENDING_INPUT" -t 1 -p "chat> " INPUT; then
    PENDING_INPUT=""
    run_command "$INPUT"
  else
    PENDING_INPUT=${INPUT:-$PENDING_INPUT}
  fi
done
echo "Bye."
