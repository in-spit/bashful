#!/usr/bin/env bash
# Requires: bash 4+, openssl 1.1.1+ (X25519), nc or ncat (listening side only)

set -u
umask 077

die()   { echo "error: $*" >&2; exit 1; }
usage() {
  cat >&2 <<'EOF'
Usage:
  ./chat.sh [-u USER]                       open the menu
  ./chat.sh [-u USER] listen  [PORT]        wait for a peer
  ./chat.sh [-u USER] connect HOST [PORT]   connect to a listening peer
EOF
  exit 1
}

USERNAME=""
if [[ ${1:-} == -u ]]; then (( $# >= 2 )) || usage; USERNAME=$2; shift 2; fi
MODE=${1:-}
PORT=${CHAT_PORT:-47555}
HOST=""
case $MODE in
  "")      ;;
  listen)  PORT=${2:-$PORT} ;;
  connect) HOST=${2:-}; PORT=${3:-$PORT}; [[ -n $HOST ]] || usage ;;
  *)       usage ;;
esac
[[ $PORT =~ ^[0-9]+$ ]] || die "bad port: $PORT"
(( BASH_VERSINFO[0] >= 4 )) || die "bash 4+ required (macOS: brew install bash)"
command -v openssl >/dev/null 2>&1 || die "openssl not found"
CHAT_HOME=${CHAT_HOME:-$HOME/.e2e-chat}

T=$(mktemp -d) || die "mktemp failed"
CPID="" RECV_PID=""
MAIN_PID=$$
cleanup() {
  trap - EXIT INT TERM
  [[ -t 0 ]] && stty echo 2>/dev/null
  [[ -t 1 ]] && printf '\033[?25h'
  [[ -n $RECV_PID ]] && kill "$RECV_PID" 2>/dev/null
  [[ -n $CPID ]] && kill "$CPID" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT
trap 'echo; exit 0' INT TERM
trap '' PIPE

sha256hex() { openssl dgst -sha256 -hex | sed 's/^.*= *//'; }

fingerprint() { printf '%s' "$1" | sha256hex | cut -c1-24 | sed 's/\(....\)/\1 /g; s/ $//'; }

pub_hex() { openssl pkey -pubout -outform DER 2>/dev/null <<<"$1" | tail -c 32 | od -An -tx1 | tr -d ' \n'; }

dh() {
  printf '%b' "$(printf '302a300506032b656e032100%s' "$2" | sed 's/../\\x&/g')" > "$T/peer.der"
  openssl pkeyutl -derive -inkey <(printf '%s\n' "$1") -peerkey "$T/peer.der" -peerform DER 2>/dev/null \
    | od -An -tx1 | tr -d ' \n'
}

kdf() { printf '%s|%s|%s' "$SHARED" "$1" "$TRANSCRIPT" | sha256hex; }

make_pads() {
  local key=$1 i b h
  IPAD="" OPAD=""
  for ((i = 0; i < 64; i++)); do
    if ((i < 32)); then b=$((16#${key:2*i:2})); else b=0; fi
    printf -v h '\\x%02x' $((b ^ 0x36)); IPAD+=$h
    printf -v h '\\x%02x' $((b ^ 0x5c)); OPAD+=$h
  done
}

hmac() {
  { printf "$1"; cat; } | openssl dgst -sha256 -binary \
    | { printf "$2"; cat; } | openssl dgst -sha256 -hex | sed 's/^.*= *//'
}

encrypt() {
  printf '%s' "$1" | KEY="$S_ENC" \
    openssl enc -aes-256-cbc -pbkdf2 -iter 1 -md sha256 -pass env:KEY -a -A 2>/dev/null
}

decrypt() {
  printf '%s' "$1" | KEY="$R_ENC" \
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 1 -md sha256 -pass env:KEY -a -A 2>/dev/null
}

prompt_secret() {
  local _v
  IFS= read -r -s -p "$1" _v || die "no input"
  [[ -t 0 ]] && echo >&2
  printf -v "$2" '%s' "$_v"
}

login() {
  local ans tries PW PW2
  if [[ -z $USERNAME ]]; then
    IFS= read -r -p "Username: " USERNAME || die "no input"
  fi
  [[ $USERNAME =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die "username must be 1-32 characters: letters, digits, _ or -"
  PROFILE=$CHAT_HOME/$USERNAME
  KEYFILE=$PROFILE/identity.pem
  CONTACTS=$PROFILE/contacts
  MY_STATIC_PEM=""

  if [[ -f $KEYFILE ]]; then
    for tries in 1 2 3; do
      prompt_secret "Password for $USERNAME: " PW
      MY_STATIC_PEM=$(CHAT_PW=$PW openssl pkey -in "$KEYFILE" -passin env:CHAT_PW 2>/dev/null) && break
      MY_STATIC_PEM=""
      echo "Wrong password." >&2
    done
    [[ -n $MY_STATIC_PEM ]] || die "login failed"
    echo "Logged in as $USERNAME."
  else
    IFS= read -r -p "No account '$USERNAME' on this machine. Create it? [y/N] " ans || die "no input"
    [[ $ans == [yY]* ]] || die "cancelled"
    prompt_secret "Choose a password (min 8 characters): " PW
    (( ${#PW} >= 8 )) || die "password too short"
    prompt_secret "Repeat password: " PW2
    [[ $PW == "$PW2" ]] || die "passwords don't match"
    mkdir -p "$PROFILE" || die "cannot create $PROFILE"
    openssl genpkey -algorithm X25519 2>/dev/null \
      | CHAT_PW=$PW openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000 \
          -passout env:CHAT_PW -out "$KEYFILE" 2>/dev/null \
      || die "could not create identity (does your openssl support X25519?)"
    MY_STATIC_PEM=$(CHAT_PW=$PW openssl pkey -in "$KEYFILE" -passin env:CHAT_PW 2>/dev/null) \
      || die "could not read back the new identity"
    echo "Account created. Your identity is stored (encrypted) in $KEYFILE"
    echo "There is no password recovery: forget the password and that identity is gone."
  fi
  MYSTAT=$(pub_hex "$MY_STATIC_PEM")
  [[ $MYSTAT =~ ^[0-9a-f]{64}$ ]] || die "could not read your identity key"
  echo "Your identity fingerprint: $(fingerprint "$MYSTAT")"
  echo "(Share it with contacts over another channel so they can verify you.)"
  echo
}

check_contact() {
  local u k known="" ans
  if [[ -f $CONTACTS ]]; then
    while read -r u k; do
      [[ $u == "$1" ]] && { known=$k; break; }
    done < "$CONTACTS"
  fi
  if [[ -z $known ]]; then
    echo "First contact with '$1'."
    echo "Their identity fingerprint: $(fingerprint "$2")"
    echo "Verify it with them over another channel (call, in person) before trusting."
    IFS= read -r -p "Trust this identity? [y/N] " ans || die "no input"
    [[ $ans == [yY]* ]] || die "identity not trusted, disconnecting"
    printf '%s %s\n' "$1" "$2" >> "$CONTACTS"
    echo "Saved '$1' as a trusted contact."
  elif [[ $known != "$2" ]]; then
    {
      echo "!!! WARNING: the identity key of '$1' has CHANGED !!!"
      echo "    saved:   $(fingerprint "$known")"
      echo "    offered: $(fingerprint "$2")"
      echo "Either they re-created their account, or someone is impersonating them."
      echo "If you verified the new key with them, delete their line from"
      echo "$CONTACTS and reconnect."
    } >&2
    die "refusing to continue"
  else
    echo "Known contact: '$1' ($(fingerprint "$2"))"
  fi
}

local_ip() {
  local addr
  addr=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
  [[ -n $addr ]] || addr=$(hostname -I 2>/dev/null | awk '{print $1}')
  [[ -n $addr ]] || addr=$(ifconfig 2>/dev/null | sed -n 's/.*inet \(addr:\)\{0,1\}\([0-9][0-9.]*\).*/\2/p' | grep -v '^127\.' | head -1)
  [[ -n $addr ]] || addr=$(ipconfig 2>/dev/null | tr -d '\r' | sed -n 's/.*IPv4[^:]*: *\([0-9.]*\).*/\1/p' | head -1)
  printf '%s' "$addr"
}

scan() {
  local me base i ip pids=() targets=(127.0.0.1)
  FOUND=()
  : > "$T/found"
  me=$(local_ip)
  if [[ $me =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
    base=${BASH_REMATCH[1]}
    for i in {1..254}; do
      [[ $base.$i == "$me" ]] || targets+=("$base.$i")
    done
  fi
  for ip in "${targets[@]}"; do
    { exec 5<>"/dev/tcp/$ip/$PORT" && echo "$ip" >> "$T/found"; } 2>/dev/null &
    pids+=($!)
  done
  sleep 1.2
  kill "${pids[@]}" 2>/dev/null
  wait 2>/dev/null
  mapfile -t FOUND < <(sort -t. -k1,1n -k2,2n -k3,3n -k4,4n "$T/found")
}

menu() {
  local n=$# sel=0 i key rest
  local items=("$@")
  printf '\033[?25l'
  while :; do
    for ((i = 0; i < n; i++)); do
      if ((i == sel)); then
        printf '\033[7m > %s \033[0m\033[K\n' "${items[i]}"
      else
        printf '   %s\033[K\n' "${items[i]}"
      fi
    done
    IFS= read -rsn1 key || { MENU_CHOICE=-1; break; }
    if [[ $key == $'\033' ]]; then
      IFS= read -rsn2 -t 0.1 rest
      key=$rest
    fi
    case $key in
      '[A'|OA|k) sel=$(( (sel + n - 1) % n )) ;;
      '[B'|OB|j) sel=$(( (sel + 1) % n )) ;;
      '')        MENU_CHOICE=$sel; break ;;
      q)         MENU_CHOICE=-1; break ;;
    esac
    printf '\033[%dA' "$n"
  done
  printf '\033[%dA\033[J\033[?25h' "$n"
}

connect_to() {
  local i
  for i in 1 2 3 4 5 6 7 8; do
    { exec 3<>"/dev/tcp/$HOST/$PORT"; } 2>/dev/null && return 0
    sleep 0.4
  done
  return 1
}

select_mode() {
  local items actions i
  while :; do
    printf 'Scanning the local network...'
    scan
    printf '\r\033[K'
    items=("Listen for Connection")
    actions=(listen)
    if (( ${#FOUND[@]} )); then
      for i in "${!FOUND[@]}"; do
        items+=("${FOUND[i]} | connect")
        actions+=("connect:${FOUND[i]}")
      done
    else
      items+=("connection failed (select to rescan)")
      actions+=(rescan)
    fi
    menu "${items[@]}"
    (( MENU_CHOICE >= 0 )) || exit 0
    case ${actions[MENU_CHOICE]} in
      listen)
        MODE=listen
        return ;;
      connect:*)
        HOST=${actions[MENU_CHOICE]#connect:}
        MODE=connect
        if connect_to; then CONNECTED=1; return; fi
        echo "connection failed"
        sleep 1 ;;
    esac
  done
}

login

EPH_PEM=$(openssl genpkey -algorithm X25519 2>/dev/null) || die "openssl can't do X25519 (need 1.1.1+)"
MYEPH=$(pub_hex "$EPH_PEM")
[[ $MYEPH =~ ^[0-9a-f]{64}$ ]] || die "could not create session key"
HELLO_LINE="HELLO $USERNAME $MYSTAT $MYEPH"

CONNECTED=""
[[ -n $MODE ]] || select_mode

if [[ $MODE == listen ]]; then
  if command -v ncat >/dev/null 2>&1; then
    LISTEN=(ncat -l "$PORT")
  elif command -v nc >/dev/null 2>&1; then
    if nc -h 2>&1 | grep -qiE 'v1\.10|GNU netcat'; then
      LISTEN=(nc -l -p "$PORT")
    else
      LISTEN=(nc -l "$PORT")
    fi
  else
    die "need nc or ncat to listen"
  fi
  if { exec 6<>"/dev/tcp/127.0.0.1/$PORT"; } 2>/dev/null; then
    exec 6>&-
    die "port $PORT is already in use"
  fi
  me=$(local_ip)
  echo "Listening on port $PORT${me:+ (your address: $me)}, waiting for a peer..."
  tries=0
  while :; do
    (( ++tries > 200 )) && die "the listener keeps failing, giving up"
    coproc NC { exec "${LISTEN[@]}"; }
    CPID=$NC_PID
    exec 3<&"${NC[0]}" 4>&"${NC[1]}" || die "could not start the listener"
    echo "$HELLO_LINE" >&4
    IFS= read -r -t 600 -n 300 line <&3 && break
    (( $? > 128 )) && die "timed out waiting for a peer"
    exec 3<&- 4>&-
    wait "$CPID" 2>/dev/null
  done
  IN=3 OUT=4
else
  [[ -n $CONNECTED ]] || connect_to || die "could not connect to $HOST:$PORT"
  IN=3 OUT=3
  echo "$HELLO_LINE" >&3 || die "could not send handshake"
  IFS= read -r -t 30 -n 300 line <&3 \
    || die "no handshake from peer (connection failed or timed out)"
fi

read -r hello PEER PEERSTAT PEEREPH extra <<<"$line"
[[ $hello == HELLO && $PEER =~ ^[A-Za-z0-9_-]{1,32}$ \
   && $PEERSTAT =~ ^[0-9a-f]{64}$ && $PEEREPH =~ ^[0-9a-f]{64}$ && -z $extra ]] \
  || die "bad handshake from peer"
[[ $PEEREPH != "$MYEPH" ]] || die "peer sent our session key back (reflection), aborting"

check_contact "$PEER" "$PEERSTAT"

EE=$(dh "$EPH_PEM" "$PEEREPH")
SS=$(dh "$MY_STATIC_PEM" "$PEERSTAT")
unset EPH_PEM MY_STATIC_PEM
[[ $EE =~ ^[0-9a-f]{64}$ && -n ${EE//0/} && $SS =~ ^[0-9a-f]{64}$ && -n ${SS//0/} ]] \
  || die "key agreement failed"
SHARED="$EE$SS"
unset EE SS

if [[ $MODE == listen ]]; then
  TRANSCRIPT="$USERNAME|$MYSTAT|$MYEPH|$PEER|$PEERSTAT|$PEEREPH"; SEND=L2C RECV=C2L
else
  TRANSCRIPT="$PEER|$PEERSTAT|$PEEREPH|$USERNAME|$MYSTAT|$MYEPH"; SEND=C2L RECV=L2C
fi

S_ENC=$(kdf "enc-$SEND"); S_MAC=$(kdf "mac-$SEND")
R_ENC=$(kdf "enc-$RECV"); R_MAC=$(kdf "mac-$RECV")
make_pads "$S_MAC"; S_IPAD=$IPAD S_OPAD=$OPAD
make_pads "$R_MAC"; R_IPAD=$IPAD R_OPAD=$OPAD
unset SHARED S_MAC R_MAC IPAD OPAD

printf 'AUTH %s\n' "$(printf '%s' "AUTH|$SEND" | hmac "$S_IPAD" "$S_OPAD")" >&"$OUT" \
  || die "could not send key confirmation"
IFS= read -r -t 120 -n 100 line <&"$IN" || die "peer disconnected before completing the handshake"
read -r kind atag extra <<<"$line"
expect=$(printf '%s' "AUTH|$RECV" | hmac "$R_IPAD" "$R_OPAD")
[[ $kind == AUTH && $atag == "$expect" && -z $extra ]] \
  || die "peer could not prove they own the identity '$PEER' (impersonation or tampering), aborting"

show_fp() {
  echo "You  ($USERNAME): $(fingerprint "$MYSTAT")"
  echo "Peer ($PEER): $(fingerprint "$PEERSTAT")"
}
echo
echo "Secure session with $PEER. Messages are end-to-end encrypted and authenticated."
echo "Type a message and press Enter. /fp shows fingerprints, /quit leaves."
echo

PROMPT="you> "

recv_loop() {
  local line kind seq ct tag extra expect plain rseq=0
  while IFS= read -r -n 8192 line <&"$IN"; do
    read -r kind seq ct tag extra <<<"$line"
    if [[ $kind != MSG || ! $seq =~ ^[0-9]{1,9}$ || ! $ct =~ ^[A-Za-z0-9+/=]+$ \
          || ! $tag =~ ^[0-9a-f]{64}$ || -n $extra ]]; then
      printf '\r\033[K[!] ignored a malformed line\n%s' "$PROMPT"; continue
    fi
    expect=$(printf '%s' "$seq|$ct" | hmac "$R_IPAD" "$R_OPAD")
    if [[ $tag != "$expect" ]]; then
      printf '\r\033[K[!] message failed authentication (tampered or forged), ignored\n%s' "$PROMPT"; continue
    fi
    if (( seq != rseq + 1 )); then
      printf '\r\033[K[!] replayed or out-of-order message, ignored\n%s' "$PROMPT"; continue
    fi
    rseq=$seq
    plain=$(decrypt "$ct") || { printf '\r\033[K[!] could not decrypt a message\n%s' "$PROMPT"; continue; }
    plain=${plain//[[:cntrl:]]/}
    printf '\r\033[K%s: %s\n%s' "$PEER" "$plain" "$PROMPT"
  done
  printf '\r\033[K* %s disconnected\n' "$PEER"
  kill -TERM "$MAIN_PID" 2>/dev/null
}
recv_loop &
RECV_PID=$!

seq=0
while IFS= read -r -e -p "$PROMPT" text; do
  [[ -z $text ]] && continue
  case $text in
    /quit) break ;;
    /fp)   show_fp; continue ;;
  esac
  if (( ${#text} > 1000 )); then echo "(message too long, max 1000 characters)"; continue; fi
  ct=$(encrypt "$text")
  tag=$(printf '%s' "$((seq + 1))|$ct" | hmac "$S_IPAD" "$S_OPAD")
  if [[ -z $ct || ${#tag} -ne 64 ]]; then echo "[!] encryption failed, message not sent"; continue; fi
  seq=$((seq + 1))
  printf 'MSG %s %s %s\n' "$seq" "$ct" "$tag" >&"$OUT" || { echo "[!] send failed, connection lost"; break; }
done
echo "Bye."
