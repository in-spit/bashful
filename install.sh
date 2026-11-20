#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
  printf 'Usage: bash install.sh [BIN_DIRECTORY]\n' >&2
  exit 2
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
client="$repo_dir/chat.sh"
[[ -f $client ]] || { printf 'error: chat.sh not found in %s\n' "$repo_dir" >&2; exit 1; }

bin_dir=${1:-"$HOME/.local/bin"}
mkdir -p -- "$bin_dir"
bin_dir=$(cd -- "$bin_dir" && pwd -P)
launcher="$bin_dir/bashful"

if [[ -e $launcher || -L $launcher ]]; then
  if ! grep -Fxq '# Managed by Bashful install.sh' "$launcher"; then
    printf 'error: refusing to replace existing file: %s\n' "$launcher" >&2
    exit 1
  fi
fi

tmp=$(mktemp "$bin_dir/.bashful.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
printf '#!/usr/bin/env bash\n# Managed by Bashful install.sh\nexec bash %q "$@"\n' "$client" > "$tmp"
chmod 755 "$tmp"
mv -f -- "$tmp" "$launcher"
trap - EXIT

printf 'Installed bashful at %s\n' "$launcher"
case ":${PATH}:" in
  *":${bin_dir}:"*)
    printf 'Run it with: bashful\n'
    ;;
  *)
    printf '%s is not currently in PATH. Add it to your shell startup file.\n' "$bin_dir"
    if [[ $bin_dir == "$HOME/.local/bin" ]]; then
      printf '  export PATH="$HOME/.local/bin:$PATH"\n'
    fi
    printf 'Then open a new terminal (or run that command in this one).\n'
    ;;
esac
