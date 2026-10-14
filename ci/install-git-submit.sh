#!/usr/bin/env bash
#
# Install the `git submit` subcommand.
#
# Modelled on heyo/cicd/install-git-submit.sh, whose `git submit` this
# repository's CI replaces. Same two sources as that one:
#
#   local   copy bin/git-submit from this checkout
#   remote  download from the release channel and verify its SHA-256
#
# Defaults to `local` when run from a checkout that has the script, `remote`
# otherwise — which is what makes `curl … | bash` work.
#
# The public copy of this script, and the release channel it reads, are served
# from heyo.computer; `ci/publish-git-submit.sh` writes both into the marketing
# site. No credential is involved anywhere: the client is a public script.
#
#   curl -fsSL https://heyo.computer/git-submit/install.sh | bash
#   ./install-git-submit.sh
#   GIT_SUBMIT_INSTALL_DIR=~/bin ./install-git-submit.sh
#   GIT_SUBMIT_INSTALL_SOURCE=remote ./install-git-submit.sh
set -euo pipefail

install_dir="${GIT_SUBMIT_INSTALL_DIR:-$HOME/.local/bin}"
target="$install_dir/git-submit"
base_url="${GIT_SUBMIT_INSTALL_BASE_URL:-https://heyo.computer/git-submit}"

# Piped into bash, `BASH_SOURCE[0]` is unset or `-`, so there is no checkout to
# copy from and remote is the only possible source.
default_source="auto"
if [ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]:-}" = "-" ]; then
  default_source="remote"
fi
source_mode="${GIT_SUBMIT_INSTALL_SOURCE:-$default_source}"

local_script=""
if [ "$default_source" != "remote" ]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  [ -f "$here/bin/git-submit" ] && local_script="$here/bin/git-submit"
fi

version_of() {
  [ -f "$1" ] || { echo "not installed"; return 0; }
  sed -n 's/^GIT_SUBMIT_VERSION="\([^"]*\)".*/\1/p' "$1" | head -1 || echo unknown
}

download() {
  local dest="$1"
  command -v curl >/dev/null 2>&1 || {
    echo "Error: curl is required to install from ${base_url}" >&2; exit 1; }

  local version
  version="$(curl --fail --show-error --silent --location "${base_url%/}/latest/version.txt" | tr -d '[:space:]')"
  [ -n "$version" ] || { echo "Error: no version manifest at ${base_url}" >&2; exit 1; }

  echo "Downloading git-submit $version"
  curl --fail --show-error --silent --location "${base_url%/}/latest/git-submit" --output "$dest"

  # Verified, not trusted. This script is also the thing people pipe into bash,
  # so the one artifact it fetches has to be checked.
  local expected actual
  expected="$(curl --fail --show-error --silent --location "${base_url%/}/latest/sha256.txt" | awk '{print $1}')"
  if [ -n "$expected" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum "$dest" | awk '{print $1}')"
    else
      actual="$(shasum -a 256 "$dest" | awk '{print $1}')"
    fi
    [ "$expected" = "$actual" ] || {
      echo "Error: checksum mismatch for git-submit" >&2
      echo "  expected $expected" >&2
      echo "  actual   $actual" >&2
      rm -f "$dest"; exit 1; }
  else
    echo "Warning: no published checksum; installing unverified" >&2
  fi
}

mkdir -p "$install_dir"
tmp="$(mktemp "${TMPDIR:-/tmp}/git-submit.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

case "$source_mode" in
  local)
    [ -n "$local_script" ] || { echo "Error: no bin/git-submit beside this script" >&2; exit 1; }
    cp "$local_script" "$tmp" ;;
  remote)
    download "$tmp" ;;
  auto)
    if [ -n "$local_script" ]; then cp "$local_script" "$tmp"; else download "$tmp"; fi ;;
  *)
    echo "Error: GIT_SUBMIT_INSTALL_SOURCE must be local, remote or auto" >&2; exit 1 ;;
esac

was="$(version_of "$target")"
install -m 0755 "$tmp" "$target"
now="$(version_of "$target")"

echo "Installed git-submit $now (was $was) to $target"

# This client used to install as `git-ci`. It is one script that names itself
# after however it was invoked, so refreshing an existing `git-ci` in place keeps
# `git ci` working — and keeps it from being an old build that talks to this
# server with a credential it no longer needs.
if [ -e "$install_dir/git-ci" ]; then
  install -m 0755 "$tmp" "$install_dir/git-ci"
  echo "Refreshed $install_dir/git-ci too, so \`git ci\` keeps working (same script)."
fi

case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo
     echo "$install_dir is not on your PATH. Add it, then \`git submit\` will work:"
     echo "  export PATH=\"$install_dir:\$PATH\"" ;;
esac

cat <<'EOF'

Register the repository on your CI's /repos page, then paste the two lines it
gives you:

  git config ci.endpoint https://ci.example.com
  git config ci.token    <the token it minted>

The token is scoped to that one repository and can be revoked on its own. An
installation that has not registered anything yet signs with the shared secret
instead:

  git config ci.secret <the server's CI_WEBHOOK_SECRET>

Then, from a repository with .ci/workflows/*.yml:

  git submit --dry-run    # see what would be sent
  git submit              # submit HEAD
  git submit --dirty      # include uncommitted tracked changes
EOF
