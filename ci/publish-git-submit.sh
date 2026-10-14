#!/usr/bin/env bash
#
# Write the public `git submit` release channel into a static site tree.
#
#   ci/publish-git-submit.sh ~/Projects/marketing/src
#
# heyo.computer serves the result, which is what the one-line install reads:
#
#   curl -fsSL https://heyo.computer/git-submit/install.sh | bash
#
# Layout, under <site>/git-submit/ — the one install-git-submit.sh's `remote`
# source and `git submit --upgrade` already expect:
#
#   install.sh                 this repository's ci/install-git-submit.sh
#   latest/git-submit          ci/bin/git-submit
#   latest/version.txt         its GIT_SUBMIT_VERSION
#   latest/sha256.txt          sha256 of latest/git-submit
#   <version>/git-submit       the same bytes, kept so a version stays fetchable
#   <version>/sha256.txt
#
# Nothing here is secret and nothing is uploaded: the site's own deploy
# publishes the files. Re-running for an unchanged client is a no-op diff.
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <site source dir>" >&2; exit 2; }
site="$1"
[ -d "$site" ] || { echo "Error: $site is not a directory" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
client="$here/bin/git-submit"
installer="$here/install-git-submit.sh"

version="$(sed -n 's/^GIT_SUBMIT_VERSION="\([^"]*\)".*/\1/p' "$client" | head -1)"
[ -n "$version" ] || { echo "Error: no GIT_SUBMIT_VERSION in $client" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# A published version is immutable: the same number with different bytes would
# make the version directory lie about what it holds. Bump GIT_SUBMIT_VERSION.
out="$site/git-submit"
sum="$(sha256_of "$client")"
if [ -f "$out/$version/sha256.txt" ] && [ "$(awk '{print $1}' "$out/$version/sha256.txt")" != "$sum" ]; then
  echo "Error: git-submit $version is already published with different bytes; bump GIT_SUBMIT_VERSION" >&2
  exit 1
fi

for dir in "$out/latest" "$out/$version"; do
  mkdir -p "$dir"
  install -m 0644 "$client" "$dir/git-submit"
  printf '%s  git-submit\n' "$sum" > "$dir/sha256.txt"
done
printf '%s\n' "$version" > "$out/latest/version.txt"
install -m 0644 "$installer" "$out/install.sh"

echo "Published git-submit $version ($sum) into $out"
