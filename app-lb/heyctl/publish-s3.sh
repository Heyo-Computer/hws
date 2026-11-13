#!/bin/sh
# Publish tested heyctl archives to the existing heyvm release bucket.
# Usage: sh publish-s3.sh VERSION DIST_DIR
set -eu
VERSION="${1:?usage: publish-s3.sh VERSION DIST_DIR}"
DIST="${2:?usage: publish-s3.sh VERSION DIST_DIR}"
case "$VERSION" in
    ""|*[!0-9.]*|.*) echo 'expected a stable numeric version' >&2; exit 1 ;;
esac
BUCKET=heyo-cli-releases
BASE="https://$BUCKET.s3.amazonaws.com/heyctl"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}
# A failed put (including a race with another publisher) never overwrites an
# existing release. Retry only after checking that the existing bytes match.
immutable() {
    file="$1"; key="$2"
    if ! aws s3api put-object --bucket "$BUCKET" --key "$key" --body "$file" \
        --if-none-match '*' --cache-control 'public,max-age=31536000,immutable' >/dev/null; then
        aws s3 cp "s3://$BUCKET/$key" "$TMP/existing" --only-show-errors
        [ "$(sha256 "$file")" = "$(sha256 "$TMP/existing")" ] || {
            echo "refusing to replace s3://$BUCKET/$key with different bytes" >&2; exit 1;
        }
    fi
}
for platform in apple-darwin-aarch64 unknown-linux-gnu-x86_64; do
    archive="$DIST/heyctl-$VERSION-$platform.tar.gz"
    [ -s "$archive" ] || { echo "missing $archive" >&2; exit 1; }
    tar -tzf "$archive" | grep -Eq '(^|/)heyctl$' || {
        echo "no heyctl binary in $archive" >&2; exit 1;
    }
done
for platform in apple-darwin-aarch64 unknown-linux-gnu-x86_64; do
    name="heyctl-$VERSION-$platform.tar.gz"
    digest="$(sha256 "$DIST/$name")"
    printf '%s\n' "$digest" > "$TMP/$name.sha256"
    immutable "$DIST/$name" "heyctl/v$VERSION/$name"
    immutable "$TMP/$name.sha256" "heyctl/v$VERSION/$name.sha256"
    curl -fsSL "$BASE/v$VERSION/$name" -o "$TMP/download"
    [ "$(sha256 "$TMP/download")" = "$digest" ]
    curl -fsSL "$BASE/v$VERSION/$name.sha256" -o "$TMP/checksum"
    [ "$(cat "$TMP/checksum")" = "$digest" ]
done
aws s3 cp "$SCRIPT_DIR/install.sh" "s3://$BUCKET/heyctl/install.sh" \
    --content-type text/plain --cache-control no-cache --only-show-errors
curl -fsSL "$BASE/install.sh" -o "$TMP/installer"
cmp "$SCRIPT_DIR/install.sh" "$TMP/installer"
printf '%s\n' "$VERSION" > "$TMP/latest.txt"
aws s3 cp "$TMP/latest.txt" "s3://$BUCKET/heyctl/latest.txt" \
    --content-type text/plain --cache-control no-cache --only-show-errors
echo "Published heyctl $VERSION at $BASE"
