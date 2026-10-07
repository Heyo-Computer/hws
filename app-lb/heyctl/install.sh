#!/bin/sh
# heyctl installer — fetches a published `heyctl` binary from the Heyo artifact
# store and installs it into ${HEYCTL_PREFIX}/bin (default ~/.local/bin).
#
#   curl -fsSL https://heyo.computer/heyctl/install.sh | sh
#   curl -fsSL https://heyo.computer/heyctl/install.sh | sh -s -- --prefix /usr/local
#   curl -fsSL https://heyo.computer/heyctl/install.sh | HEYCTL_VERSION=0.2.0 sh
#
# Note the `-s --` when passing flags through a pipe: without it `sh` reads the
# script from stdin and treats the flags as its own.
#
# ## Why this is not `.ci/install.sh`
#
# The internal installer resolves a *tag* in the store to find the newest build,
# and tags need `ART_API_KEY`. This one must work for a stranger with no
# credential of any kind, and the store's anonymous carve-out is exactly one
# route: `GET /blobs/{digest}` for a blob somebody marked public
# (`artifacts/src/http.rs`, `authorize`). No listing, no tags, no manifests.
#
# So the "which build is current" question is answered *off* the store, by a
# small static manifest served from the same site as this script. That is also
# why this script sends no Authorization header and must not learn to: the
# carve-out is anonymous-only, and a *presented* stale key is rejected even for
# a public blob. An `ART_API_KEY` exported in someone's shell would turn a
# working install into a 401.
#
# ## The manifest contract
#
# `${HEYCTL_BASE_URL}/heyctl/versions.json`, a static file the release process
# writes:
#
#   {
#     "latest": "0.1.7",
#     "store": "https://art.us2.heyo.work",
#     "artifacts": [
#       { "version": "0.1.7",
#         "platform": "linux-x86_64",
#         "digest": "<the sha256 of the published tarball>",
#         "bin": "heyctl" }
#     ]
#   }
#
# `artifacts` is a flat array rather than a nested version->platform object on
# purpose: this script has to parse it in POSIX sh on a machine that may have no
# `jq`, and a flat record splits on `{` unambiguously while a nested one needs
# brace counting. `store` lives in the manifest so the store can move without a
# new install.sh on the CDN; `bin` is the file to pull out of the tarball, so a
# future heyctl-only artifact needs no change here either.
#
# Adding a platform is a manifest entry plus a CI target — this script already
# asks for `${OS}-${ARCH}` and reports what the manifest actually offers.
#
# ## What it verifies
#
# A blob's name *is* the sha256 of its bytes, so hashing the download and
# comparing it to the digest it was fetched by is free, and covers the transfer
# and the store in one check. Then, if the tarball carries the build's own
# `SHA256SUMS`, the extracted binary is checked against that too. The manifest
# is the trust root either way, which is why it must be served over HTTPS from
# a host you control.
#
# ## Environment
#
#   HEYCTL_BASE_URL     Site serving the manifest. Default https://heyo.computer
#   HEYCTL_MANIFEST_URL Full manifest URL; overrides HEYCTL_BASE_URL entirely.
#   HEYCTL_STORE_URL    Artifact store base. Default: the manifest's "store".
#   HEYCTL_VERSION      Version to install. Default: the manifest's "latest".
#   HEYCTL_DIGEST       Install this exact blob and skip the manifest entirely.
#                       For a rollback, or for a public link handed to you.
#   HEYCTL_PREFIX       Install prefix. Binaries land in $HEYCTL_PREFIX/bin.
#                       Default $HOME/.local.
#   HEYCTL_NO_VERIFY    If non-empty, skip the SHA256SUMS cross-check. The blob
#                       digest is always verified; that one is not optional.

set -eu

# Everything lives in `main`, called on the last line. A `curl | sh` that is cut
# off mid-transfer feeds `sh` a truncated script, and `sh` executes what it has
# already read — so a flat script can run its first half against a half-finished
# download. With the body in a function nothing runs until the final line has
# arrived, and a truncated file is a syntax error instead of half an install.
main() {

# ---- defaults ---------------------------------------------------------------

BASE_URL="${HEYCTL_BASE_URL:-https://heyo.computer}"
MANIFEST_URL="${HEYCTL_MANIFEST_URL:-}"
STORE_URL="${HEYCTL_STORE_URL:-}"
VERSION="${HEYCTL_VERSION:-}"
DIGEST="${HEYCTL_DIGEST:-}"
PREFIX="${HEYCTL_PREFIX:-$HOME/.local}"

# The store the manifest points at when it names none, and when --digest is used
# without one. Kept in step with .ci/README.md.
DEFAULT_STORE="https://art.us2.heyo.work"

# ---- output -----------------------------------------------------------------

info() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
step() { printf '    %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat >&2 <<'USAGE'
heyctl installer

  curl -fsSL https://heyo.computer/heyctl/install.sh | sh
  curl -fsSL https://heyo.computer/heyctl/install.sh | sh -s -- --prefix /usr/local

Options
  --prefix PATH     Install into PATH/bin (default ~/.local)
  --version VER     Install this version (default: the manifest's "latest")
  --digest SHA256   Install this exact blob, ignoring the manifest
  --list            Show the versions the manifest offers, install nothing
  -h, --help        This

Environment
  HEYCTL_BASE_URL HEYCTL_MANIFEST_URL HEYCTL_STORE_URL
  HEYCTL_VERSION HEYCTL_DIGEST HEYCTL_PREFIX HEYCTL_NO_VERIFY
USAGE
}

# ---- arguments --------------------------------------------------------------

DO_LIST=0
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)  shift; [ $# -gt 0 ] || die "--prefix needs a path";   PREFIX="$1" ;;
        --version) shift; [ $# -gt 0 ] || die "--version needs a value"; VERSION="$1" ;;
        --digest)  shift; [ $# -gt 0 ] || die "--digest needs a sha256"; DIGEST="$1" ;;
        --list)    DO_LIST=1 ;;
        -h|--help) usage; exit 0 ;;
        *)         usage; die "unknown argument: $1" ;;
    esac
    shift
done

if [ "$DO_LIST" = 1 ] && [ -n "$DIGEST" ]; then
    die "--list reads the manifest and --digest skips it; pick one"
fi

BINDIR="$PREFIX/bin"

# ---- prerequisites ----------------------------------------------------------

# `awk` does the manifest parsing, `find` locates the binary inside the
# artifact, and `sort -u` renders the platform list in an error message.
for tool in uname tar awk sed find grep sort tr mktemp; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required but was not found"
done

if command -v curl >/dev/null 2>&1; then
    DOWNLOADER=curl
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER=wget
else
    die "curl or wget is required"
fi

# No credential is ever attached: see the note at the top. `-L` because the site
# may redirect the manifest; the store does not.
#
# A redirect may not downgrade to plaintext. The manifest is this script's trust
# root — the digest everything else is checked against comes out of it — so a
# MITM on the manifest is a MITM on the binary, and silently following
# `https://site` -> `http://anywhere` would hand that away. Constraining
# *redirects* rather than the request itself leaves an `http://` URL somebody
# typed on purpose (a local mirror, a staging site) working.
download() {
    # download <url> <dest>
    if [ "$DOWNLOADER" = curl ]; then
        curl -fsSL --retry 3 --proto-redir '=https' -o "$2" "$1"
    else
        case "$1" in
            https://*) wget -q --https-only -O "$2" "$1" ;;
            *)         wget -q -O "$2" "$1" ;;
        esac
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

# ---- platform ---------------------------------------------------------------

detect_os() {
    case "$(uname -s)" in
        Linux)  echo linux ;;
        Darwin) echo darwin ;;
        *)      die "unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        *)             die "unsupported architecture: $(uname -m)" ;;
    esac
}

PLATFORM="$(detect_os)-$(detect_arch)"

# ---- manifest ---------------------------------------------------------------

# One record per `{...}` in `artifacts`, matched on literal strings rather than
# regexes: `index()` does not treat the dots in a version as wildcards. `want`
# is a field name this script chooses, so a regex is safe there.
manifest_field() {
    # manifest_field <file> <version> <platform> <field>
    awk -v ver="$2" -v plat="$3" -v want="$4" '
        BEGIN { RS = "{" }
        {
            rec = $0
            gsub(/[ \t\r\n]/, "", rec)
            if (index(rec, "\"version\":\"" ver "\"") \
             && index(rec, "\"platform\":\"" plat "\"") \
             && match(rec, "\"" want "\":\"[^\"]*\"")) {
                f = substr(rec, RSTART, RLENGTH)
                sub("^\"" want "\":\"", "", f)
                sub("\"$", "", f)
                print f
                exit
            }
        }
    ' "$1"
}

# Every version the manifest carries for this platform, newest last is not
# knowable here — the order is whatever the file says, which is the release
# process's business and not this script's.
manifest_versions_for() {
    # manifest_versions_for <file> <platform>
    awk -v plat="$2" '
        BEGIN { RS = "{" }
        {
            rec = $0
            gsub(/[ \t\r\n]/, "", rec)
            if (index(rec, "\"platform\":\"" plat "\"") \
             && match(rec, "\"version\":\"[^\"]*\"")) {
                f = substr(rec, RSTART, RLENGTH)
                sub("^\"version\":\"", "", f)
                sub("\"$", "", f)
                print f
            }
        }
    ' "$1"
}

manifest_platforms() {
    awk '
        BEGIN { RS = "{" }
        {
            rec = $0
            gsub(/[ \t\r\n]/, "", rec)
            if (match(rec, "\"platform\":\"[^\"]*\"")) {
                f = substr(rec, RSTART, RLENGTH)
                sub("^\"platform\":\"", "", f)
                sub("\"$", "", f)
                print f
            }
        }
    ' "$1" | sort -u
}

# Top level, so it cannot be confused with a record: no artifact entry carries
# a `latest` or a `store` key.
manifest_top() {
    # manifest_top <file> <key>
    tr -d ' \t\r\n' < "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p" | head -1
}

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t heyctl-install)"
trap 'rm -rf "$TMP"' EXIT INT TERM

BIN=heyctl

if [ -n "$DIGEST" ]; then
    # The manifest is the thing that says which digest is current; naming one
    # explicitly answers that question, so there is nothing left to fetch.
    case "$DIGEST" in
        *[!0-9a-f]* | "") die "--digest must be 64 lowercase hex characters" ;;
    esac
    [ "${#DIGEST}" -eq 64 ] || die "--digest must be 64 lowercase hex characters"
    [ -n "$STORE_URL" ] || STORE_URL="$DEFAULT_STORE"
    VERSION="${VERSION:-(pinned)}"
    info "installing the blob you named; the manifest is not consulted"
else
    [ -n "$MANIFEST_URL" ] || MANIFEST_URL="${BASE_URL%/}/heyctl/versions.json"
    download "$MANIFEST_URL" "$TMP/versions.json" \
        || die "could not fetch $MANIFEST_URL — is HEYCTL_BASE_URL right?"
    [ -s "$TMP/versions.json" ] || die "$MANIFEST_URL is empty"

    if [ "$DO_LIST" = 1 ]; then
        info "manifest: $MANIFEST_URL"
        step "latest:   $(manifest_top "$TMP/versions.json" latest)"
        step "platforms: $(manifest_platforms "$TMP/versions.json" | tr '\n' ' ')"
        step "versions for $PLATFORM:"
        manifest_versions_for "$TMP/versions.json" "$PLATFORM" \
            | while IFS= read -r v; do printf '      %s\n' "$v" >&2; done
        exit 0
    fi

    if [ -z "$VERSION" ]; then
        VERSION="$(manifest_top "$TMP/versions.json" latest)"
        [ -n "$VERSION" ] || die "$MANIFEST_URL names no \"latest\" version"
    fi

    [ -n "$STORE_URL" ] || STORE_URL="$(manifest_top "$TMP/versions.json" store)"
    [ -n "$STORE_URL" ] || STORE_URL="$DEFAULT_STORE"

    DIGEST="$(manifest_field "$TMP/versions.json" "$VERSION" "$PLATFORM" digest)"
    if [ -z "$DIGEST" ]; then
        # No platforms at all means the file parsed but holds no `artifacts`
        # records — almost always a manifest written in some other shape. Say
        # so, rather than reporting it as "your platform is unsupported" and
        # sending somebody to look at their machine.
        [ -n "$(manifest_platforms "$TMP/versions.json")" ] \
            || die "$MANIFEST_URL has no artifacts[] entries — see the manifest contract at the top of this script"

        # Two different mistakes with two different fixes, so they get two
        # different messages: a platform nobody has built, or a version that
        # does not exist for a platform that does.
        if manifest_platforms "$TMP/versions.json" | grep -qx "$PLATFORM"; then
            die "no heyctl $VERSION for $PLATFORM. Available: $(manifest_versions_for "$TMP/versions.json" "$PLATFORM" | tr '\n' ' ')"
        fi
        die "no heyctl is published for $PLATFORM. The manifest offers: $(manifest_platforms "$TMP/versions.json" | tr '\n' ' ')"
    fi

    # Optional: a manifest that names no `bin` means the default, `heyctl`.
    b="$(manifest_field "$TMP/versions.json" "$VERSION" "$PLATFORM" bin)"
    if [ -n "$b" ]; then BIN="$b"; fi
fi

STORE_URL="${STORE_URL%/}"
BLOB_URL="$STORE_URL/blobs/$DIGEST"

info "heyctl $VERSION  ($PLATFORM)"
step "store:  $BLOB_URL"
step "target: $BINDIR/heyctl"

# ---- fetch and verify -------------------------------------------------------

# Refuse before a multi-megabyte download rather than after it, and name the
# directory rather than letting `mkdir` say "no such file or directory".
#
# The nearest *existing* ancestor is what decides this, not the parent: a
# `--prefix /opt/heyo/tools` two levels below anything that exists has a parent
# that fails `-d`, and checking only the parent would let that sail past the
# guard and land on a raw mkdir error after the download.
probe="$BINDIR"
while [ ! -e "$probe" ] && [ "$probe" != "/" ] && [ "$probe" != "." ]; do
    probe="$(dirname "$probe")"
done
[ -d "$probe" ] || die "$probe is not a directory; --prefix must name one"
[ -w "$probe" ] || die "cannot install into $BINDIR — $probe is not writable (try --prefix ~/.local, or run as root)"

TARBALL="$TMP/heyctl.tar.gz"
step "downloading"
download "$BLOB_URL" "$TARBALL" \
    || die "could not fetch $BLOB_URL — the blob may not be marked public, or the digest is wrong"

ACTUAL="$(sha256_of "$TARBALL")"
if [ -z "$ACTUAL" ]; then
    # Not a warning to shrug at: the digest is the only end-to-end check there
    # is, and without it this script is trusting whatever answered the request.
    die "no sha256sum or shasum on this machine; refusing to install unverified bytes"
fi
[ "$ACTUAL" = "$DIGEST" ] \
    || die "the download hashes to $ACTUAL, not the $DIGEST it was fetched by"
step "digest verified"

# ---- extract ----------------------------------------------------------------

mkdir -p "$TMP/unpacked"
# GNU tar shells out to `gzip` for `-z`, so a box with tar and no gzip fails
# here rather than in the preflight above — worth naming, because the bare
# "could not extract" sends people to look at the download instead.
tar -xzf "$TARBALL" -C "$TMP/unpacked" \
    || die "could not extract the artifact — is gzip installed, and is $BLOB_URL a .tar.gz?"

# Located rather than assumed. The current artifact is the app-lb release
# tarball, whose contents sit under `dist/`; a heyctl-only artifact would put
# the binary at the root. Searching for it costs nothing and survives both.
SRC="$(find "$TMP/unpacked" -type f -name "$BIN" -print 2>/dev/null | head -1)"
[ -n "$SRC" ] || die "the artifact does not contain a file named '$BIN'"

# The build's own statement about the bytes it produced. Only the line for the
# binary being installed is checked: the app-lb tarball lists `app-lb` too, and
# `sha256sum -c` on the whole file would fail over a sibling this script has no
# business installing.
if [ -z "${HEYCTL_NO_VERIFY:-}" ]; then
    SUMS="$(find "$TMP/unpacked" -type f -name SHA256SUMS -print 2>/dev/null | head -1)"
    if [ -n "$SUMS" ]; then
        expected="$(awk -v b="$BIN" '$2 == b || $2 == "*" b {print $1; exit}' "$SUMS")"
        if [ -n "$expected" ]; then
            got="$(sha256_of "$SRC")"
            [ "$expected" = "$got" ] \
                || die "$BIN does not match the SHA256SUMS shipped with it"
            step "SHA256SUMS verified"
        fi
    fi
fi

if [ -f "$(dirname "$SRC")/BUILD-INFO" ]; then
    sed 's/^/    /' "$(dirname "$SRC")/BUILD-INFO" >&2
fi

# ---- install ----------------------------------------------------------------

mkdir -p "$BINDIR"
chmod 0755 "$SRC"
# Into place by rename. A running binary cannot be written through (ETXTBSY)
# but can be renamed over: the old inode stays alive for whoever holds it, and
# the next start picks up the new one.
mv -f "$SRC" "$BINDIR/.heyctl.incoming.$$"
mv -f "$BINDIR/.heyctl.incoming.$$" "$BINDIR/heyctl"
info "installed $BINDIR/heyctl"

# ---- afterwards -------------------------------------------------------------

# The published binary is dynamically linked against glibc, so on Alpine or any
# other musl system it installs perfectly and then cannot start. Better to find
# that out here, in one line, than at somebody's first real command.
if ! "$BINDIR/heyctl" --version >/dev/null 2>&1; then
    warn "$BINDIR/heyctl was installed but will not run here"
    if [ -e /lib/ld-musl-x86_64.so.1 ] || [ -e /lib/ld-musl-aarch64.so.1 ]; then
        warn "this looks like a musl system; the published build needs glibc"
        warn "build it from source instead — heyctl is a member of app-lb's"
        warn "workspace, so it is reached by manifest path, not from the root:"
        warn "    git clone https://github.com/Heyo-Computer/heyo-public"
        warn "    cargo build --release --manifest-path heyo-public/app-lb/heyctl/Cargo.toml"
    else
        warn "try running it directly to see why: $BINDIR/heyctl --version"
    fi
    exit 1
fi

case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *)
        warn "$BINDIR is not on your PATH — add this to your shell rc:"
        warn "    export PATH=\"$BINDIR:\$PATH\""
        ;;
esac

info "$("$BINDIR/heyctl" --version). Try: heyctl --help"

}

main "$@"
