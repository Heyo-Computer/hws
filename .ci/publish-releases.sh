#!/bin/sh
# Publish the release manifests `install-apps.sh` reads — `app-lb/heyctl/
# publish-versions.sh` generalized from one binary to every installable app.
#
#   ART_API_KEY=… sh .ci/publish-releases.sh --all --from-url https://get.us2.heyo.work --out releases
#   ART_API_KEY=… sh .ci/publish-releases.sh cloud auth --out releases --push-tag releases-live
#
# ## Why this exists
#
# The same reason as publish-versions.sh: the store answers exactly one route
# anonymously — `GET /blobs/{digest}` for a public blob — and "which build is
# newest" is a question about *tags*, which need `ART_API_KEY`. So a key holder
# resolves every app's newest build to a digest once, at release time, and
# writes the answers somewhere anonymous. The installer then holds nothing.
#
# ## What it writes
#
# Into `--out DIR`:
#
#   <app>.json        One manifest per app, in the flat shape heyctl's
#                     versions.json established so a POSIX-sh installer can
#                     parse it without jq:
#                       { "app": "cloud", "kind": "bin", "bins": "cloud",
#                         "latest": "0.43.0", "store": "https://art.us2.heyo.work",
#                         "artifacts": [ { "version": "0.43.0",
#                           "platform": "linux-x86_64", "digest": "<sha256>",
#                           "commit": "<sha>" } ] }
#   index.json        { "store": …, "apps": { "<app>": "<latest>", … } }
#   install-apps.sh   The installer, copied in so the site serving the
#                     manifests also serves the script that reads them.
#   bootstrap-host.sh The fleet host installer (`--binaries releases` uses install-apps.sh).
#
# `kind` tells the installer what to do with the unpacked tarball:
#
#   bin      copy each of `bins` into $PREFIX/bin; migrations/ and <app>.conf
#            are handled as .ci/install.sh handles them
#   tree     install the whole unpacked tree at $OPT_ROOT/<app> (auth: its own
#            bun, node_modules and start.sh)
#   site     install the tree at $SITE_ROOT/<app> (retail's static bundle)
#   tarball  the artifact holds a release tarball; unpack it and copy `bins`
#            (heyvm and heyvmd)
#
# ## Pushing
#
# `--push-tag TAG` also uploads DIR to the store as one tar.gz, marks it public,
# and moves TAG to it. A us2 app-lb `site` deployment with an `artifact` block
# on that tag (see `app-lb/examples/releases-site.json`) serves it; `heyctl pull
# <deployment>` makes it live.
#
# ## Usage
#
#   sh publish-releases.sh [options] [--all | app...]
#
#   --all             Every app in the table below.
#   --out DIR         Where to write. Default ./releases.
#   --from-url URL    Merge into the manifests live at URL/<app>.json, so a
#                     version somebody pinned keeps installing after the next.
#   --from DIR        Merge into a local copy instead.
#   --ref APP=TAG     Publish this exact build of APP rather than its newest.
#   --keep N          Keep at most N versions per app and platform.
#   --push-tag TAG    Upload DIR to the store and move TAG to it.
#   --dry-run         Resolve and verify everything; write and change nothing.
#
# ## Environment
#
#   ART_URL      Default https://art.us2.heyo.work
#   ART_API_KEY  Required: tags are not public.

set -eu

ART_URL="${ART_URL:-https://art.us2.heyo.work}"
ART_API_KEY="${ART_API_KEY:-}"
OUT="releases"
FROM_URL=""
FROM_DIR=""
PINS=""
KEEP=0
PUSH_TAG=""
DRY=0
SELECTED=""
PLATFORM="linux-x86_64"

# `app workflow job name kind bins`. `workflow` is an ERE alternation because
# the CI service tags a build `ci-<workflow id>-<run>-<job>-<name>` and the
# workflow id is the file's `name:` on one installation and the registered
# repository (`Heyo-Mono` for the private monorepo) on another. The first six
# come from heyo-public's `.ci/workflows/`, the rest from the monorepo's.
APPS_TABLE='
app-lb     app-lb                release app-lb     bin     app-lb,heyctl
app-obs    app-obs               release app-obs    bin     app-obs,app-obs-dump
ci         ci                    release ci         bin     ci
queue      queue                 release queue      bin     queue
art        art                   release art        bin     art
heyosecret heyosecret            release heyosecret bin     heyosecret
cloud      cloud|Heyo-Mono       build   cloud      bin     cloud
auth       auth|Heyo-Mono        build   auth       tree    start.sh
retail     retail|Heyo-Mono      build   retail     site    index.html
heyvm      mvm-ctrl|Heyo-Mono    build   heyvm      tarball heyvm,heyvmd
'

info() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
step() { printf '    %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,$ { /^#/!q; s/^# \{0,1\}//; p; }' "$0"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --all)      SELECTED="$(printf '%s\n' "$APPS_TABLE" | awk 'NF { printf "%s ", $1 }')" ;;
        --out)      shift; [ $# -gt 0 ] || die "--out needs a path"; OUT="$1" ;;
        --from-url) shift; [ $# -gt 0 ] || die "--from-url needs a URL"; FROM_URL="${1%/}" ;;
        --from)     shift; [ $# -gt 0 ] || die "--from needs a directory"; FROM_DIR="$1" ;;
        --ref)      shift; [ $# -gt 0 ] || die "--ref needs APP=TAG"; PINS="$PINS $1" ;;
        --keep)     shift; [ $# -gt 0 ] || die "--keep needs a count"; KEEP="$1" ;;
        --push-tag) shift; [ $# -gt 0 ] || die "--push-tag needs a tag"; PUSH_TAG="$1" ;;
        --dry-run)  DRY=1 ;;
        -h|--help)  usage; exit 0 ;;
        -*)         usage >&2; die "unknown option: $1" ;;
        *)          SELECTED="$SELECTED $1" ;;
    esac
    shift
done

[ -n "$SELECTED" ] || die "name the apps to publish, or --all"
[ -n "$FROM_URL" ] && [ -n "$FROM_DIR" ] && die "--from-url and --from both name the manifests to merge into; pick one"
case "$KEEP" in *[!0-9]*) die "--keep needs a number" ;; esac
case "$PUSH_TAG" in
    ci-*) die "--push-tag may not start with ci- (that series belongs to the CI service)" ;;
    *[!A-Za-z0-9_.-]*) die "--push-tag '$PUSH_TAG' has characters a tag cannot hold" ;;
esac

for tool in curl tar awk sed sort grep sha256sum mktemp find; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required and was not found"
done
ART_URL="${ART_URL%/}"
[ -n "$ART_API_KEY" ] || die "ART_API_KEY is required — tags are not public"

HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/publish-releases.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT INT TERM
# See publish-versions.sh: a `die` inside `$( … )` only exits the subshell.
FATAL="$TMP/fatal"
fail() { printf '%s\n' "$*" > "$FATAL"; die "$*"; }
checkpoint() { [ -s "$FATAL" ] && die "$(cat "$FATAL")"; return 0; }

# ---- the store --------------------------------------------------------------

http() {
    method="$1"; path="$2"; out="$3"; shift 3
    code="$(curl -sS -L -X "$method" -o "$out" -w '%{http_code}' \
        -H "Authorization: Bearer $ART_API_KEY" "$@" "$ART_URL$path" 2>>"$TMP/curl.err")" || true
    case "$code" in ''|*[!0-9]*) echo 000 ;; *) echo "$code" ;; esac
}

api() {
    body="$TMP/body.$$"
    code="$(http GET "$1" "$body")"
    case "$code" in
        200) cat "$body"; rm -f "$body" ;;
        000) rm -f "$body"; fail "could not reach $ART_URL — $(tail -1 "$TMP/curl.err" 2>/dev/null)" ;;
        401|403) rm -f "$body"; fail "the store rejected the credential (HTTP $code)" ;;
        *) rm -f "$body"; fail "GET $ART_URL$1 failed with HTTP $code" ;;
    esac
}

strip_ws() { tr -d ' \t\r\n'; }

TAGS="$TMP/tags.txt"
api /tags | strip_ws | tr ',' '\n' | sed -n 's/.*"tag":"\([^"]*\)".*/\1/p' > "$TAGS"
checkpoint
[ -s "$TAGS" ] || die "$ART_URL holds no tags"

manifest_blob() {
    api "/manifests/$1" | strip_ws | grep -oE '"digest":"[0-9a-f]{64}"' | head -1 | sed 's/.*:"\(.*\)"/\1/'
}

# The run id is fixed-width hex (`%012x-%08x`, epoch ms then a sequence), so
# sorting on it alone is chronological even across workflow-id prefixes. The
# widths are in the pattern as a tripwire.
newest_tag() {
    grep -E "^ci-(${1})-[0-9a-f]{12}-[0-9a-f]{8}-${2}-${3}\$" "$TAGS" \
        | sed -E "s/^.*-([0-9a-f]{12}-[0-9a-f]{8})-${2}-${3}\$/\1 &/" \
        | sort | tail -1 | cut -d' ' -f2
}

ensure_public() {
    d="$1"
    code="$(http GET "/public/$d" "$TMP/public.json")"
    [ "$code" = 200 ] || die "GET /public/$d returned HTTP $code"
    if strip_ws < "$TMP/public.json" | grep -q '"public":true'; then
        step "blob is public"
    elif [ "$DRY" = 1 ]; then
        warn "blob is NOT public; would mark it (dry run)"
    else
        code="$(http PUT "/public/$d" "$TMP/put.json")"
        [ "$code" = 200 ] || die "PUT /public/$d returned HTTP $code"
        step "marked public"
    fi
}

# ---- manifests --------------------------------------------------------------

# `version<TAB>platform<TAB>digest<TAB>commit` per artifact record; the flat
# array splits on `{` exactly as publish-versions.sh's does.
records() {
    [ -s "$1" ] || return 0
    awk '
        BEGIN { RS = "{" }
        {
            rec = $0; gsub(/[ \t\r\n]/, "", rec)
            v = field(rec, "version"); p = field(rec, "platform")
            d = field(rec, "digest");  c = field(rec, "commit")
            if (v != "" && p != "" && d != "") print v "\t" p "\t" d "\t" c
        }
        function field(s, k,   m) {
            if (!match(s, "\"" k "\":\"[^\"]*\"")) return ""
            m = substr(s, RSTART, RLENGTH); sub("^\"" k "\":\"", "", m); sub("\"$", "", m)
            return m
        }
    ' "$1"
}

render() {
    app="$1"; kind="$2"; bins="$3"; latest="$4"; tsv="$5"
    printf '{\n  "app": "%s",\n  "kind": "%s",\n  "bins": "%s",\n' "$app" "$kind" "$bins"
    printf '  "latest": "%s",\n  "store": "%s",\n  "artifacts": [\n' "$latest" "$ART_URL"
    awk -F'\t' '
        {
            printf "%s    { \"version\": \"%s\",\n", (NR > 1 ? ",\n" : ""), $1
            printf "      \"platform\": \"%s\",\n", $2
            printf "      \"digest\": \"%s\",\n", $3
            printf "      \"commit\": \"%s\" }", $4
        }
        END { if (NR > 0) printf "\n" }
    ' "$tsv"
    printf '  ]\n}\n'
}

pin_for() {
    for p in $PINS; do
        case "$p" in "$1="*) printf '%s\n' "${p#*=}"; return 0 ;; esac
    done
    return 0
}

STAGE="$TMP/out"
mkdir -p "$STAGE"
published=""

for app in $SELECTED; do
    row="$(printf '%s\n' "$APPS_TABLE" | awk -v a="$app" '$1 == a')"
    [ -n "$row" ] || die "unknown app '$app' (known: $(printf '%s\n' "$APPS_TABLE" | awk 'NF { printf "%s ", $1 }'))"
    # shellcheck disable=SC2086
    set -- $row
    wf="$2"; job="$3"; name="$4"; kind="$5"; bins="$(printf '%s' "$6" | tr ',' ' ')"

    tag="$(pin_for "$app")"
    [ -n "$tag" ] || tag="$(newest_tag "$wf" "$job" "$name")"
    [ -n "$tag" ] || die "no published build of $app (looked for ci-$wf-<run>-$job-$name)"
    info "$app  $tag"

    digest="$(manifest_blob "$tag")"
    checkpoint
    [ -n "$digest" ] || die "$tag resolves to no blob"

    work="$TMP/$app"; mkdir -p "$work/unpacked"
    code="$(http GET "/blobs/$digest" "$work/a.tar.gz")"
    [ "$code" = 200 ] || die "$app: GET /blobs/$digest returned HTTP $code"
    [ "$(sha256sum "$work/a.tar.gz" | cut -d' ' -f1)" = "$digest" ] || die "$app: download does not hash to $digest"
    tar -xzf "$work/a.tar.gz" -C "$work/unpacked" --strip-components=1 || die "$app: could not extract"
    if [ -f "$work/unpacked/SHA256SUMS" ]; then
        ( cd "$work/unpacked" && sha256sum -c SHA256SUMS >/dev/null ) || die "$app: SHA256SUMS does not match"
    else
        die "$app: $tag carries no SHA256SUMS; the installer requires one"
    fi

    # Refuse to publish what the installer would fail to install.
    case "$kind" in
        tarball)
            inner="$(find "$work/unpacked" -maxdepth 1 -name '*.tar.gz' | head -1)"
            [ -n "$inner" ] || die "$app: kind tarball but no inner .tar.gz"
            for b in $bins; do tar -tzf "$inner" | grep -qx "$b" || die "$app: $inner has no $b"; done ;;
        *)
            for b in $bins; do [ -f "$work/unpacked/$b" ] || die "$app: the artifact has no $b"; done ;;
    esac

    bi="$work/unpacked/BUILD-INFO"
    [ -f "$bi" ] || die "$app: no BUILD-INFO"
    version="$(awk '$1 == "version" { print $NF; exit }' "$bi")"
    commit="$(awk '$1 == "commit" { print $2; exit }' "$bi")"
    # retail has no version of its own; its commit is the only identity it has.
    [ -n "$version" ] || version="$(printf '%s' "$commit" | cut -c1-12)"
    version="${version#v}"
    case "$version" in *[!A-Za-z0-9._+-]*|"") die "$app: version '$version' is not publishable" ;; esac
    case "$commit" in *[!0-9a-f]*) commit="" ;; esac
    step "$app $version ($PLATFORM) ${digest%${digest#????????}}…"

    ensure_public "$digest"

    existing="$TMP/$app.existing.json"; : > "$existing"
    if [ -n "$FROM_URL" ]; then
        curl -fsSL --retry 3 -o "$existing" "$FROM_URL/$app.json" 2>/dev/null \
            || { warn "no live $FROM_URL/$app.json; starting a new manifest"; : > "$existing"; }
    elif [ -n "$FROM_DIR" ] && [ -f "$FROM_DIR/$app.json" ]; then
        cp "$FROM_DIR/$app.json" "$existing"
    elif [ -f "$OUT/$app.json" ]; then
        cp "$OUT/$app.json" "$existing"
    fi

    new="$TMP/$app.tsv"
    printf '%s\t%s\t%s\t%s\n' "$version" "$PLATFORM" "$digest" "$commit" > "$new"
    records "$existing" | awk -F'\t' -v v="$version" -v p="$PLATFORM" '!($1 == v && $2 == p)' >> "$new"
    if [ "$KEEP" -gt 0 ]; then
        awk -F'\t' -v keep="$KEEP" '{ if (++n[$2] <= keep) print }' "$new" > "$new.k" && mv "$new.k" "$new"
    fi

    render "$app" "$kind" "$bins" "$version" "$new" > "$STAGE/$app.json"
    back="$(records "$STAGE/$app.json" | awk -F'\t' -v v="$version" '$1 == v { print $3; exit }')"
    [ "$back" = "$digest" ] || die "internal error: $app.json does not read back"
    published="$published $app=$version"
done

# ---- index, installer, output ------------------------------------------------

# The index covers every app with a manifest in the output, not only the ones
# published this run, so a partial publish never drops an app from it.
for f in "$OUT"/*.json; do
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    [ "$b" = index.json ] && continue
    [ -f "$STAGE/$b" ] || cp "$f" "$STAGE/$b"
done
{
    printf '{\n  "store": "%s",\n  "apps": {\n' "$ART_URL"
    first=1
    for f in "$STAGE"/*.json; do
        a="$(basename "$f" .json)"
        [ "$a" = index ] && continue
        l="$(strip_ws < "$f" | sed -n 's/.*"latest":"\([^"]*\)".*/\1/p' | head -1)"
        [ "$first" = 1 ] || printf ',\n'
        printf '    "%s": "%s"' "$a" "$l"
        first=0
    done
    printf '\n  }\n}\n'
} > "$TMP/index.json"
mv "$TMP/index.json" "$STAGE/index.json"
cp "$HERE/install-apps.sh" "$STAGE/install-apps.sh"
cp "$HERE/bootstrap-host.sh" "$STAGE/bootstrap-host.sh"

info "published:$published"

if [ "$DRY" = 1 ]; then
    info "dry run — would write $(ls "$STAGE" | wc -l | tr -d ' ') file(s) to $OUT"
    cat "$STAGE/index.json"
    exit 0
fi

mkdir -p "$OUT"
for f in "$STAGE"/*; do
    cp "$f" "$OUT/$(basename "$f").incoming.$$"
    mv -f "$OUT/$(basename "$f").incoming.$$" "$OUT/$(basename "$f")"
done
info "wrote $OUT"

[ -n "$PUSH_TAG" ] || exit 0

# One tarball with a single `releases/` wrapper — the shape an app-lb site pulls
# with `strip_components: 1`.
bundle="$TMP/releases.tar.gz"
mkdir -p "$TMP/bundle/releases"
cp "$OUT"/*.json "$OUT/install-apps.sh" "$OUT/bootstrap-host.sh" "$TMP/bundle/releases/"
tar -czf "$bundle" -C "$TMP/bundle" releases
bd="$(sha256sum "$bundle" | cut -d' ' -f1)"
size="$(wc -c < "$bundle" | tr -d ' ')"
code="$(http PUT "/blobs/$bd" "$TMP/put-blob.json" --data-binary "@$bundle" -H 'Content-Type: application/octet-stream')"
case "$code" in 200|201) step "bundle blob ${bd%${bd#????????}}… stored" ;; *) die "PUT /blobs/$bd returned HTTP $code" ;; esac
code="$(http PUT /manifests "$TMP/put-manifest.json" -H 'Content-Type: application/json' \
    --data "{\"schema\":1,\"kind\":\"generic\",\"entries\":[{\"name\":\"releases.tar.gz\",\"digest\":\"$bd\",\"size\":$size}],\"annotations\":{\"purpose\":\"install-apps manifests\"}}")"
case "$code" in 200|201) ;; *) die "PUT /manifests returned HTTP $code" ;; esac
md="$(strip_ws < "$TMP/put-manifest.json" | sed -n 's/.*"digest":"\([0-9a-f]\{64\}\)".*/\1/p')"
[ -n "$md" ] || die "the store accepted the manifest but returned no digest; $PUSH_TAG was NOT moved"
code="$(http PUT "/tags/$PUSH_TAG" "$TMP/put-tag.json" -H 'Content-Type: text/plain' --data "$md")"
case "$code" in 200|204) ;; *) die "PUT /tags/$PUSH_TAG returned HTTP $code" ;; esac
ensure_public "$bd"
info "$PUSH_TAG -> $md"
step "make it live: heyctl pull releases   (the site deployment following $PUSH_TAG)"
