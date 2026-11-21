#!/usr/bin/env python3
"""Publish a validated release tarball to the hub as `<repo>:<revision>` and `<repo>:latest`.

A manual tool for a tarball in hand. The production release policy's `hub` job
does not use it: that job tags the validated artifact by digest without
transferring it (.ci/release-policies/us2-production.yml).

    ART_API_KEY=… python3 .ci/publish-hub.py \
        --store https://art.us2.heyo.work --repo heyo/app-lb --name app-lb \
        --description "app-lb: …" app-lb-release.tar.gz

The tarball is the artifact a validation workflow uploaded (`ci/download-artifact`
keeps its bytes exactly), so its digest is already in the store. This writes a
generic manifest naming that blob, points the revision and `latest` tags at it,
and refreshes the repository's description. hub.heyo.work serves the same
global store, so the tags show up there after its next sync.

The revision comes from `dist/REVISION` inside the tarball, not from the
caller, so a tag always says which commit the bytes were built from. The
tarball must also carry `dist/SHA256SUMS`, and every file it lists has to match,
the same check a host does before installing.

Only the standard library is used, so this runs on the release image as it is.
"""

import argparse
import hashlib
import io
import json
import os
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 300


def die(msg):
    print(f"publish-hub: {msg}", file=sys.stderr)
    sys.exit(1)


def request(method, url, key, body=None, content_type=None):
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("x-api-key", key)
    if content_type:
        req.add_header("content-type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def inspect(path):
    """Return (sha256, size, revision) after verifying SHA256SUMS inside the tarball."""
    data = open(path, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile():
                files[member.name] = tar.extractfile(member).read()
    if "dist/REVISION" not in files or "dist/SHA256SUMS" not in files:
        die(f"{path} has no dist/REVISION or dist/SHA256SUMS")
    revision = files["dist/REVISION"].decode().strip()
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        die(f"dist/REVISION is not a 40-character commit: {revision!r}")
    for line in files["dist/SHA256SUMS"].decode().splitlines():
        if not line.strip():
            continue
        want, name = line.split(maxsplit=1)
        name = "dist/" + name.lstrip("*")
        if name not in files:
            die(f"SHA256SUMS lists {name}, which the tarball does not contain")
        if hashlib.sha256(files[name]).hexdigest() != want:
            die(f"{name} does not match SHA256SUMS")
    return digest, len(data), revision


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tarball")
    ap.add_argument("--store", required=True, help="the store to write to, e.g. https://art.us2.heyo.work")
    ap.add_argument("--repo", required=True, help="hub repository, e.g. heyo/app-lb")
    ap.add_argument("--name", required=True, help="the manifest entry name, e.g. app-lb")
    ap.add_argument("--description", required=True, help="first line(s) of the repository description")
    ap.add_argument("--run", default=os.environ.get("CI_RUN_ID", ""), help="CI run id, recorded on the manifest")
    ap.add_argument("--no-latest", action="store_true", help="tag only the revision")
    args = ap.parse_args()

    key = os.environ.get("ART_API_KEY", "")
    if not key:
        die("ART_API_KEY is not set")
    store = args.store.rstrip("/")
    digest, size, revision = inspect(args.tarball)
    short = revision[:7]
    print(f"publish-hub: {args.tarball} is {digest} ({size} bytes), built from {revision}")

    status, _ = request("HEAD", f"{store}/blobs/{digest}", key)
    if status == 404:
        with open(args.tarball, "rb") as f:
            status, body = request("PUT", f"{store}/blobs/{digest}", key, f.read(), "application/octet-stream")
        if status >= 300:
            die(f"uploading the blob answered {status}: {body[:300]!r}")
        print("publish-hub: uploaded the blob (the store did not have it)")
    elif status >= 300:
        die(f"checking for the blob answered {status}")

    annotations = {"heyo.revision": revision}
    if args.run:
        annotations["ci.run"] = args.run
    manifest = {
        "schema": 1,
        "kind": "generic",
        "entries": [{"name": args.name, "digest": digest, "size": size}],
        "annotations": annotations,
    }
    status, body = request("PUT", f"{store}/manifests", key, json.dumps(manifest).encode(), "application/json")
    if status >= 300:
        die(f"writing the manifest answered {status}: {body[:300]!r}")
    manifest_digest = json.loads(body)["digest"]

    tags = [short] + ([] if args.no_latest else ["latest"])
    for tag in tags:
        ref = urllib.parse.quote(f"{args.repo}:{tag}", safe="/:")
        status, body = request("PUT", f"{store}/tags/{ref}", key, manifest_digest.encode(), "text/plain")
        if status >= 300:
            die(f"tagging {args.repo}:{tag} answered {status}: {body[:300]!r}")
        print(f"publish-hub: {args.repo}:{tag} -> {manifest_digest}")

    description = f"{args.description.strip()}\nBuilt by heyo-public CI from {revision}. Linux x86_64. Source: Heyo-Computer/hws."
    repo = urllib.parse.quote(args.repo, safe="/")
    status, body = request(
        "PUT", f"{store}/repos/{repo}", key,
        json.dumps({"public": True, "description": description}).encode(), "application/json",
    )
    if status >= 300:
        die(f"updating the repository answered {status}: {body[:300]!r}")

    status, body = request("GET", f"{store}/tags/{urllib.parse.quote(f'{args.repo}:{short}', safe='/:')}", key)
    if status != 200 or manifest_digest not in body.decode(errors="replace"):
        die(f"read-back of {args.repo}:{short} did not return {manifest_digest} (answered {status})")
    print(f"publish-hub: done; hub.heyo.work serves it after its next sync")


if __name__ == "__main__":
    main()
