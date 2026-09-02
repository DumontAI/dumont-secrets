#!/usr/bin/env bash
# Rebuild the pinned Dumont Secrets image from this git checkout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
TAG="${1:-dumont-secrets-oidcwarden:v2026.8.0-1-dumont.1}"
EXPECTED_UPSTREAM_SHA="${EXPECTED_UPSTREAM_SHA:-1bed3a1868bcab88ffb895044d993be25a33e8b7}"

head_sha="$(git rev-parse HEAD)"
if ! git merge-base --is-ancestor "$EXPECTED_UPSTREAM_SHA" HEAD; then
  echo "error: checkout does not contain upstream pin $EXPECTED_UPSTREAM_SHA" >&2
  echo "       HEAD=$head_sha" >&2
  exit 2
fi

echo "Building $TAG from $head_sha (requires upstream $EXPECTED_UPSTREAM_SHA)"
DOCKER_BUILDKIT=1 docker build -t "$TAG" -f Dockerfile .
digest="$(docker image inspect "$TAG" --format '{{.Id}}')"
echo "$digest" | tee deploy/vault-syd1/IMAGE_DIGEST.txt
echo "OK $TAG $digest"
