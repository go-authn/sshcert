#!/bin/sh
# Build GÉANT's code as judges for the tests of github.com/go-authn/sshcert:
#
#   build.sh OUTDIR [CHECKOUT]
#
# clones GÉANT's ssh-cert-tool at the commit below (or uses CHECKOUT),
# and writes to OUTDIR:
#   sshcert-geant-judge   main.go of this directory, built against GÉANT's
#                         pkg/cert (SSHCERT_GEANT_JUDGE)
#   ssh-cert-authorize    GÉANT's AuthorizedPrincipalsCommand, unmodified
#                         (SSHCERT_GEANT_AUTHORIZE)
#
# Nothing is published anywhere; the checkout is a scratch copy.
set -eu
REPO=https://gitlab.geant.org/core-aai-platform/ssh-cert-tool.git
COMMIT=5a4817753ffb32f25ce355efd670c41d0c46f933
out=$1
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
src=${2:-}
if [ -z "$src" ]; then
	src=$(mktemp -d)
	git clone -q "$REPO" "$src"
	git -C "$src" checkout -q "$COMMIT"
fi
echo "GÉANT ssh-cert-tool at $(git -C "$src" rev-parse HEAD)"
mkdir -p "$src/cmd/sshcert-geant-judge"
cp "$here/main.go" "$src/cmd/sshcert-geant-judge/main.go"
(cd "$src" && GOWORK=off CGO_ENABLED=0 go build -o "$out/sshcert-geant-judge" ./cmd/sshcert-geant-judge)
(cd "$src" && GOWORK=off CGO_ENABLED=0 go build -o "$out/ssh-cert-authorize" ./cmd/ssh-cert-authorize)
rm -rf "$src/cmd/sshcert-geant-judge"
