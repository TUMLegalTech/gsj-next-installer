#!/usr/bin/env bash
# Verify before executing the installer: the descriptor's signature under the release key published beside it, and the installer's exact bytes against the descriptor.
set -euo pipefail
[[ $# == 4 ]] || { echo 'Usage: verify-release.sh INSTALLER DESCRIPTOR.json SIGNATURE.sig TRUSTED-PUBLIC.pem' >&2; exit 2; }
installer=$1 descriptor=$2 signature=$3 public=$4
fail() { printf 'Release verification failed: %s\n' "$*" >&2; exit 1; }
for file in "$installer" "$descriptor" "$signature" "$public"; do [[ -f $file ]] || fail 'Required input is not a regular file.'; done
openssl dgst -sha256 -verify "$public" -signature "$signature" "$descriptor" >/dev/null 2>&1 || fail 'Descriptor signature is invalid.'
# The builder signs this canonical descriptor shape. Parse only after signature verification.
[[ $(sed -n 's/^  "schema": "\([^"]*\)",*$/\1/p' "$descriptor") == gsj.installer-descriptor/1 ]] || fail 'Unsupported descriptor schema.'
[[ $(sed -n 's/^  "signature": "\([^"]*\)",*$/\1/p' "$descriptor") == RSA-SHA256 ]] || fail 'Unsupported signing algorithm.'
expected=$(sed -n 's/^    "sha256": "\([0-9a-f]*\)",*$/\1/p' "$descriptor")
expected_key=$(sed -n 's/^  "trustKeySha256": "\([0-9a-f]*\)",*$/\1/p' "$descriptor")
[[ $expected =~ ^[0-9a-f]{64}$ && $expected_key =~ ^[0-9a-f]{64}$ ]] || fail 'Descriptor has no unique installer/key digest.'
hash() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f 1;
  elif command -v shasum >/dev/null; then shasum -a 256 "$1" | cut -d ' ' -f 1;
  else fail 'sha256sum or shasum is required.'; fi
}
[[ $(hash "$public") == "$expected_key" ]] || fail 'Trusted public key differs from the descriptor.'
[[ $(hash "$installer") == "$expected" ]] || fail 'Installer bytes differ from the signed release.'
printf 'Verified signed descriptor and exact installer bytes. The installer was not executed.\n'
