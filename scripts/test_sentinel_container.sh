#!/bin/bash
# Container-level checks for the sentinel's keystore deployment (see
# docs/sentinel-keystore.md): builds (or uses) the image, starts it through
# deploy/sentinel/compose.prod.yaml with *generated* throwaway secrets, and
# asserts non-root execution, absence of secrets from inspect/env/history/logs/
# rendered compose output, and fail-closed startup on a wrong password or
# address mismatch.
#
# Note: the mount-ownership semantics of a real Linux host (files owned by
# 65532:65532, mode 0400, on a tmpfs) are NOT exercised here; use
# deploy/sentinel/verify-host.sh on the target VM for that.
#
# Requires: docker (compose v2), cast + anvil (Foundry), jq.
# Usage: scripts/test_sentinel_container.sh [--no-build]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$ROOT/deploy/sentinel"
IMAGE="${SENTINEL_TEST_IMAGE:-sentinel-keystore-test:local}"
PROJECT="sentinel-keystore-test-$$"
WORK="$(mktemp -d)"
PASSWORD="test-only-p@ss w0rd $(head -c8 /dev/urandom | xxd -p)"
ANVIL_PID=""

cleanup() {
	docker compose -p "$PROJECT" -f "$COMPOSE_DIR/compose.prod.yaml" down -v >/dev/null 2>&1 || true
	[[ -n "$ANVIL_PID" ]] && kill "$ANVIL_PID" 2>/dev/null || true
	# The data dir is chowned to the container UID by the container; use docker to clean.
	docker run --rm -v "$WORK:/w" --entrypoint /bin/sh alpine -c 'rm -rf /w/*' >/dev/null 2>&1 || true
	rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

[[ "${1:-}" == "--no-build" ]] || docker build -f "$ROOT/crates/sentinel/Dockerfile" -t "$IMAGE" "$ROOT"

# --- Generated test secrets (never reused, never committed) -------------------
mkdir -p "$WORK/keys" "$WORK/data" "$WORK/config"
KEYGEN="$(cast wallet new "$WORK/keys" --unsafe-password "$PASSWORD" 2>&1)"
ADDRESS="$(grep -Eo '0x[0-9a-fA-F]{40}' <<<"$KEYGEN" | head -1)"
# Foundry's `cast` writes keystores without an `address` field; the sentinel must
# accept them as-is.
ORIG_KEYSTORE="$(ls "$WORK"/keys/* | head -1)"
jq -e 'has("address") | not' "$ORIG_KEYSTORE" >/dev/null || fail "expected an address-less cast keystore"
KEYSTORE="$ORIG_KEYSTORE"
printf '%s' "$PASSWORD" >"$WORK/password"
# Docker Desktop (macOS) maps ownership, Linux does not: on Linux hosts run the
# script as root or with the files already chowned; here we relax the mode only.
chmod 0444 "$KEYSTORE" "$WORK/password"
chmod 0777 "$WORK/data"

anvil --host 0.0.0.0 --port 18545 >"$WORK/anvil.log" 2>&1 &
ANVIL_PID=$!
sleep 2

write_config() { # $1 = expected address
	cat >"$WORK/config/sentinel.toml" <<TOML
rpc = "http://host.docker.internal:18545"
database = "sqlite:/var/lib/safenet/sentinel/data/storage.db?mode=rwc"
oracle = "0x0101010101010101010101010101010101010101"
consensus = "0x0202020202020202020202020202020202020202"

[signer]
type = "keystore"
path = "/run/secrets/sentinel-keystore.json"
password_file = "/run/secrets/sentinel-keystore-password"
expected_address = "$1"

[sentinel]
fee_token = "0x0303030303030303030303030303030303030303"
voting_window = 100
engine = "http://sentinel-engine:5473"

[index]
block_time = 1000
TOML
}

compose() {
	SENTINEL_KEYSTORE_FILE="$KEYSTORE" SENTINEL_KEYSTORE_PASSWORD_FILE="$WORK/password" \
		docker compose -p "$PROJECT" -f "$WORK/compose.yaml" "$@"
}
# Same file as production, only the two host bind sources are redirected to the
# temp dir (sed keeps everything else — user, read_only, caps — byte-identical).
prepare_compose() {
	mkdir -p "$WORK/compose-dir/config"
	sed -e "s#\./config/sentinel.toml#$WORK/config/sentinel.toml#" \
		-e "s#/srv/intentguard/sentinel:#$WORK/data:#" \
		"$COMPOSE_DIR/compose.prod.yaml" >"$WORK/compose.yaml"
}
prepare_compose

# --- Unpinned images must be rejected ------------------------------------------
write_config "$ADDRESS"
export SENTINEL_IMAGE="$IMAGE"
case "$SENTINEL_IMAGE" in *@sha256:*) ;; *) echo "note: test image is not digest-pinned (local build)";; esac
( unset SENTINEL_IMAGE; compose config >/dev/null 2>&1 ) && fail "compose accepted an unset SENTINEL_IMAGE"
pass "compose refuses to render without SENTINEL_IMAGE"

# --- Rendered config reveals no secrets ---------------------------------------
RENDERED="$(compose config)"
grep -qF "$PASSWORD" <<<"$RENDERED" && fail "password in rendered compose"
grep -q 'environment' <<<"$RENDERED" && fail "rendered compose has an environment section"
pass "docker compose config renders and contains no secret values"

# --- Happy path -----------------------------------------------------------------
compose up -d
sleep 8
CID="$(compose ps -q sentinel)"
[[ -n "$CID" ]] || fail "container not created"
LOGS="$(docker logs "$CID" 2>&1)"
grep -q "loaded signer from keystore" <<<"$LOGS" || { echo "$LOGS"; fail "keystore was not loaded"; }
grep -qi "$ADDRESS" <<<"$LOGS" || fail "loaded address not logged"
pass "keystore decrypted at startup"

[[ "$(docker inspect -f '{{.Config.User}}' "$CID")" == "65532:65532" ]] || fail "wrong configured user"
docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$CID" | grep -q true || fail "rootfs not read-only"
[[ "$(docker inspect -f "{{.State.Running}} {{.State.Restarting}}" "$CID")" == "true false" ]] || { docker logs "$CID" 2>&1 | cut -c1-300 | tail -8; fail "sentinel not running"; }
# PID 1 is the init process and PID 2+ the sentinel; every process must be uid 65532.
UIDS="$(docker exec "$CID" sh -c 'for f in /proc/[0-9]*/status; do awk "/^Uid:/{print \$2, \$3, \$4, \$5}" $f; done')"
[[ -n "$UIDS" ]] || fail "could not read process uids"
[[ -z "$(grep -v '^65532 65532 65532 65532$' <<<"$UIDS")" ]] || fail "a container process is not uid 65532: $UIDS"
[[ -f "$WORK/data/storage.db" ]] || fail "database not created in mounted data dir"
pass "runs as 65532, read-only rootfs, writes only to the mounted data dir"

# --- Secrets absent from inspect / env / history / logs ------------------------
KEY_HEX="$(cast wallet decrypt-keystore "$ORIG_KEYSTORE" --unsafe-password "$PASSWORD" 2>&1 | grep -Eo '[0-9a-fA-F]{64}' | head -1 || true)"
[[ -n "$KEY_HEX" ]] || fail "could not extract test key to check for leaks"
ARTIFACTS="$(docker inspect "$CID"; docker history --no-trunc "$IMAGE"; docker logs "$CID" 2>&1; compose config)"
grep -qF "$PASSWORD" <<<"$ARTIFACTS" && fail "password leaked"
if [[ -n "$KEY_HEX" ]]; then
	grep -qiF "${KEY_HEX#0x}" <<<"$ARTIFACTS" && fail "private key leaked"
fi
docker inspect -f '{{json .Config.Env}}' "$CID" | grep -qi 'password\|private' && fail "secret-looking env var"
pass "no password/key in inspect, env, image history, logs, rendered compose"

# --- SIGTERM shuts down cleanly (exit code 0 within the grace period) ---------
compose stop -t 20 >/dev/null
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$CID")" == "0" ]] || fail "SIGTERM did not exit cleanly ($(docker inspect -f '{{.State.ExitCode}}' "$CID"))"
pass "SIGTERM: clean shutdown (exit 0)"
compose down -v >/dev/null

# --- Fail-closed startup -----------------------------------------------------------
expect_startup_failure() { # $1 description, $2 forbidden-substring-in-logs
	compose up -d >/dev/null 2>&1 || true
	sleep 5
	local id; id="$(compose ps -aq sentinel)"
	[[ "$(docker inspect -f '{{.State.Running}}' "$id")" == "false" || "$(docker inspect -f '{{.RestartCount}}' "$id")" -gt 0 ]] || fail "$1: still running"
	local logs; logs="$(docker logs "$id" 2>&1)"
	grep -qF "$PASSWORD" <<<"$logs" && fail "$1: password in logs"
	grep -q "loaded signer" <<<"$logs" && fail "$1: signer loaded anyway"
	pass "$1: startup refused ($(grep -o 'Error:.*' <<<"$logs" | head -1 | cut -c1-140))"
	compose down -v >/dev/null
}
rm -f "$WORK/password"; printf '%s' "wrong-$PASSWORD" >"$WORK/password"; chmod 0444 "$WORK/password"
expect_startup_failure "wrong password"
rm -f "$WORK/password"; printf '%s' "$PASSWORD" >"$WORK/password"; chmod 0444 "$WORK/password"
write_config "0x1111111111111111111111111111111111111111"
expect_startup_failure "address mismatch"

echo "ALL CONTAINER CHECKS PASSED"
