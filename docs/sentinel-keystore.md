# Sentinel Keystore Operations

The sentinel signs onchain transactions with a `secp256k1` key. In production this key is stored as a standard **Web3 Secret Storage v3 (Geth-compatible) encrypted JSON keystore** and decrypted in memory at startup. The TOML configuration contains only _references_ to two secret files; no raw key is ever in the image, the Compose file, the environment, or the TOML.

```toml
[signer]
type = "keystore"
path = "/run/secrets/sentinel-keystore.json"
password_file = "/run/secrets/sentinel-keystore-password"
expected_address = "0x..."
```

| Field              | Meaning                                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `type`             | Must be `"keystore"` (the only supported value).                                                                                |
| `path`             | The encrypted keystore. Only read, never written.                                                                               |
| `password_file`    | File holding the password, **read byte-for-byte**. Only read, never written.                                                    |
| `password_env`     | Alternative to `password_file`: the _name_ of an environment variable holding the password, **read byte-for-byte** once at startup. Set exactly one of the two. |
| `expected_address` | Mandatory. After decryption the derived address must match exactly, otherwise startup is refused (guards against wrong mounts). |

Relative `path`/`password_file` values resolve against the directory of the TOML file, not the working directory. Absolute paths are used as-is. Paths are not canonicalized, so neither file needs to be writable.

The sentinel refuses to start (fails closed, no fallback to any other key source) on: missing/unreadable keystore or password file, invalid or unsupported keystore, empty or oversized (> 4 KiB) password file, incorrect password, invalid `expected_address`, or an address mismatch. Errors name the file and the problem but never include the password, key, or keystore contents.

### Keystore format and limits

Standard Web3 Secret Storage v3 keystores (scrypt or PBKDF2, `aes-128-ctr`) written by Geth, Foundry's `cast`, or `sentinel-keystore` are accepted. The optional `address` and `id` fields are not needed and never trusted: the address derived from the decrypted key is what is checked against `expected_address`. (If a keystore lacks them, the sentinel decrypts a private, immediately deleted copy in `/tmp` carrying placeholders; the original file is never modified, so a writable `/tmp` must exist. The Compose example provides a tmpfs.)

The structure is validated *before* decryption, so a crafted file cannot crash or exhaust the process: the derived key length must be 32, the IV/ciphertext/MAC lengths exact, scrypt `N` a power of two up to 2^20 with `r,p <= 16` and `128*N*r <= 1 GiB`, PBKDF2 iterations at most 10,000,000, files at most 64 KiB. Anything else is refused with an "unsupported or unsafe parameters" error. Size the container memory above `128*N*r` of your keystore (Geth's standard N=2^18, r=8 needs 256 MiB; the Compose example allows 512 MiB). Any residual panic inside the decryption dependency is additionally contained and reported as an invalid-keystore error.

## Password file format

The password is used exactly as stored: **no whitespace or newline is trimmed**. A trailing newline is therefore part of the password. Create the file with `printf '%s'`, never `echo`:

```sh
umask 077
printf '%s' 'PASSWORD' > /secure/path/sentinel-keystore-password
```

That literal example is for illustration only (it puts the password in shell history and, briefly, in the process list). In production retrieve it from a secret manager into a tmpfs-backed file, as below. An "incorrect password" error with a password you believe correct usually means a stray trailing newline.

## Creating or importing a keystore

Use the repository-owned, operator-only tool `sentinel-keystore` (built with the sentinel crate, **not** included in the runtime image and never run at sentinel startup). It wraps Alloy's `PrivateKeySigner::encrypt_keystore` — the same code that later decrypts it — so there is no custom cryptography.

```sh
# Import an existing key. The key and password are typed at hidden prompts:
# never passed as arguments or environment variables, never printed.
cargo run --release --package sentinel --bin sentinel-keystore -- import --out ./sentinel-keystore.json

# Or generate a fresh key:
cargo run --release --package sentinel --bin sentinel-keystore -- generate --out ./sentinel-keystore.json
```

It writes the keystore with mode `0600` (via a private scratch directory; an existing file is never overwritten) and prints the derived **address** on stdout. Verify it is the account you intended and put it in `expected_address`. Run it on a trusted, offline-capable workstation, not in the production container. Keystores written by Geth, Foundry's `cast wallet import`/`new`, or this tool all work.

## Docker Compose deployment

[`deploy/sentinel/compose.prod.yaml`](../deploy/sentinel/compose.prod.yaml) is the production example. Highlights: image pinned by digest (`repo@sha256:...`, never `latest`/`main`; Compose itself only enforces that `SENTINEL_IMAGE` is set, so pin it in your deploy tooling), non-root `65532:65532`, `read_only: true` root filesystem with a `tmpfs` `/tmp`, all capabilities dropped, `no-new-privileges`, memory/CPU/PID limits, bounded logs, a 30 s stop grace period, no published ports, and a dedicated state volume.

```sh
cd deploy/sentinel
mkdir -p config && cp ../../crates/sentinel/sentinel.sample.toml config/sentinel.toml   # then edit
export SENTINEL_IMAGE=ghcr.io/safe-research/safenet-sentinel@sha256:<digest>
export SENTINEL_KEYSTORE_FILE=/etc/intentguard/sentinel/keystore.json
export SENTINEL_KEYSTORE_PASSWORD_FILE=/run/intentguard/sentinel/keystore-password
docker compose -f compose.prod.yaml up -d
```

`config/sentinel.toml` must set `engine` to a reachable engine (for example a `sentinel-engine` service attached to the `sentinel-private` network) and use the `/run/secrets/...` paths above. Never publish the engine port.

### Secret file ownership and permissions

The keystore is a Compose file-backed secret (mounted at `/run/secrets/sentinel-keystore.json`) and the password is an explicit read-only bind mount at `/run/secrets/sentinel-keystore-password`, with `create_host_path: false` so Compose refuses to start instead of silently creating an empty directory. Compose v2 (non-swarm) does **not reliably honor `uid`/`gid`/`mode` for file-backed secrets**: a secret is just a bind mount of the *host* file, so the container sees the host file's owner and mode. Because the container runs as `65532:65532`, both host files must be:

```sh
chown 65532:65532 "$SENTINEL_KEYSTORE_FILE" "$SENTINEL_KEYSTORE_PASSWORD_FILE"
chmod 0400        "$SENTINEL_KEYSTORE_FILE" "$SENTINEL_KEYSTORE_PASSWORD_FILE"
```

The password's parent directory (e.g. `/run/intentguard/sentinel`, mode `0700` or `0750` root:root/65532) must not let other host users in. The state directory must be writable by the container: `install -d -o 65532 -g 65532 -m 0700 /srv/intentguard/sentinel`.

On the target Linux VM, run [`deploy/sentinel/verify-host.sh`](../deploy/sentinel/verify-host.sh) after provisioning. It checks that the password directory is tmpfs, both secret files are `65532:65532` mode `0400`, the container runs as `65532:65532` with a read-only root filesystem, the keystore decrypts, SQLite is created with `mode=rwc`, and SIGTERM exits cleanly. It was written against the requirements but has **not** been run on a real GCP VM yet.

## GCP provisioning flow

1. Store the password in **GCP Secret Manager** (created out-of-band; **never** put the value in Terraform source or state — Terraform may create the empty secret and IAM binding only, with the version added by an operator using `printf '%s' "$PASSWORD" | gcloud secrets versions add sentinel-keystore-password --data-file=-`, so no newline is stored).
2. Grant the VM's service account `roles/secretmanager.secretAccessor` on that one secret.
3. At host/service start (e.g. a systemd `ExecStartPre`) fetch it with the VM service account into a **tmpfs** path (`/run/intentguard/sentinel/...`), byte-exact:

   ```sh
   install -d -m 0700 /run/intentguard/sentinel   # /run is tmpfs; verify: findmnt -no FSTYPE /run/intentguard
   umask 077
   ```

   Do not post-process the value. `gcloud secrets versions access` writes the payload without adding a newline, so redirect it straight to the file:

   ```sh
   gcloud secrets versions access latest --secret=sentinel-keystore-password \
     --out-file=/run/intentguard/sentinel/keystore-password
   chown 65532:65532 /run/intentguard/sentinel/keystore-password
   chmod 0400        /run/intentguard/sentinel/keystore-password
   ```

4. Start Compose (`docker compose -f compose.prod.yaml up -d`).
5. On service stop (`ExecStopPost`), remove the runtime file: `rm -f /run/intentguard/sentinel/keystore-password`.

The encrypted keystore may live on persistent disk (owner `65532:65532`, mode `0400`) and is mounted read-only.

## Rotation, backup and recovery

- **Password rotation:** decrypting and re-encrypting needs a tool run on a trusted host: `sentinel-keystore import` with the same key and a new password, verify the printed address equals `expected_address`, add the new secret version, deploy the new keystore and password file together, restart, and destroy old versions.
- **Key rotation:** create a new keystore (`generate`), fund the new address, update `expected_address` and the keystore, restart. Handle onchain bonds/claims of the old address per the sentinel handbook before retiring it.
- **Backup:** back up the encrypted keystore to encrypted, access-controlled storage, and the password separately (the Secret Manager version history is its backup). Neither alone is sufficient to recover the key; keep them apart. Also back up the state directory (`/srv/intentguard/sentinel`).
- **Recovery:** restore the keystore and password to a new host, run the provisioning flow, and start with the same `expected_address`. If either is lost and there is no other copy of the key, the account is unrecoverable: rotate to a new key.

## Migrating from an inline key

Replace

```toml
signer = "0x<private key>"
```

with the `[signer]` table above:

1. Import the existing key with `sentinel-keystore import --out ...` (paste it at the hidden prompt) and note the printed address.
2. Provision the password file and mount both files as described.
3. Delete the inline `signer = ...` line (both forms cannot coexist) and add `[signer]` with `expected_address` set to the printed address. The `[signer]` table must come after all top-level keys, or be moved into place before the first `[table]`.
4. Start the sentinel; the log shows `loaded signer from keystore` with the address. Then purge the old inline key from config files, backups, shell history and CI variables.

The inline form still parses for now (upstream compatibility) but logs a `DEPRECATED` warning (address only, never the key) and is not shown in the sample configuration. It will be removed.

## Security note

An encrypted keystore protects the key **at rest** (disk, backups, images, Compose files). It does **not** protect against a compromised running process or host: once decrypted at startup, the key is in the sentinel's memory, and anyone who can read that memory, or who can read both the keystore and the password file, can sign as the sentinel. The password file is a plaintext secret at runtime, so its tmpfs placement, `0400` mode and container isolation matter. Fund the account only with what gas and bonds require. A KMS/HSM or remote-signing boundary (key never in the process) remains the stronger future design.

Implementation notes: the password is read into a buffer that is zeroized right after the decryption attempt (success or failure) and is never stored in configuration. The upstream `eth-keystore` crate's own intermediate buffers are outside this control. Hostile keystore shapes are rejected up front (see [Keystore format and limits](#keystore-format-and-limits)).
