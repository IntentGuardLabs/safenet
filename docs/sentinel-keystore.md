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

Standard Web3 Secret Storage v3 keystores (scrypt or PBKDF2, `aes-128-ctr`) written by Geth, Foundry's `cast`, or `sentinel-keystore` are accepted. The optional `address` and `id` fields are not needed and never trusted: the address derived from the decrypted key is what is checked against `expected_address`. (If a keystore lacks them, the sentinel decrypts a private, immediately deleted copy in `/tmp` carrying placeholders; the original file is never modified, so a writable `/tmp` must exist. The infra repo's Compose example provides a tmpfs.)

The structure is validated *before* decryption, so a crafted file cannot crash or exhaust the process: the derived key length must be 32, the IV/ciphertext/MAC lengths exact, scrypt `N` a power of two up to 2^20 with `r,p <= 16` and `128*N*r <= 1 GiB`, PBKDF2 iterations at most 10,000,000, files at most 64 KiB. Anything else is refused with an "unsupported or unsafe parameters" error. Size the container memory above `128*N*r` of your keystore (Geth's standard N=2^18, r=8 needs 256 MiB; the infra Compose example allows 512 MiB). Any residual panic inside the decryption dependency is additionally contained and reported as an invalid-keystore error.

## Password file format

The password is used exactly as stored: **no whitespace or newline is trimmed**. A trailing newline is therefore part of the password. Create the file with `printf '%s'`, never `echo`:

```sh
umask 077
printf '%s' 'PASSWORD' > /secure/path/sentinel-keystore-password
```

That literal example is for illustration only (it puts the password in shell history and, briefly, in the process list). In production retrieve it from a secret manager into a tmpfs-backed file (see the infra runbook). An "incorrect password" error with a password you believe correct usually means a stray trailing newline.

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

## Docker Compose deployment, provisioning and rotation

Deployment is owned by the infra repo, not this one: the production Compose file, host verification script, GCP Secret Manager provisioning flow, secret-file ownership/permissions, and the rotation, backup and recovery runbook are in `infra/docs/sentinel-keystore.md` (Compose file: `infra/server/sentinel/compose.prod.yaml`). The container must provide a writable `/tmp` (a tmpfs) for keystores without `address`/`id` fields, and memory above `128*N*r` of the keystore's scrypt parameters (see [Keystore format and limits](#keystore-format-and-limits)).

## Migrating from an inline key

Replace

```toml
signer = "0x<private key>"
```

with the `[signer]` table above:

1. Import the existing key with `sentinel-keystore import --out ...` (paste it at the hidden prompt) and note the printed address.
2. Provision the password file and mount both files as described in the infra runbook.
3. Delete the inline `signer = ...` line (both forms cannot coexist) and add `[signer]` with `expected_address` set to the printed address. The `[signer]` table must come after all top-level keys, or be moved into place before the first `[table]`.
4. Start the sentinel; the log shows `loaded signer from keystore` with the address. Then purge the old inline key from config files, backups, shell history and CI variables.

The inline form still parses for now (upstream compatibility) but logs a `DEPRECATED` warning (address only, never the key) and is not shown in the sample configuration. It will be removed.

## Security note

An encrypted keystore protects the key **at rest** (disk, backups, images, Compose files). It does **not** protect against a compromised running process or host: once decrypted at startup, the key is in the sentinel's memory, and anyone who can read that memory, or who can read both the keystore and the password file, can sign as the sentinel. The password file is a plaintext secret at runtime, so its tmpfs placement, `0400` mode and container isolation matter. Fund the account only with what gas and bonds require. A KMS/HSM or remote-signing boundary (key never in the process) remains the stronger future design.

Implementation notes: the password is read into a buffer that is zeroized right after the decryption attempt (success or failure) and is never stored in configuration. The upstream `eth-keystore` crate's own intermediate buffers are outside this control. Hostile keystore shapes are rejected up front (see [Keystore format and limits](#keystore-format-and-limits)).
