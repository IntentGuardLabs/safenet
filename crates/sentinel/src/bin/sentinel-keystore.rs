//! Operator tool for creating the encrypted keystore the sentinel loads.
//!
//! This is deliberately a separate binary from `sentinel`: it is never run at
//! startup and is not copied into the runtime image. Encryption is Alloy's
//! `PrivateKeySigner::encrypt_keystore` (Web3 Secret Storage v3, scrypt +
//! AES-128-CTR), i.e. the same code that later decrypts it.
//!
//! Secrets are only ever entered at a hidden terminal prompt — never as
//! arguments or environment variables — and are never printed.

use alloy::{primitives::B256, signers::local::PrivateKeySigner};
use argh::FromArgs;
use k256::elliptic_curve::zeroize::{Zeroize as _, Zeroizing};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, FromArgs)]
/// Create a Web3 Secret Storage (Geth-compatible) keystore for the sentinel.
struct Options {
    #[argh(subcommand)]
    command: Command,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand)]
enum Command {
    Import(Import),
    Generate(Generate),
}

/// import an existing secp256k1 private key, entered at a hidden prompt
#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "import")]
struct Import {
    /// where to write the new keystore file (must not exist)
    #[argh(option)]
    out: PathBuf,
}

/// generate a fresh random key and store it encrypted
#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "generate")]
struct Generate {
    /// where to write the new keystore file (must not exist)
    #[argh(option)]
    out: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let options: Options = argh::from_env();
    let (key, out) = match options.command {
        Command::Import(Import { out }) => {
            let hex = Zeroizing::new(rpassword::prompt_password(
                "Private key (hex, hidden; not stored or printed): ",
            )?);
            (parse_key(&hex)?, out)
        }
        Command::Generate(Generate { out }) => {
            let mut key = B256::ZERO;
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key.0);
            (Zeroizing::new(key.0), out)
        }
    };

    let password = prompt_new_password()?;
    let address = write_keystore(&out, &key, password.as_bytes())?;

    eprintln!("Keystore written to {} (mode 0600).", out.display());
    println!("{address}");
    eprintln!(
        "Verify that address is the account you intended, and use it as `expected_address`.\n\
         Store the password separately, byte-exact and without a trailing newline (see the sentinel handbook)."
    );
    Ok(())
}

/// Parses a 32-byte secp256k1 secret from hex (with optional `0x` prefix).
fn parse_key(hex: &str) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
    let mut bytes = alloy::hex::decode(hex.trim())
        .map_err(|_| "private key must be 32 bytes of hex (optionally 0x-prefixed)")?;
    let result = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| "private key must be exactly 32 bytes")
        .map(Zeroizing::new);
    bytes.zeroize();
    Ok(result?)
}

fn prompt_new_password() -> Result<Zeroizing<String>, Box<dyn Error>> {
    let password = Zeroizing::new(rpassword::prompt_password("New keystore password: ")?);
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    let confirm = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
    if *password != *confirm {
        return Err("passwords do not match".into());
    }
    Ok(password)
}

/// Encrypts `key` to a new keystore at `out`, returning its address.
///
/// The keystore is first written inside a private (0700) scratch directory
/// next to `out`, made 0600, and then hard-linked into place, so it is never
/// readable by others and an existing file is never overwritten.
fn write_keystore(
    out: &Path,
    key: &[u8; 32],
    password: &[u8],
) -> Result<alloy::primitives::Address, Box<dyn Error>> {
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let scratch = tempfile::Builder::new()
        .prefix(".sentinel-keystore-")
        .tempdir_in(parent)?;
    let (signer, _uuid) = PrivateKeySigner::encrypt_keystore(
        scratch.path(),
        &mut rand::thread_rng(),
        key,
        password,
        Some("keystore.json"),
    )?;
    let staged = scratch.path().join("keystore.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
    }
    fs::hard_link(&staged, out)
        .map_err(|err| format!("cannot create {} (must not exist): {err}", out.display()))?;
    Ok(signer.address())
}

#[cfg(test)]
mod tests {
    use super::*;
    use safenet_core::tx::Signer;

    #[test]
    fn written_keystore_loads_in_the_sentinel_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("keystore.json");
        let address = write_keystore(&out, &[7u8; 32], b"pw").unwrap();

        std::fs::write(dir.path().join("pw"), b"pw").unwrap();
        let signer = Signer::from_keystore(&out, &dir.path().join("pw"), address).unwrap();
        assert_eq!(signer.address(), address);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // No scratch directory left behind, and no overwriting.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        assert!(write_keystore(&out, &[7u8; 32], b"pw").is_err());
    }

    #[test]
    fn rejects_malformed_keys_without_echoing_them() {
        assert!(parse_key("0x1234").is_err());
        assert!(parse_key("zz").is_err());
        let err = parse_key("0xnotsecret").unwrap_err().to_string();
        assert!(!err.contains("notsecret"));
        assert!(parse_key(&"11".repeat(32)).is_ok());
    }
}
