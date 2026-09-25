//! The local account used to sign transactions for submitting onchain.

use crate::kdf;
use alloy::{
    consensus::{SignableTransaction as _, TxEip1559},
    eips::Encodable2718 as _,
    network::TxSignerSync as _,
    primitives::{Address, B256, TxHash, keccak256},
    signers::local::PrivateKeySigner,
};
use k256::{
    ecdsa::SigningKey,
    elliptic_curve::zeroize::{Zeroize, Zeroizing},
};
use serde::{Deserialize, Deserializer, de};
use serde_json::Value;
use std::{
    fmt::{self, Debug, Formatter},
    fs::{self, File},
    io::{self, Read as _},
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
};

/// The maximum size of a keystore password file. Anything larger is certainly
/// not a password and is rejected instead of being read into memory.
const MAX_PASSWORD_LEN: u64 = 4096;

/// The maximum size of a keystore file. Real keystores are under 1 KiB.
const MAX_KEYSTORE_LEN: u64 = 64 * 1024;

/// KDF cost ceilings. They are far above every real-world setting (Geth
/// "standard" scrypt is N = 2^18, r = 8, p = 1; PBKDF2 is 262144 iterations) but
/// stop a hostile keystore from exhausting memory or CPU at startup. The
/// sentinel's memory limit must exceed `128 * N * r` bytes of the keystore in use.
const MAX_SCRYPT_LOG_N: u32 = 20;
const MAX_SCRYPT_R: u64 = 16;
const MAX_SCRYPT_P: u64 = 16;
const MAX_SCRYPT_MEMORY: u64 = 1 << 30;
const MAX_PBKDF2_ITERATIONS: u64 = 10_000_000;

/// An error ECDSA signing a transaction.
#[derive(Debug, thiserror::Error)]
#[error("an error occurred signing an Ethereum transaction")]
pub struct SigningError;

/// An error loading a [`Signer`] from an encrypted keystore.
///
/// Messages are intended for operators: they name the offending file and
/// what is wrong with it, and never contain the password, key material or any
/// keystore contents.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("cannot read keystore password file {}: {kind}", path.display())]
    PasswordFile { path: PathBuf, kind: io::ErrorKind },
    #[error(
        "keystore password file {} is empty; it must contain the exact keystore password",
        .0.display()
    )]
    EmptyPassword(PathBuf),
    #[error(
        "keystore password file {} is larger than {MAX_PASSWORD_LEN} bytes; it must contain only the keystore password",
        .0.display()
    )]
    PasswordTooLarge(PathBuf),
    #[error("keystore password environment variable {name}: {reason}")]
    PasswordEnv { name: String, reason: &'static str },
    #[error("cannot read keystore file {}: {kind}", path.display())]
    KeystoreFile { path: PathBuf, kind: io::ErrorKind },
    #[error(
        "{} is not a valid Web3 Secret Storage (Geth-compatible) JSON keystore",
        .0.display()
    )]
    InvalidKeystore(PathBuf),
    #[error("keystore {} uses unsupported or unsafe parameters: {reason}", path.display())]
    UnsupportedKeystore { path: PathBuf, reason: &'static str },
    #[error(
        "keystore {} has no `address`/`id` field and a temporary copy to decrypt could not be created (is a writable /tmp available?)",
        .0.display()
    )]
    TempCopy(PathBuf),
    #[error(
        "could not decrypt keystore {}: incorrect password (or corrupted keystore); check that the password has no trailing newline",
        .0.display()
    )]
    IncorrectPassword(PathBuf),
    #[error("keystore {} decrypts to address {actual} but {expected} was expected", path.display())]
    AddressMismatch {
        path: PathBuf,
        expected: Address,
        actual: Address,
    },
}

/// A local account that signs and submits transactions onchain on behalf of a
/// service.
#[derive(Clone)]
pub struct Signer(PrivateKeySigner);

/// A raw signed transaction.
pub struct SignedTransaction(Vec<u8>);

impl Signer {
    /// Creates an account for the given `private_key`.
    pub fn new(private_key: SigningKey) -> Self {
        let signer = PrivateKeySigner::from_signing_key(private_key);
        Self(signer)
    }

    /// Loads an account from a Web3 Secret Storage v3 (Geth-compatible)
    /// encrypted JSON keystore.
    ///
    /// The password is read verbatim from `password_file`: **no whitespace or
    /// newline is trimmed**, so the file must contain exactly the password
    /// (e.g. created with `printf '%s'`). An empty file is rejected. The
    /// password only lives for the duration of this call and is zeroized
    /// before returning, on success and error alike. Files are only read.
    ///
    /// The decrypted account must have exactly the `expected` address,
    /// otherwise an error is returned and the key is dropped.
    pub fn from_keystore(
        keystore: &Path,
        password_file: &Path,
        expected: Address,
    ) -> Result<Self, KeystoreError> {
        let password = read_password(password_file)?;
        Self::decrypt_keystore(keystore, password, expected)
    }

    /// Like [`Signer::from_keystore`], but reads the password from the
    /// environment variable `password_env` instead of a file.
    ///
    /// The value is used verbatim (no trimming), must be non-empty valid UTF-8
    /// and at most 4 KiB. Only the *name* of the variable is ever part of an
    /// error; its value never is.
    pub fn from_keystore_env(
        keystore: &Path,
        password_env: &str,
        expected: Address,
    ) -> Result<Self, KeystoreError> {
        let password = read_password_env(password_env)?;
        Self::decrypt_keystore(keystore, password, expected)
    }

    fn decrypt_keystore(
        keystore: &Path,
        password: Zeroizing<Vec<u8>>,
        expected: Address,
    ) -> Result<Self, KeystoreError> {
        let result = decrypt(keystore, &password);
        drop(password); // zeroizes
        let signer = result?;

        let actual = signer.address();
        if actual != expected {
            return Err(KeystoreError::AddressMismatch {
                path: keystore.to_owned(),
                expected,
                actual,
            });
        }
        Ok(Self(signer))
    }

    /// The address of the local account.
    pub fn address(&self) -> Address {
        self.0.address()
    }

    /// Signs a transaction.
    pub fn sign_transaction(&self, mut tx: TxEip1559) -> Result<SignedTransaction, SigningError> {
        let signature = self
            .0
            .sign_transaction_sync(&mut tx)
            .map_err(|_| SigningError)?;
        let raw_tx = tx.into_signed(signature).encoded_2718();
        Ok(SignedTransaction(raw_tx))
    }

    /// Deterministically derives a 32-byte value from this account's private key using
    /// HKDF-SHA256, bound to the caller-supplied `domain` and `message`.
    ///
    /// `domain` must be a non-empty, caller-chosen constant identifying the specific use case
    /// (e.g. `"safenet-sentinel-reveal-salt"`), so that derivations for unrelated purposes over
    /// the same private key can never collide. See [`kdf::derive_key`] for details.
    ///
    /// Since the output is keyed by the account's own private key, it is
    /// reproducible without persisting anything beyond `domain` and `message`.
    pub fn derive_key(&self, domain: &[u8], message: &[u8]) -> B256 {
        let mut key = self.0.to_bytes();
        let derived = kdf::derive_key(key.as_slice(), domain, &[message]);
        key.0.zeroize();
        derived
    }
}

/// Decrypts `keystore` after validating its structure, so nothing hostile ever
/// reaches the (panicking, unbounded) KDF/cipher code.
///
/// Both key-only keystores (as written by Foundry's `cast`, without `address`
/// or `id`) and full Geth keystores are accepted. The `address` field is never
/// trusted: it is not used for decryption, and the caller verifies the address
/// derived from the decrypted key against the configured `expected_address`.
fn decrypt(keystore: &Path, password: &[u8]) -> Result<PrivateKeySigner, KeystoreError> {
    // Classify plain I/O problems ourselves so they are not conflated with a
    // malformed keystore.
    let io_err = |err: io::Error| KeystoreError::KeystoreFile {
        path: keystore.to_owned(),
        kind: err.kind(),
    };
    let mut raw = Vec::new();
    File::open(keystore)
        .map_err(io_err)?
        .take(MAX_KEYSTORE_LEN + 1)
        .read_to_end(&mut raw)
        .map_err(io_err)?;
    let invalid = || KeystoreError::InvalidKeystore(keystore.to_owned());
    if raw.len() as u64 > MAX_KEYSTORE_LEN {
        return Err(invalid());
    }
    let mut json = serde_json::from_slice::<Value>(&raw).map_err(|_| invalid())?;
    validate_structure(&json).map_err(|reason| KeystoreError::UnsupportedKeystore {
        path: keystore.to_owned(),
        reason,
    })?;

    // The underlying reader insists on `address` and `id` fields it never uses
    // for decryption. If they are missing, decrypt a private, immediately
    // removed copy carrying placeholders; the original is never modified.
    let object = json.as_object_mut().expect("validated as an object");
    if object.contains_key("address") && object.contains_key("id") {
        return decrypt_contained(keystore, password, keystore);
    }
    object
        .entry("address")
        .or_insert_with(|| Value::String("0".repeat(40)));
    object
        .entry("id")
        .or_insert_with(|| Value::String(uuid_nil()));
    let copy = || -> io::Result<_> {
        let dir = tempfile::Builder::new().prefix(".keystore-").tempdir()?; // mode 0700
        let path = dir.path().join("keystore.json");
        fs::write(&path, serde_json::to_vec(&json)?)?;
        Ok((dir, path))
    };
    let (_dir, path) = copy().map_err(|_| KeystoreError::TempCopy(keystore.to_owned()))?;
    decrypt_contained(keystore, password, &path) // `_dir` removes the copy
}

fn uuid_nil() -> String {
    "00000000-0000-0000-0000-000000000000".to_owned()
}

/// Decrypts from `path`, mapping every failure (and, as defense in depth, any
/// panic in the dependency) to a sanitized [`KeystoreError`].
fn decrypt_contained(
    keystore: &Path,
    password: &[u8],
    path: &Path,
) -> Result<PrivateKeySigner, KeystoreError> {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        PrivateKeySigner::decrypt_keystore(path, password)
    }));
    match result {
        Ok(Ok(signer)) => Ok(signer),
        // The upstream error is deliberately not forwarded: its text can echo
        // parts of the input. `eth-keystore` signals a bad password (or
        // corrupted ciphertext) with a MAC mismatch.
        Ok(Err(err)) if err.to_string() == "Mac Mismatch" => {
            Err(KeystoreError::IncorrectPassword(keystore.to_owned()))
        }
        Ok(Err(_)) | Err(_) => Err(KeystoreError::InvalidKeystore(keystore.to_owned())),
    }
}

/// Decodes a JSON hex string field to exactly `len` bytes.
fn hex_field(value: Option<&Value>, len: usize) -> Option<Vec<u8>> {
    let bytes = alloy::hex::decode(value?.as_str()?).ok()?;
    (bytes.len() == len).then_some(bytes)
}

/// Checks that a keystore is a well-formed, bounded Web3 Secret Storage v3
/// document that decryption cannot panic or blow up on. Returns a static,
/// secret-free reason otherwise.
fn validate_structure(json: &Value) -> Result<(), &'static str> {
    let root = json.as_object().ok_or("not a JSON object")?;
    if root.get("version").and_then(Value::as_u64) != Some(3) {
        return Err("only keystore version 3 is supported");
    }
    let crypto = root
        .get("crypto")
        .and_then(Value::as_object)
        .ok_or("missing `crypto` section")?;
    if crypto.get("cipher").and_then(Value::as_str) != Some("aes-128-ctr") {
        return Err("only the aes-128-ctr cipher is supported");
    }
    let iv = crypto.get("cipherparams").and_then(|p| p.get("iv"));
    hex_field(iv, 16).ok_or("the cipher IV must be 16 bytes of hex")?;
    hex_field(crypto.get("ciphertext"), 32).ok_or("the ciphertext must be 32 bytes of hex")?;
    hex_field(crypto.get("mac"), 32).ok_or("the MAC must be 32 bytes of hex")?;

    let params = crypto
        .get("kdfparams")
        .and_then(Value::as_object)
        .ok_or("missing `kdfparams`")?;
    let number = |key: &str| params.get(key).and_then(Value::as_u64);
    // The derived key must be exactly 32 bytes: 16 for AES, 16 for the MAC.
    if number("dklen") != Some(32) {
        return Err("the KDF derived key length must be 32");
    }
    match params.get("salt").and_then(Value::as_str) {
        Some(salt) if !salt.is_empty() && salt.len() <= 512 && alloy::hex::decode(salt).is_ok() => {
        }
        _ => return Err("the KDF salt must be non-empty hex of at most 256 bytes"),
    }
    match crypto.get("kdf").and_then(Value::as_str) {
        Some("scrypt") => {
            let (n, r, p) = (number("n"), number("r"), number("p"));
            let (Some(n), Some(r), Some(p)) = (n, r, p) else {
                return Err("scrypt requires n, r and p");
            };
            if !n.is_power_of_two() || !(2..=1 << MAX_SCRYPT_LOG_N).contains(&n) {
                return Err("scrypt N must be a power of two between 2 and 2^20");
            }
            if !(1..=MAX_SCRYPT_R).contains(&r) || !(1..=MAX_SCRYPT_P).contains(&p) {
                return Err("scrypt r and p are out of the supported range");
            }
            if 128 * n * r > MAX_SCRYPT_MEMORY {
                return Err("scrypt memory cost (128*N*r) exceeds 1 GiB");
            }
        }
        Some("pbkdf2") => {
            if params.get("prf").and_then(Value::as_str) != Some("hmac-sha256") {
                return Err("only the hmac-sha256 PBKDF2 PRF is supported");
            }
            match number("c") {
                Some(c) if (1..=MAX_PBKDF2_ITERATIONS).contains(&c) => {}
                _ => return Err("PBKDF2 iterations are out of the supported range"),
            }
        }
        _ => return Err("only the scrypt and pbkdf2 KDFs are supported"),
    }
    Ok(())
}

/// Reads a password file byte-for-byte into a buffer that is zeroized on drop.
fn read_password(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let io_err = |err: io::Error| KeystoreError::PasswordFile {
        path: path.to_owned(),
        kind: err.kind(),
    };
    let file = File::open(path).map_err(io_err)?;
    // Zeroizing wraps the buffer up front so partially-read data is wiped on
    // the error paths as well.
    let mut password = Zeroizing::new(Vec::new());
    file.take(MAX_PASSWORD_LEN + 1)
        .read_to_end(&mut password)
        .map_err(io_err)?;
    if password.len() as u64 > MAX_PASSWORD_LEN {
        return Err(KeystoreError::PasswordTooLarge(path.to_owned()));
    }
    if password.is_empty() {
        return Err(KeystoreError::EmptyPassword(path.to_owned()));
    }
    Ok(password)
}

/// Reads the keystore password from the environment variable `name`, verbatim.
fn read_password_env(name: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let env_err = |reason| KeystoreError::PasswordEnv {
        name: name.to_owned(),
        reason,
    };
    // `std::env::var_os` panics on these; reject them as a configuration error.
    if name.is_empty() || name.contains(['=', '\0']) {
        return Err(env_err("is not a valid environment variable name"));
    }
    let value = std::env::var_os(name).ok_or_else(|| env_err("is not set"))?;
    let password = Zeroizing::new(
        value
            .into_string()
            .map_err(|_| env_err("is not valid UTF-8"))?
            .into_bytes(),
    );
    if password.is_empty() {
        return Err(env_err("is empty"));
    }
    if password.len() as u64 > MAX_PASSWORD_LEN {
        return Err(env_err("is larger than 4096 bytes"));
    }
    Ok(password)
}

impl SignedTransaction {
    /// Compute the hash of the signed transaction.
    pub fn hash(&self) -> TxHash {
        keccak256(self.0.as_slice())
    }

    /// Turn a signed transaction into its raw underlying bytes.
    pub fn into_raw(self) -> Vec<u8> {
        self.0
    }

    /// Views the signed transaction as its raw underlying bytes.
    pub fn as_raw(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Signer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut raw = B256::deserialize(deserializer)?;
        let result = SigningKey::from_slice(raw.as_slice());
        raw.0.zeroize();
        result.map(Signer::new).map_err(de::Error::custom)
    }
}

impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("Signer").field(&self.address()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{consensus::Signed, eips::Decodable2718, signers::Signature};

    const KEY: [u8; 32] = [0x42; 32];

    /// Writes a keystore encrypted with `password` for `KEY` into `dir`.
    fn write_keystore(dir: &Path, password: &[u8]) -> (PathBuf, Address) {
        let (signer, _uuid) = PrivateKeySigner::encrypt_keystore(
            dir,
            &mut rand::thread_rng(),
            KEY,
            password,
            Some("ks.json"),
        )
        .unwrap();
        (dir.join("ks.json"), signer.address())
    }

    fn write_password(dir: &Path, password: &[u8]) -> PathBuf {
        let path = dir.join("password");
        std::fs::write(&path, password).unwrap();
        path
    }

    fn load(dir: &Path, keystore_pw: &[u8], file_pw: &[u8]) -> Result<Signer, KeystoreError> {
        let (ks, address) = write_keystore(dir, keystore_pw);
        let pw = write_password(dir, file_pw);
        Signer::from_keystore(&ks, &pw, address)
    }

    #[test]
    fn loads_keystore_with_expected_address() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, address) = write_keystore(dir.path(), b"hunter2");
        let pw = write_password(dir.path(), b"hunter2");

        let signer = Signer::from_keystore(&ks, &pw, address).unwrap();
        let expected = Signer::new(SigningKey::from_bytes(&KEY.into()).unwrap());
        assert_eq!(signer.address(), expected.address());
        assert_eq!(signer.address(), address);
    }

    #[test]
    fn rejects_address_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, address) = write_keystore(dir.path(), b"pw");
        let pw = write_password(dir.path(), b"pw");
        let other = Address::repeat_byte(0x11);

        let err = Signer::from_keystore(&ks, &pw, other).unwrap_err();
        assert!(
            matches!(err, KeystoreError::AddressMismatch { actual, expected, .. }
            if actual == address && expected == other)
        );
    }

    #[test]
    fn rejects_incorrect_password() {
        let dir = tempfile::tempdir().unwrap();
        let err = load(dir.path(), b"right", b"wrong").err().unwrap();
        assert!(matches!(err, KeystoreError::IncorrectPassword(_)));
    }

    #[test]
    fn rejects_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, address) = write_keystore(dir.path(), b"pw");
        let pw = write_password(dir.path(), b"pw");
        let missing = dir.path().join("missing");

        let err = Signer::from_keystore(&ks, &missing, address).unwrap_err();
        assert!(matches!(
            err,
            KeystoreError::PasswordFile {
                kind: io::ErrorKind::NotFound,
                ..
            }
        ));
        let err = Signer::from_keystore(&missing, &pw, address).unwrap_err();
        assert!(matches!(
            err,
            KeystoreError::KeystoreFile {
                kind: io::ErrorKind::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn loads_password_from_environment_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, address) = write_keystore(dir.path(), b"env pw");
        // Unique names: tests run in parallel in one process.
        // SAFETY: no other test reads or writes these variables.
        unsafe {
            std::env::set_var("SAFENET_TEST_KEYSTORE_PW_OK", "env pw");
            std::env::set_var("SAFENET_TEST_KEYSTORE_PW_WRONG", "env pw\n");
            std::env::set_var("SAFENET_TEST_KEYSTORE_PW_EMPTY", "");
        }

        let signer = Signer::from_keystore_env(&ks, "SAFENET_TEST_KEYSTORE_PW_OK", address);
        assert_eq!(signer.unwrap().address(), address);

        // A trailing newline is part of the password, as with password files.
        let err =
            Signer::from_keystore_env(&ks, "SAFENET_TEST_KEYSTORE_PW_WRONG", address).unwrap_err();
        assert!(matches!(err, KeystoreError::IncorrectPassword(_)));

        for name in [
            "SAFENET_TEST_KEYSTORE_PW_EMPTY",
            "SAFENET_TEST_KEYSTORE_PW_UNSET",
            "",
            "A=B",
        ] {
            let err = Signer::from_keystore_env(&ks, name, address).unwrap_err();
            assert!(matches!(err, KeystoreError::PasswordEnv { .. }), "{name}");
        }
    }

    #[test]
    fn rejects_invalid_keystore_json() {
        let dir = tempfile::tempdir().unwrap();
        let ks = dir.path().join("bad.json");
        std::fs::write(&ks, b"{ \"secret-marker\": nope").unwrap();
        let pw = write_password(dir.path(), b"pw");

        let err = Signer::from_keystore(&ks, &pw, Address::ZERO).unwrap_err();
        assert!(matches!(err, KeystoreError::InvalidKeystore(_)));
        assert!(!err.to_string().contains("secret-marker"));
    }

    #[test]
    fn rejects_empty_and_oversized_password_files() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, address) = write_keystore(dir.path(), b"pw");

        let pw = write_password(dir.path(), b"");
        let err = Signer::from_keystore(&ks, &pw, address).unwrap_err();
        assert!(matches!(err, KeystoreError::EmptyPassword(_)));

        let pw = write_password(dir.path(), &vec![b'a'; 5000]);
        let err = Signer::from_keystore(&ks, &pw, address).unwrap_err();
        assert!(matches!(err, KeystoreError::PasswordTooLarge(_)));
    }

    #[test]
    fn password_with_spaces_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path(), b" pass word ", b" pass word ").is_ok());
    }

    #[test]
    fn password_bytes_are_never_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        // Keystore encrypted with a trailing newline: only the exact bytes work.
        assert!(load(dir.path(), b"pw\n", b"pw\n").is_ok());
        let err = load(dir.path(), b"pw\n", b"pw").err().unwrap();
        assert!(matches!(err, KeystoreError::IncorrectPassword(_)));
        // And the other way around: a stray newline in the file is a wrong password.
        let err = load(dir.path(), b"pw", b"pw\n").err().unwrap();
        assert!(matches!(err, KeystoreError::IncorrectPassword(_)));
    }

    #[test]
    fn errors_and_debug_do_not_leak_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let password = b"very-secret-password";
        let (ks, address) = write_keystore(dir.path(), password);
        let pw = write_password(dir.path(), b"very-secret-wrong");

        let key_hex = alloy::hex::encode(KEY);
        let errs = [
            Signer::from_keystore(&ks, &pw, address).unwrap_err(),
            Signer::from_keystore(&ks, &write_password(dir.path(), password), Address::ZERO)
                .unwrap_err(),
        ];
        for err in errs {
            let text = format!("{err} {err:?}");
            assert!(!text.contains("very-secret"));
            assert!(!text.contains(&key_hex));
        }

        let signer = load(dir.path(), password, password).unwrap();
        let debug = format!("{signer:?}");
        assert!(!debug.contains(&key_hex));
        assert!(debug.contains(&format!("{address:?}")));
    }

    /// Reads the keystore at `path` as JSON, applies `edit`, writes it to
    /// `mutated.json` next to it and returns that path.
    fn mutate(path: &Path, edit: impl FnOnce(&mut Value)) -> PathBuf {
        let mut json: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        edit(&mut json);
        let out = path.with_file_name("mutated.json");
        std::fs::write(&out, serde_json::to_vec(&json).unwrap()).unwrap();
        out
    }

    #[test]
    fn loads_key_only_keystores_without_address_or_id() {
        // Foundry's `cast` writes keystores without `address` (and Geth-style
        // tools sometimes drop `id`). The address is not needed to decrypt;
        // the derived address is still verified against `expected_address`.
        let dir = tempfile::tempdir().unwrap();
        let (ks, address) = write_keystore(dir.path(), b"pw");
        let pw = write_password(dir.path(), b"pw");
        let stripped = mutate(&ks, |json| {
            json.as_object_mut().unwrap().remove("address");
            json.as_object_mut().unwrap().remove("id");
        });
        let before = std::fs::read(&stripped).unwrap();

        let signer = Signer::from_keystore(&stripped, &pw, address).unwrap();
        assert_eq!(signer.address(), address);
        assert!(matches!(
            Signer::from_keystore(&stripped, &pw, Address::repeat_byte(0x11)),
            Err(KeystoreError::AddressMismatch { .. })
        ));
        // The original is never modified, and nothing is written next to it.
        assert_eq!(std::fs::read(&stripped).unwrap(), before);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3); // ks, password, stripped
    }

    #[test]
    fn a_wrong_address_field_is_never_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, address) = write_keystore(dir.path(), b"pw");
        let pw = write_password(dir.path(), b"pw");
        let lying = mutate(&ks, |json| {
            json["address"] = Value::String("11".repeat(20));
        });
        // The lie neither changes the derived address nor satisfies the check.
        assert_eq!(
            Signer::from_keystore(&lying, &pw, address)
                .unwrap()
                .address(),
            address
        );
        assert!(matches!(
            Signer::from_keystore(&lying, &pw, Address::repeat_byte(0x11)),
            Err(KeystoreError::AddressMismatch { .. })
        ));
    }

    type Edit = Box<dyn Fn(&mut Value)>;

    /// Hostile or malformed keystores that used to panic (or exhaust memory or
    /// CPU) inside the decryption dependency.
    fn hostile_shapes() -> Vec<(&'static str, Edit)> {
        fn set(json: &mut Value, path: &[&str], value: Value) {
            let mut current = json;
            for key in &path[..path.len() - 1] {
                current = &mut current[*key];
            }
            current[path[path.len() - 1]] = value;
        }
        let kdf = |key: &'static str, value: Value| -> Edit {
            Box::new(move |json| set(json, &["crypto", "kdfparams", key], value.clone()))
        };
        vec![
            // `key[16..32]` slices out of range: the known panic.
            ("short dklen", kdf("dklen", Value::from(16))),
            ("huge dklen", kdf("dklen", Value::from(255))),
            ("scrypt n = 2^30", kdf("n", Value::from(1u64 << 30))),
            ("scrypt n not a power of two", kdf("n", Value::from(1000))),
            ("scrypt r huge", kdf("r", Value::from(1_000_000))),
            ("scrypt p zero", kdf("p", Value::from(0))),
            ("empty salt", kdf("salt", Value::from(""))),
            (
                "short iv (slice panic)",
                Box::new(|json| set(json, &["crypto", "cipherparams", "iv"], "abcd".into())),
            ),
            (
                "short ciphertext",
                Box::new(|json| set(json, &["crypto", "ciphertext"], "ab".repeat(31).into())),
            ),
            (
                "short mac",
                Box::new(|json| set(json, &["crypto", "mac"], "ab".repeat(16).into())),
            ),
            (
                "other cipher",
                Box::new(|json| set(json, &["crypto", "cipher"], "aes-256-gcm".into())),
            ),
            (
                "wrong version",
                Box::new(|json| set(json, &["version"], 2.into())),
            ),
            (
                "pbkdf2 with excessive iterations",
                Box::new(|json| {
                    set(json, &["crypto", "kdf"], "pbkdf2".into());
                    set(
                        json,
                        &["crypto", "kdfparams"],
                        serde_json::json!({"c": 4_000_000_000u64, "dklen": 32,
                            "prf": "hmac-sha256", "salt": "abcd"}),
                    );
                }),
            ),
            ("not an object", Box::new(|json| *json = Value::from(3))),
        ]
    }

    #[test]
    fn rejects_hostile_keystores_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, address) = write_keystore(dir.path(), b"pw");
        let pw = write_password(dir.path(), b"pw");
        for (name, edit) in hostile_shapes() {
            let bad = mutate(&ks, |json| edit(json));
            // The validator itself rejects it, before any decryption...
            let json: Value = serde_json::from_slice(&std::fs::read(&bad).unwrap()).unwrap();
            let reason = validate_structure(&json).unwrap_err();
            // ...and the public entry point returns a sanitized error.
            let err = Signer::from_keystore(&bad, &pw, address).unwrap_err();
            assert!(
                matches!(err, KeystoreError::UnsupportedKeystore { .. }),
                "{name}: {err}"
            );
            assert!(err.to_string().contains(reason), "{name}");
        }
    }

    #[test]
    fn oversized_keystore_files_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (_, address) = write_keystore(dir.path(), b"pw");
        let pw = write_password(dir.path(), b"pw");
        let big = dir.path().join("big.json");
        std::fs::write(&big, vec![b' '; 70_000]).unwrap();
        assert!(matches!(
            Signer::from_keystore(&big, &pw, address),
            Err(KeystoreError::InvalidKeystore(_))
        ));
    }

    #[test]
    fn dependency_panics_are_contained_as_sanitized_errors() {
        // Bypass validation on the exact known-panic shape (dklen 16 slices
        // `key[16..32]` out of range) to prove the containment layer alone
        // turns an upstream panic into a `KeystoreError`, not an abort.
        let dir = tempfile::tempdir().unwrap();
        let (ks, _) = write_keystore(dir.path(), b"pw");
        let bad = mutate(&ks, |json| json["crypto"]["kdfparams"]["dklen"] = 16.into());
        let err = decrypt_contained(&bad, b"pw", &bad).unwrap_err();
        assert!(matches!(err, KeystoreError::InvalidKeystore(_)));
        assert!(!err.to_string().contains("range"));
    }

    #[test]
    fn can_sign_transactions() {
        let private_key = SigningKey::from_bytes(&keccak256("top secret key").0.into()).unwrap();
        let account = Signer::new(private_key);
        let tx = TxEip1559::default();
        let signed = account.sign_transaction(tx.clone()).unwrap();

        let decoded = Signed::<TxEip1559, Signature>::decode_2718_exact(signed.as_raw()).unwrap();
        assert_eq!(decoded.tx(), &tx);
        assert_eq!(decoded.recover_signer().unwrap(), account.address());
    }
}
