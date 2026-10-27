//! Go keyring file-backend compatible PBES2/AES-GCM credential storage.

use std::{
    fs::{self, OpenOptions},
    io::Read,
    num::NonZeroU32,
    path::{Path, PathBuf},
};

use aes::{
    Aes128,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{aead, pbkdf2};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{credentials::CredentialStore, state::KEYCHAIN_SERVICE_NAME};

const ALGORITHM: &str = "PBES2-HS256+A128KW";
const ENCRYPTION: &str = "A256GCM";
const PBKDF2_ROUNDS: u32 = 8192;
const MAX_PBKDF2_ROUNDS: u32 = 1_300_000;
const MAX_ITEM_BYTES: u64 = 1024 * 1024;

pub struct FileKeychain {
    directory: PathBuf,
    passphrase: Zeroizing<String>,
}

impl FileKeychain {
    pub fn new(directory: PathBuf, passphrase: String) -> Result<Self> {
        if passphrase.is_empty() {
            bail!("file keychain passphrase must not be empty");
        }
        let metadata = fs::metadata(&directory)
            .with_context(|| format!("inspect file keychain directory {}", directory.display()))?;
        if !metadata.is_dir() {
            bail!("file keychain path is not a directory");
        }
        Ok(Self {
            directory,
            passphrase: Zeroizing::new(passphrase),
        })
    }

    fn path_for(directory: &Path, key: &str) -> Result<PathBuf> {
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("invalid file keychain item name");
        }
        Ok(directory.join(key))
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        Self::path_for(&self.directory, key)
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
    pub(crate) fn item_exists(directory: &Path, key: &str) -> Result<bool> {
        let path = Self::path_for(directory, key)?;
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).context("inspect file keychain item"),
        }
    }

    pub(crate) fn remove_item(directory: &Path, key: &str) -> Result<bool> {
        match fs::remove_file(Self::path_for(directory, key)?) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).context("remove file keychain item"),
        }
    }
}

impl CredentialStore for FileKeychain {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(key)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open keychain item {key}")),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_ITEM_BYTES {
            bail!("file keychain item has invalid file type or size");
        }
        let mut token = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        file.by_ref()
            .take(MAX_ITEM_BYTES + 1)
            .read_to_end(&mut token)?;
        if token.len() as u64 > MAX_ITEM_BYTES {
            bail!("file keychain item exceeds size limit");
        }
        let plain = decrypt_token(&token, self.passphrase.as_bytes())?;
        let item: GoKeyringItem = serde_json::from_slice(&plain).context("decode keyring item")?;
        if item.key != key {
            bail!("keyring item key does not match file name");
        }
        let data = STANDARD
            .decode(&item.data)
            .context("decode keyring item data")?;
        Ok(Some(data))
    }

    fn set(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.path(key)?;
        let item = GoKeyringItem {
            key: key.to_owned(),
            data: STANDARD.encode(data),
            label: KEYCHAIN_SERVICE_NAME.to_owned(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&item)?);
        let token = encrypt_token(&plain, self.passphrase.as_bytes())?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".ipatool-keyring-")
            .tempfile_in(&self.directory)
            .context("create private keychain staging file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        use std::io::Write;
        temporary.write_all(token.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .context("publish file keychain item")?;
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<bool> {
        Self::remove_item(&self.directory, key)
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct GoKeyringItem {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Data")]
    pub data: String,
    #[serde(rename = "Label", default)]
    pub label: String,
}

impl Drop for GoKeyringItem {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
struct ProtectedHeader {
    alg: String,
    enc: String,
    p2c: u32,
    p2s: String,
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow!("generate keychain random bytes: {error}"))?;
    Ok(bytes)
}

fn derive_kek(passphrase: &[u8], salt: &[u8], rounds: u32) -> Result<Zeroizing<[u8; 16]>> {
    let rounds = NonZeroU32::new(rounds).context("invalid keychain iteration count")?;
    let mut full_salt = Vec::with_capacity(ALGORITHM.len() + 1 + salt.len());
    full_salt.extend_from_slice(ALGORITHM.as_bytes());
    full_salt.push(0);
    full_salt.extend_from_slice(salt);
    let mut kek = Zeroizing::new([0u8; 16]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        rounds,
        &full_salt,
        passphrase,
        &mut *kek,
    );
    Ok(kek)
}

fn wrap_cek(cek: &[u8; 32], kek: &[u8; 16]) -> Result<[u8; 40]> {
    let cipher = Aes128::new_from_slice(kek).map_err(|_| anyhow!("invalid key encryption key"))?;
    let mut a = [0xa6u8; 8];
    let mut r = [[0u8; 8]; 4];
    for (slot, bytes) in r.iter_mut().zip(cek.as_chunks::<8>().0) {
        slot.copy_from_slice(bytes);
    }
    for j in 0..6 {
        for (i, slot) in r.iter_mut().enumerate() {
            let mut block =
                GenericArray::clone_from_slice(&[a.as_slice(), slot.as_slice()].concat());
            cipher.encrypt_block(&mut block);
            a.copy_from_slice(&block[..8]);
            let t = (4 * j + i + 1) as u64;
            for (left, right) in a.iter_mut().zip(t.to_be_bytes()) {
                *left ^= right;
            }
            slot.copy_from_slice(&block[8..]);
        }
    }
    let mut wrapped = [0u8; 40];
    wrapped[..8].copy_from_slice(&a);
    for (index, slot) in r.iter().enumerate() {
        wrapped[8 + index * 8..16 + index * 8].copy_from_slice(slot);
    }
    Ok(wrapped)
}

fn unwrap_cek(wrapped: &[u8], kek: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped.len() != 40 {
        bail!("invalid wrapped key length");
    }
    let cipher = Aes128::new_from_slice(kek).map_err(|_| anyhow!("invalid key encryption key"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut r = [[0u8; 8]; 4];
    for (slot, bytes) in r.iter_mut().zip(wrapped[8..].as_chunks::<8>().0) {
        slot.copy_from_slice(bytes);
    }
    for j in (0..6).rev() {
        for i in (0..4).rev() {
            let t = (4 * j + i + 1) as u64;
            let mut block = GenericArray::default();
            for (index, right) in t.to_be_bytes().iter().enumerate() {
                block[index] = a[index] ^ right;
            }
            block[8..].copy_from_slice(&r[i]);
            cipher.decrypt_block(&mut block);
            a.copy_from_slice(&block[..8]);
            r[i].copy_from_slice(&block[8..]);
        }
    }
    let mut diff = 0;
    for byte in a {
        diff |= byte ^ 0xa6;
    }
    if diff != 0 {
        bail!("keychain passphrase or wrapped key is invalid");
    }
    let mut cek = Zeroizing::new([0u8; 32]);
    for (slot, bytes) in r.iter().zip(cek.as_chunks_mut::<8>().0) {
        bytes.copy_from_slice(slot);
    }
    r.zeroize();
    Ok(cek)
}

fn encrypt_token(plain: &[u8], passphrase: &[u8]) -> Result<String> {
    let salt = random::<12>()?;
    let mut cek = Zeroizing::new(random::<32>()?);
    let iv = random::<12>()?;
    let kek = derive_kek(passphrase, &salt, PBKDF2_ROUNDS)?;
    let wrapped = wrap_cek(&cek, &kek)?;
    let header = ProtectedHeader {
        alg: ALGORITHM.into(),
        enc: ENCRYPTION.into(),
        p2c: PBKDF2_ROUNDS,
        p2s: URL_SAFE_NO_PAD.encode(salt),
    };
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &*cek)
            .map_err(|_| anyhow!("create keychain encryption key"))?,
    );
    cek.zeroize();
    let mut ciphertext = Zeroizing::new(plain.to_vec());
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(iv),
        aead::Aad::from(protected.as_bytes()),
        &mut *ciphertext,
    )
    .map_err(|_| anyhow!("encrypt keychain item"))?;
    let tag_start = ciphertext.len() - 16;
    let tag = ciphertext.split_off(tag_start);
    Ok(format!(
        "{}.{}.{}.{}.{}",
        protected,
        URL_SAFE_NO_PAD.encode(wrapped),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(&*ciphertext),
        URL_SAFE_NO_PAD.encode(tag)
    ))
}

fn decrypt_token(token: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let token = std::str::from_utf8(token).context("keychain token is not UTF-8")?;
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 5 {
        bail!("invalid keychain JWE token");
    }
    let header: ProtectedHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)
        .context("decode keychain JWE header")?;
    if header.alg != ALGORITHM || header.enc != ENCRYPTION {
        bail!("unsupported keychain JWE algorithm");
    }
    if header.p2c == 0 || header.p2c > MAX_PBKDF2_ROUNDS {
        bail!("invalid keychain PBKDF2 iteration count");
    }
    let salt = URL_SAFE_NO_PAD.decode(header.p2s)?;
    if !(8..=32).contains(&salt.len()) {
        bail!("invalid keychain PBKDF2 salt length");
    }
    let wrapped = URL_SAFE_NO_PAD.decode(parts[1])?;
    let iv = URL_SAFE_NO_PAD.decode(parts[2])?;
    let mut ciphertext = Zeroizing::new(URL_SAFE_NO_PAD.decode(parts[3])?);
    let tag = URL_SAFE_NO_PAD.decode(parts[4])?;
    if iv.len() != 12 || tag.len() != 16 {
        bail!("invalid keychain AES-GCM nonce or tag");
    }
    let kek = derive_kek(passphrase, &salt, header.p2c)?;
    let cek = unwrap_cek(&wrapped, &kek)?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &*cek)
            .map_err(|_| anyhow!("create keychain decryption key"))?,
    );
    ciphertext.extend_from_slice(&tag);
    let nonce: [u8; 12] = iv
        .try_into()
        .map_err(|_| anyhow!("invalid keychain nonce"))?;
    let plain = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(parts[0].as_bytes()),
            &mut ciphertext,
        )
        .map_err(|_| anyhow!("keychain passphrase or token authentication is invalid"))?;
    let length = plain.len();
    ciphertext.truncate(length);
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_keyring_roundtrip_and_tamper_detection() {
        let token = encrypt_token(b"test secret", b"test passphrase").unwrap();
        assert_eq!(
            &*decrypt_token(token.as_bytes(), b"test passphrase").unwrap(),
            b"test secret"
        );
        assert!(decrypt_token(token.as_bytes(), b"wrong passphrase").is_err());
        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        parts[3].push('A');
        assert!(decrypt_token(parts.join(".").as_bytes(), b"test passphrase").is_err());
    }

    #[test]
    fn file_keyring_stores_go_item_shape_and_rejects_path_escape() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            FileKeychain::new(directory.path().to_owned(), "test passphrase".into()).unwrap();
        assert!(store.get("account").unwrap().is_none());
        store.set("account", b"test account").unwrap();
        assert_eq!(store.get("account").unwrap().unwrap(), b"test account");
        assert!(store.get("../account").is_err());
        assert!(store.remove("account").unwrap());
        assert!(!store.remove("account").unwrap());
    }

    #[test]
    fn decrypts_go_keyring_fixture() {
        let token = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjo4MTkyLCJwMnMiOiJzSG9vVnljZVJuTGdsLUlXIn0.BsZ7M1fz-otj43I4u1EMEei0FZ3e-BRzsrWMtieBeHx4I5JufzIZ1w.EI5DdRRIH4nr48Ea.zX9Bnc4q9Zj8LSZb8a3kICs0C2sTRvzoM8bQEsxpDGFp0d-UmUXJHdZLIaj678vDEzzJ6d2T-fhD7dEFyDHnN1nwg_UbDm2sdIU.6HvxbFRDe3dzP0QzicJbjw";
        let plain = decrypt_token(token.as_bytes(), b"test passphrase").unwrap();
        let item: GoKeyringItem = serde_json::from_slice(&plain).unwrap();
        assert_eq!(item.key, "account");
        assert_eq!(STANDARD.decode(&item.data).unwrap(), b"go fixture");
    }
}
