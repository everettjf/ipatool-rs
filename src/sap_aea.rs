//! Bounded parsing of AEA cryptex headers and FCS metadata.

use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use aes::Aes256;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{
    Deserializable, Kem, OpModeR, aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256,
    setup_receiver,
};
use p256::{SecretKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use sha2::Sha256;
use url::Url;
use zeroize::Zeroizing;

use crate::{sap_archive::ArchiveEntry, sap_remote::RemoteFile};

const HEADER_SIZE: usize = 12;
const MAX_AUTH_DATA: usize = 1 << 20;
const MAX_FCS_KEY_SIZE: u64 = 64 << 10;
const MAIN_SALT_SIZE: usize = 32;
const ENCRYPTED_ROOT_SIZE: usize = 112;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub struct AeaRoot {
    pub file_size: u64,
    pub segment_size: u32,
    pub segments_per_cluster: u32,
    pub cluster_offset: u64,
    pub cluster_mac: [u8; 32],
    pub main_key: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
struct FcsResponse {
    #[serde(rename = "enc-request")]
    enc_request: String,
    #[serde(rename = "wrapped-key")]
    wrapped_key: String,
}

pub struct AeaHeader {
    pub profile_and_scrypt_strength: u32,
    pub metadata: HashMap<String, Vec<u8>>,
    pub auth_data: Vec<u8>,
}

impl AeaHeader {
    pub fn fcs_key_url(&self) -> Result<Url> {
        let bytes = self
            .metadata
            .get("com.apple.wkms.fcs-key-url")
            .context("AEA metadata does not contain an FCS key URL")?;
        let text = std::str::from_utf8(bytes).context("invalid Apple FCS key URL")?;
        let url = Url::parse(text).context("invalid Apple FCS key URL")?;
        if url.scheme() != "https"
            || url.host_str() != Some("wkms-public.apple.com")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("invalid Apple FCS key URL {text:?}");
        }
        Ok(url)
    }

    pub fn fcs_response(&self) -> Result<&[u8]> {
        self.metadata
            .get("com.apple.wkms.fcs-response")
            .map(Vec::as_slice)
            .context("AEA metadata does not contain an FCS response")
    }

    /// Fetch the Apple-published restore-image key and unwrap this image's AEA key.
    pub fn resolve_symmetric_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let url = self.fcs_key_url()?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .context("create Apple FCS client")?;
        let mut response = client
            .get(url)
            .send()
            .context("download Apple FCS key")?
            .error_for_status()
            .context("Apple FCS key server returned an error")?;
        let mut pem = Zeroizing::new(Vec::new());
        response
            .by_ref()
            .take(MAX_FCS_KEY_SIZE + 1)
            .read_to_end(&mut pem)
            .context("read Apple FCS key")?;
        if pem.len() as u64 > MAX_FCS_KEY_SIZE {
            bail!("Apple FCS key response is too large");
        }
        self.unwrap_fcs_key(&pem)
    }

    /// Decrypt an HPKE-wrapped AEA key using a PKCS#8 P-256 FCS private key.
    pub fn unwrap_fcs_key(&self, pem: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if pem.len() as u64 > MAX_FCS_KEY_SIZE {
            bail!("Apple FCS key response is too large");
        }
        let pem = std::str::from_utf8(pem).context("Apple FCS key is not PEM encoded")?;
        let secret = SecretKey::from_pkcs8_pem(pem)
            .context("Apple FCS key is not a PKCS#8 P-256 private key")?;
        let wrapped: FcsResponse =
            serde_json::from_slice(self.fcs_response()?).context("parse AEA FCS response")?;
        let encapsulation = STANDARD
            .decode(&wrapped.enc_request)
            .context("decode AEA FCS encapsulation")?;
        let ciphertext = STANDARD
            .decode(&wrapped.wrapped_key)
            .context("decode AEA wrapped key")?;
        type FcsKem = DhP256HkdfSha256;
        let private_key = <FcsKem as Kem>::PrivateKey::from_bytes(secret.to_bytes().as_ref())
            .map_err(|_| anyhow::anyhow!("load AEA FCS private key"))?;
        let encapsulated_key = <FcsKem as Kem>::EncappedKey::from_bytes(&encapsulation)
            .map_err(|_| anyhow::anyhow!("invalid AEA FCS encapsulation"))?;
        let mut receiver = setup_receiver::<AesGcm256, HkdfSha256, FcsKem>(
            &OpModeR::Base,
            &private_key,
            &encapsulated_key,
            b"",
        )
        .map_err(|_| anyhow::anyhow!("initialize AEA FCS recipient"))?;
        let key = receiver
            .open(&ciphertext, b"")
            .map_err(|_| anyhow::anyhow!("unwrap AEA symmetric key"))?;
        Ok(Zeroizing::new(key))
    }
}

pub fn read_remote_header(remote: &RemoteFile, entry: ArchiveEntry) -> Result<AeaHeader> {
    if entry.size < HEADER_SIZE as u64
        || entry
            .offset
            .checked_add(entry.size)
            .is_none_or(|end| end > remote.size())
    {
        bail!("AEA archive entry exceeds remote image");
    }
    let mut prefix = [0u8; HEADER_SIZE];
    read_exact_at(remote, &mut prefix, entry.offset)?;
    let auth_size = validate_prefix(&prefix)?;
    if auth_size as u64 > entry.size - HEADER_SIZE as u64 {
        bail!("AEA authentication data exceeds archive entry");
    }
    let mut auth_data = vec![0u8; auth_size];
    read_exact_at(remote, &mut auth_data, entry.offset + HEADER_SIZE as u64)?;
    Ok(AeaHeader {
        profile_and_scrypt_strength: u32::from_le_bytes(prefix[4..8].try_into()?),
        metadata: parse_metadata(&auth_data)?,
        auth_data,
    })
}

pub fn read_remote_root(
    remote: &RemoteFile,
    entry: ArchiveEntry,
    header: &AeaHeader,
    symmetric_key: &[u8],
) -> Result<AeaRoot> {
    if entry
        .offset
        .checked_add(entry.size)
        .is_none_or(|end| end > remote.size())
    {
        bail!("AEA archive entry exceeds remote image");
    }
    let salt_offset = HEADER_SIZE as u64 + header.auth_data.len() as u64;
    let cluster_offset = salt_offset
        .checked_add((MAIN_SALT_SIZE + ENCRYPTED_ROOT_SIZE) as u64)
        .context("AEA root offset overflow")?;
    if cluster_offset > entry.size {
        bail!("AEA root header exceeds archive entry");
    }
    let mut salt = [0u8; MAIN_SALT_SIZE];
    let mut encrypted_root = [0u8; ENCRYPTED_ROOT_SIZE];
    read_exact_at(remote, &mut salt, entry.offset + salt_offset)?;
    read_exact_at(
        remote,
        &mut encrypted_root,
        entry.offset + salt_offset + MAIN_SALT_SIZE as u64,
    )?;
    decrypt_root_header(header, entry.size, &salt, &encrypted_root, symmetric_key).map(
        |mut root| {
            root.cluster_offset = entry.offset + cluster_offset;
            root
        },
    )
}

fn decrypt_root_header(
    header: &AeaHeader,
    encrypted_size: u64,
    main_salt: &[u8; MAIN_SALT_SIZE],
    encrypted_root: &[u8; ENCRYPTED_ROOT_SIZE],
    symmetric_key: &[u8],
) -> Result<AeaRoot> {
    if symmetric_key.is_empty() {
        bail!("empty AEA symmetric key");
    }
    let mut info = b"AEA_AMK".to_vec();
    info.extend_from_slice(&header.profile_and_scrypt_strength.to_le_bytes());
    let mut main_key = Zeroizing::new(vec![0u8; symmetric_key.len()]);
    Hkdf::<Sha256>::new(Some(main_salt), symmetric_key)
        .expand(&info, &mut main_key)
        .map_err(|_| anyhow::anyhow!("derive AEA main key"))?;

    let mut root_key = Zeroizing::new([0u8; 80]);
    Hkdf::<Sha256>::new(None, &main_key)
        .expand(b"AEA_RHEK", &mut *root_key)
        .map_err(|_| anyhow::anyhow!("derive AEA root key"))?;
    let (expected_mac, rest) = encrypted_root.split_at(32);
    let (ciphertext, cluster_mac) = rest.split_at(48);
    let mut mac = Hmac::<Sha256>::new_from_slice(&root_key[..32])?;
    mac.update(cluster_mac);
    mac.update(&header.auth_data);
    mac.update(ciphertext);
    mac.update(&(cluster_mac.len() as u64 + header.auth_data.len() as u64).to_le_bytes());
    mac.verify_slice(expected_mac)
        .map_err(|_| anyhow::anyhow!("AEA root header failed authentication"))?;

    let mut plain = Zeroizing::new([0u8; 48]);
    plain.copy_from_slice(ciphertext);
    Aes256Ctr::new_from_slices(&root_key[32..64], &root_key[64..80])?.apply_keystream(&mut *plain);
    let file_size = u64::from_le_bytes(plain[0..8].try_into()?);
    let actual_encrypted_size = u64::from_le_bytes(plain[8..16].try_into()?);
    let segment_size = u32::from_le_bytes(plain[16..20].try_into()?);
    let segments_per_cluster = u32::from_le_bytes(plain[20..24].try_into()?);
    if file_size == 0 || file_size > i64::MAX as u64 {
        bail!("invalid AEA output size {file_size}");
    }
    if actual_encrypted_size != encrypted_size {
        bail!("AEA encrypted size is {actual_encrypted_size}, expected {encrypted_size}");
    }
    if segment_size == 0 || segments_per_cluster == 0 {
        bail!("AEA has an invalid segment layout");
    }
    if plain[24] != b'e' || plain[25] != 2 {
        bail!("unsupported AEA encoding");
    }
    Ok(AeaRoot {
        file_size,
        segment_size,
        segments_per_cluster,
        cluster_offset: 0,
        cluster_mac: cluster_mac.try_into()?,
        main_key,
    })
}

fn read_exact_at(remote: &RemoteFile, buffer: &mut [u8], offset: u64) -> Result<()> {
    if remote.read_at(buffer, offset)? != buffer.len() {
        bail!("short AEA archive read at {offset}");
    }
    Ok(())
}

fn validate_prefix(prefix: &[u8; HEADER_SIZE]) -> Result<usize> {
    if &prefix[..4] != b"AEA1" {
        bail!("invalid AEA magic");
    }
    let profile = u32::from_le_bytes(prefix[4..8].try_into()?);
    if profile & 0x00ff_ffff != 1 {
        bail!("unsupported AEA profile {}", profile & 0x00ff_ffff);
    }
    let auth_size = u32::from_le_bytes(prefix[8..12].try_into()?) as usize;
    if auth_size > MAX_AUTH_DATA {
        bail!("AEA authentication data is too large: {auth_size}");
    }
    Ok(auth_size)
}

pub fn parse_metadata(data: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    let mut metadata = HashMap::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let Some(length_bytes) = data.get(cursor..cursor + 4) else {
            bail!("read AEA metadata length: truncated record");
        };
        let length = u32::from_le_bytes(length_bytes.try_into()?) as usize;
        if length < 5 || length > data.len() - cursor {
            bail!("invalid AEA metadata record length {length}");
        }
        let record = &data[cursor + 4..cursor + length];
        let Some(separator) = record.iter().position(|byte| *byte == 0) else {
            bail!("invalid AEA metadata record");
        };
        if separator == 0 {
            bail!("invalid AEA metadata record");
        }
        let key = std::str::from_utf8(&record[..separator]).context("invalid AEA metadata key")?;
        metadata.insert(key.to_owned(), record[separator + 1..].to_vec());
        cursor += length;
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{OpModeS, Serializable, setup_sender};
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    #[test]
    fn parses_bounded_aea_metadata_and_fcs_url() {
        let mut bytes = Vec::new();
        for (key, value) in [
            (
                "com.apple.wkms.fcs-key-url",
                b"https://wkms-public.apple.com/key".as_slice(),
            ),
            ("com.apple.wkms.fcs-response", b"{}".as_slice()),
        ] {
            let length = 4 + key.len() + 1 + value.len();
            bytes.extend_from_slice(&(length as u32).to_le_bytes());
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(value);
        }
        let header = AeaHeader {
            profile_and_scrypt_strength: 1,
            metadata: parse_metadata(&bytes).unwrap(),
            auth_data: bytes,
        };
        assert_eq!(
            header.fcs_key_url().unwrap().host_str(),
            Some("wkms-public.apple.com")
        );
        assert_eq!(header.fcs_response().unwrap(), b"{}");
        assert!(validate_prefix(&[b'A', b'E', b'A', b'1', 1, 0, 0, 0, 0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn rejects_bad_profile_record_and_key_url() {
        assert!(validate_prefix(&[0; HEADER_SIZE]).is_err());
        let mut prefix = *b"AEA1\x01\x00\x00\x00\x00\x00\x20\x00";
        assert!(validate_prefix(&prefix).is_err());
        prefix[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate_prefix(&prefix).is_ok());
        assert!(parse_metadata(&[32, 0, 0, 0, 1, 2, 3, 4]).is_err());
        let header = AeaHeader {
            profile_and_scrypt_strength: 1,
            metadata: HashMap::from([(
                "com.apple.wkms.fcs-key-url".into(),
                b"https://example.com/key".to_vec(),
            )]),
            auth_data: Vec::new(),
        };
        assert!(header.fcs_key_url().is_err());
    }

    #[test]
    fn unwraps_fcs_hpke_key_and_rejects_tampering() {
        type FcsKem = DhP256HkdfSha256;
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let public =
            <FcsKem as Kem>::PublicKey::from_bytes(secret.public_key().to_sec1_bytes().as_ref())
                .unwrap();
        let (encapsulation, mut sender) =
            setup_sender::<AesGcm256, HkdfSha256, FcsKem>(&OpModeS::Base, &public, b"").unwrap();
        let wrapped = sender.seal(&[0x42; 32], b"").unwrap();
        let mut header = AeaHeader {
            profile_and_scrypt_strength: 1,
            metadata: HashMap::from([(
                "com.apple.wkms.fcs-response".into(),
                serde_json::json!({
                    "enc-request": STANDARD.encode(encapsulation.to_bytes()),
                    "wrapped-key": STANDARD.encode(&wrapped),
                })
                .to_string()
                .into_bytes(),
            )]),
            auth_data: Vec::new(),
        };
        assert_eq!(
            &*header.unwrap_fcs_key(pem.as_bytes()).unwrap(),
            &[0x42; 32]
        );

        let mut tampered = wrapped;
        tampered[0] ^= 1;
        header.metadata.insert(
            "com.apple.wkms.fcs-response".into(),
            serde_json::json!({
                "enc-request": STANDARD.encode(encapsulation.to_bytes()),
                "wrapped-key": STANDARD.encode(tampered),
            })
            .to_string()
            .into_bytes(),
        );
        assert!(header.unwrap_fcs_key(pem.as_bytes()).is_err());
    }

    #[test]
    fn authenticates_and_decrypts_root_header() {
        let header = AeaHeader {
            profile_and_scrypt_strength: 1,
            metadata: HashMap::new(),
            auth_data: b"fixture-auth-data".to_vec(),
        };
        let salt = [0x12; MAIN_SALT_SIZE];
        let symmetric_key = [0x34; 32];
        let mut info = b"AEA_AMK".to_vec();
        info.extend_from_slice(&1u32.to_le_bytes());
        let mut main_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), &symmetric_key)
            .expand(&info, &mut main_key)
            .unwrap();
        let mut root_key = [0u8; 80];
        Hkdf::<Sha256>::new(None, &main_key)
            .expand(b"AEA_RHEK", &mut root_key)
            .unwrap();
        let mut encrypted = [0u8; ENCRYPTED_ROOT_SIZE];
        encrypted[32..40].copy_from_slice(&8192u64.to_le_bytes());
        encrypted[40..48].copy_from_slice(&4096u64.to_le_bytes());
        encrypted[48..52].copy_from_slice(&4096u32.to_le_bytes());
        encrypted[52..56].copy_from_slice(&2u32.to_le_bytes());
        encrypted[56] = b'e';
        encrypted[57] = 2;
        encrypted[80..].fill(0x56);
        Aes256Ctr::new_from_slices(&root_key[32..64], &root_key[64..80])
            .unwrap()
            .apply_keystream(&mut encrypted[32..80]);
        let mut mac = Hmac::<Sha256>::new_from_slice(&root_key[..32]).unwrap();
        mac.update(&encrypted[80..]);
        mac.update(&header.auth_data);
        mac.update(&encrypted[32..80]);
        mac.update(&(32u64 + header.auth_data.len() as u64).to_le_bytes());
        encrypted[..32].copy_from_slice(&mac.finalize().into_bytes());

        let root = decrypt_root_header(&header, 4096, &salt, &encrypted, &symmetric_key).unwrap();
        assert_eq!(root.file_size, 8192);
        assert_eq!(root.segment_size, 4096);
        assert_eq!(root.segments_per_cluster, 2);
        assert_eq!(root.cluster_mac, [0x56; 32]);
        assert_eq!(&*root.main_key, &main_key);

        encrypted[32] ^= 1;
        assert!(decrypt_root_header(&header, 4096, &salt, &encrypted, &symmetric_key).is_err());
    }
}
