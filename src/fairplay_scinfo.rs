//! Verify signed FairPlay keyfile envelopes using the pinned Apple authority.
//! Ported from UnfairPlay b3a7a432 internal/scinfo (MIT).
//! This is protocol signature verification, not Apple CMS or TLS validation.

use anyhow::{Context, Result, bail};
use num_bigint::BigUint;
use ring::signature::{
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RsaPublicKeyComponents,
};
use x509_cert::{
    Certificate,
    der::{
        Decode, Encode, Reader, SliceReader, Tag, Tagged,
        asn1::{Any, Ia5StringRef, PrintableStringRef, UintRef},
    },
    ext::pkix::BasicConstraints,
    name::Name,
};

const AUTHORITY_MODULUS: &str = "b2673c5d2ae78ff277cfef31bcd104fdea9fd08629900aa3ff644aef69f40ab9efc4c463ca3a2d213d528c238929aadb17dccb28c469cd7224c210c1f4781d3116c5e6ea191d2a33be80abdc1148062a1f0e6181cd799a5d12f48490c87cf6789b52f8faf1886e1072f85dcb88ecb6551497a44d0bc14f276799a6a4b3d7daad";

/// The runtime exposes only the pinned authority. A synthetic constructor is
/// compiled exclusively into library tests for independent signed fixtures.
pub(crate) struct Trust {
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl Trust {
    pub(crate) fn pinned() -> Self {
        Self {
            modulus: BigUint::parse_bytes(AUTHORITY_MODULUS.as_bytes(), 16)
                .expect("fixed public authority")
                .to_bytes_be(),
            exponent: vec![1, 0, 1],
        }
    }

    #[cfg(test)]
    pub(crate) fn synthetic(modulus: Vec<u8>, exponent: Vec<u8>) -> Self {
        Self { modulus, exponent }
    }

    pub(crate) fn verify(
        &self,
        variant: u8,
        prefix: &[u8],
        certificate: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        crate::application::operation::check()?;
        if certificate.len() > 1 << 20 || signature.len() != 128 {
            bail!("invalid FairPlay certificate or signature extent");
        }
        let certificate =
            Certificate::from_der(certificate).context("parse FairPlay certificate")?;
        if certificate.signature_algorithm.oid.to_string() != "1.2.840.113549.1.1.5"
            || certificate.signature_algorithm != certificate.tbs_certificate.signature
        {
            bail!("unsupported FairPlay authority signature algorithm");
        }
        let issuer = subject_names(&certificate.tbs_certificate.issuer)?;
        if issuer.0.last().map(String::as_str) != Some("Apple FairPlay Certification Authority")
            || issuer.1 != ["Apple Inc."]
            || issuer.2 != ["Apple Certification Authority"]
        {
            bail!("unexpected FairPlay certificate authority");
        }
        let subject = subject_names(&certificate.tbs_certificate.subject)?;
        if subject.1 != ["Apple Inc."]
            || subject.2 != ["Apple FairPlay"]
            || !subject
                .0
                .last()
                .is_some_and(|cn| cn.starts_with("SINF.") || cn.starts_with("AP."))
            || certificate
                .tbs_certificate
                .get::<BasicConstraints>()?
                .is_some_and(|(_, value)| value.ca)
        {
            bail!("unexpected FairPlay certificate subject");
        }
        let signature_bytes = certificate
            .signature
            .as_bytes()
            .context("invalid authority signature bit string")?;
        if signature_bytes.len() != 128 {
            bail!("invalid authority signature length");
        }
        let tbs = certificate.tbs_certificate.to_der()?;
        RsaPublicKeyComponents {
            n: self.modulus.as_slice(),
            e: self.exponent.as_slice(),
        }
        .verify(
            &RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            &tbs,
            signature_bytes,
        )
        .map_err(|_| anyhow::anyhow!("FairPlay certificate authority signature failed"))?;
        let info = &certificate.tbs_certificate.subject_public_key_info;
        if info.algorithm.oid.to_string() != "1.2.840.113549.1.1.1"
            || !info.algorithm.parameters.as_ref().is_some_and(Any::is_null)
        {
            bail!("unsupported FairPlay public key algorithm");
        }
        let bytes = info
            .subject_public_key
            .as_bytes()
            .context("invalid RSA public key bit string")?;
        let mut reader = SliceReader::new(bytes)?;
        let (modulus, exponent) = reader.sequence(|reader| {
            let n = UintRef::decode(reader)?;
            let e = UintRef::decode(reader)?;
            Ok((n.as_bytes(), e.as_bytes()))
        })?;
        reader.finish(())?;
        if modulus.len() != 128 || modulus[0] & 0x80 == 0 || exponent != [1, 0, 1] {
            bail!("unsupported FairPlay RSA key geometry");
        }
        let algorithm = match variant {
            1 | 3 => &RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            4 | 5 => &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            _ => bail!("unsupported FairPlay keyfile envelope variant"),
        };
        RsaPublicKeyComponents {
            n: modulus,
            e: exponent,
        }
        .verify(algorithm, prefix, signature)
        .map_err(|_| anyhow::anyhow!("FairPlay signed keyfile prefix authentication failed"))
    }
}

pub fn verify_envelope(
    variant: u8,
    prefix: &[u8],
    certificate: &[u8],
    signature: &[u8],
) -> Result<()> {
    Trust::pinned().verify(variant, prefix, certificate, signature)
}

pub(crate) struct Envelope<'a> {
    pub variant: u8,
    pub prefix: &'a [u8],
    pub certificate: &'a [u8],
    pub signature: &'a [u8],
}

impl Trust {
    /// Authenticate the complete envelope, including its keyfile class. Codec
    /// parsers intentionally remain usable without a trust decision.
    pub(crate) fn keyfile(&self, data: &[u8], supp: bool) -> Result<u8> {
        let envelope = parse_envelope(data)?;
        if supp != matches!(envelope.variant, 1 | 4) {
            bail!("FairPlay keyfile variant disagrees with its file class");
        }
        self.verify(
            envelope.variant,
            envelope.prefix,
            envelope.certificate,
            envelope.signature,
        )?;
        Ok(envelope.variant)
    }
}

fn word(data: &[u8], cursor: usize) -> Result<usize> {
    let bytes = data
        .get(cursor..cursor + 4)
        .context("truncated keyfile length")?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()) as usize)
}

pub(crate) fn parse_envelope(data: &[u8]) -> Result<Envelope<'_>> {
    if !(12..=128 * 1024 * 1024).contains(&data.len()) {
        bail!("FairPlay keyfile has an invalid size");
    }
    let variant = data[0];
    let (end, certificate_start, certificate_end, signature_start) = match variant {
        1 | 4 => {
            let count_offset = if variant == 1 { 24 } else { 4 };
            let pages = word(data, count_offset)?;
            let records = count_offset + 4;
            if pages == 0 || pages > data.len().saturating_sub(records + 132) / 32 {
                bail!("SUPP page records have invalid bounds");
            }
            let end = records + pages * 32;
            let certificate_bytes = word(data, end)?;
            let start = end + 4;
            if certificate_bytes == 0 || certificate_bytes != data.len().saturating_sub(start + 128)
            {
                bail!("SUPP certificate and signature have invalid bounds");
            }
            (
                end,
                start,
                start + certificate_bytes,
                start + certificate_bytes,
            )
        }
        3 | 5 => {
            // This also validates every architecture's count, extent and
            // uniqueness before accepting the signed prefix.
            crate::fairplay_supf::Supf::parse(data)?;
            let end = 8 + word(data, 4)?;
            let certificate_bytes = word(data, end)?;
            let start = end + 4;
            if certificate_bytes == 0 || certificate_bytes > data.len().saturating_sub(start + 4) {
                bail!("SUPF certificate has invalid bounds");
            }
            let certificate_end = start + certificate_bytes;
            let signature_bytes = word(data, certificate_end)?;
            let signature_start = certificate_end + 4;
            if signature_bytes != 128 || data.len() - signature_start != signature_bytes {
                bail!("SUPF signature has invalid bounds");
            }
            (end, start, certificate_end, signature_start)
        }
        _ => bail!("unsupported FairPlay keyfile envelope variant"),
    };
    Ok(Envelope {
        variant,
        prefix: &data[..end],
        certificate: &data[certificate_start..certificate_end],
        signature: &data[signature_start..],
    })
}

fn name_value(value: &Any) -> Result<String> {
    match value.tag() {
        Tag::Utf8String => Ok(std::str::from_utf8(value.value())?.to_owned()),
        Tag::PrintableString => Ok(value
            .decode_as::<PrintableStringRef<'_>>()?
            .as_str()
            .to_owned()),
        Tag::Ia5String => Ok(value.decode_as::<Ia5StringRef<'_>>()?.as_str().to_owned()),
        Tag::TeletexString => Ok(value
            .value()
            .iter()
            .map(|&value| char::from(value))
            .collect()),
        Tag::BmpString => {
            let (pairs, remainder) = value.value().as_chunks::<2>();
            if !remainder.is_empty() {
                bail!("invalid BMP distinguished name");
            }
            Ok(String::from_utf16(
                &pairs
                    .iter()
                    .copied()
                    .map(u16::from_be_bytes)
                    .collect::<Vec<_>>(),
            )?)
        }
        _ => bail!("unsupported FairPlay distinguished-name string"),
    }
}

type Names = (Vec<String>, Vec<String>, Vec<String>);
fn subject_names(name: &Name) -> Result<Names> {
    let mut result = (Vec::new(), Vec::new(), Vec::new());
    for rdn in &name.0 {
        for attribute in rdn.0.iter() {
            match attribute.oid.to_string().as_str() {
                "2.5.4.3" => result.0.push(name_value(&attribute.value)?),
                "2.5.4.10" => result.1.push(name_value(&attribute.value)?),
                "2.5.4.11" => result.2.push(name_value(&attribute.value)?),
                _ => {}
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[derive(serde::Deserialize)]
    pub(crate) struct Control {
        pub variant: u8,
        pub accepted: bool,
        pub keyfile: Vec<u8>,
    }
    #[derive(serde::Deserialize)]
    pub(crate) struct Vectors {
        authority_modulus: Vec<u8>,
        authority_exponent: Vec<u8>,
        pub controls: Vec<Control>,
    }
    pub(crate) fn vectors() -> Vectors {
        serde_json::from_str(include_str!(
            "../tests/fixtures/fairplay-scinfo-public-vectors.json"
        ))
        .unwrap()
    }
    impl Vectors {
        pub(crate) fn trust(&self) -> Trust {
            Trust::synthetic(
                self.authority_modulus.clone(),
                self.authority_exponent.clone(),
            )
        }
    }

    #[test]
    fn signed_keyfile_variants_and_certificate_policy_match_go() {
        let vectors = vectors();
        let trust = vectors.trust();
        assert_eq!(vectors.controls.len(), 16);
        for control in &vectors.controls {
            let supp = matches!(control.variant, 1 | 4);
            assert_eq!(
                trust.keyfile(&control.keyfile, supp).is_ok(),
                control.accepted
            );
            assert!(Trust::pinned().keyfile(&control.keyfile, supp).is_err());
            assert!(trust.keyfile(&control.keyfile, !supp).is_err());
            if control.accepted {
                let mut changed = control.keyfile.clone();
                // An authenticated page record is the last byte of the prefix.
                let record_end = parse_envelope(&changed).unwrap().prefix.len();
                changed[record_end - 1] ^= 1;
                assert!(trust.keyfile(&changed, supp).is_err());
                let mut changed = control.keyfile.clone();
                *changed.last_mut().unwrap() ^= 1;
                assert!(trust.keyfile(&changed, supp).is_err());
                for length in 0..control.keyfile.len() {
                    assert!(trust.keyfile(&control.keyfile[..length], supp).is_err());
                }
                let mut trailing = control.keyfile.clone();
                trailing.push(0);
                assert!(trust.keyfile(&trailing, supp).is_err());
            }
        }
    }

    #[test]
    fn malformed_length_fields_are_bounded_and_do_not_panic() {
        for variant in [1, 3, 4, 5] {
            for length in 0..64 {
                let mut bytes = vec![0xff; length];
                if let Some(first) = bytes.first_mut() {
                    *first = variant;
                }
                assert!(parse_envelope(&bytes).is_err());
            }
        }
    }
}
