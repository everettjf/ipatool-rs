//! Resolve explicit per-image SINF relationships from an archive manifest.
//! Ported from UnfairPlay b3a7a432 internal/fairplay/license_association.go (MIT).
//! A missing adjacent license never falls back to an unrelated archive license.

use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{application::operation, slash_path::clean_slash_path};

#[derive(Default, Deserialize)]
struct Manifest {
    #[serde(rename = "SinfPaths", default)]
    sources: Vec<String>,
    #[serde(rename = "SinfReplicationPaths", default)]
    replicas: Vec<String>,
}

fn canonical(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', '\0'])
        && path != "."
        && path != ".."
        && !path.starts_with("../")
        && clean_slash_path(path) == path
}

fn manifest_member(root: &str, relative: &str) -> Result<String> {
    if !canonical(relative)
        || !crate::fairplay::has_sinf_extension(relative)
        || !format!("/{relative}").contains("/SC_Info/")
    {
        bail!("unsafe SINF manifest path");
    }
    Ok(format!("{root}/{relative}"))
}

pub(crate) fn adjacent_sinf(image: &str) -> Result<String> {
    if !canonical(image) {
        bail!("encrypted image has a noncanonical member path");
    }
    Ok(match image.rsplit_once('/') {
        Some((directory, name)) => format!("{directory}/SC_Info/{name}.sinf"),
        None => format!("SC_Info/{image}.sinf"),
    })
}

pub(crate) fn associations(
    names: &HashSet<String>,
    mut read: impl FnMut(&str) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<BTreeMap<String, String>> {
    const SUFFIX: &str = "/SC_Info/Manifest.plist";
    let mut manifests: Vec<_> = names.iter().filter(|name| name.ends_with(SUFFIX)).collect();
    manifests.sort();
    if manifests.len() > 256 {
        bail!("IPA has too many SINF manifests");
    }
    let mut result = BTreeMap::new();
    for name in manifests {
        operation::check()?;
        let root = name.strip_suffix(SUFFIX).unwrap();
        if !canonical(root) {
            bail!("invalid SINF manifest root");
        }
        let data = read(name)?;
        if data.len() > 4 * 1024 * 1024 {
            bail!("SINF manifest exceeds its size limit");
        }
        let manifest: Manifest = plist::from_bytes(&data).context("parse SINF manifest")?;
        if manifest.sources.is_empty()
            || manifest.sources.len() > 4096
            || manifest.replicas.len() > 4096
        {
            bail!("SINF manifest has an invalid source or replica count");
        }
        let mut sources = BTreeMap::new();
        let mut source_bytes = 0usize;
        for relative in manifest.sources {
            operation::check()?;
            let member = manifest_member(root, &relative)?;
            if !names.contains(&member) {
                bail!("SINF manifest source is missing");
            }
            if sources.contains_key(&member) {
                bail!("SINF manifest contains a duplicate source");
            }
            let data = read(&member)?;
            if data.len() > 1024 * 1024 {
                bail!("SINF exceeds its size limit");
            }
            source_bytes = source_bytes
                .checked_add(data.len())
                .context("SINF source size overflow")?;
            if source_bytes > 64 * 1024 * 1024 {
                bail!("manifest SINF sources exceed their total size limit");
            }
            sources.insert(member, data);
        }
        for relative in manifest.replicas {
            operation::check()?;
            let target = manifest_member(root, &relative)?;
            if result.contains_key(&target) {
                bail!("multiple manifest mappings for one SINF");
            }
            let source = if sources.contains_key(&target) {
                target.clone()
            } else if names.contains(&target) {
                let data = read(&target)?;
                if data.len() > 1024 * 1024 {
                    bail!("SINF exceeds its size limit");
                }
                sources
                    .iter()
                    .find(|(_, source)| source.as_slice() == data.as_slice())
                    .map(|(name, _)| name.clone())
                    .context("target SINF differs from every declared source")?
            } else {
                let first = sources.first_key_value().expect("nonempty sources");
                if sources
                    .values()
                    .any(|data| data.as_slice() != first.1.as_slice())
                {
                    bail!("missing target SINF has multiple distinct declared sources");
                }
                first.0.clone()
            };
            result.insert(target, source);
        }
    }
    Ok(result)
}

pub(crate) fn image_license(
    image: &str,
    names: &HashSet<String>,
    mappings: &BTreeMap<String, String>,
) -> Result<String> {
    let target = adjacent_sinf(image)?;
    mappings
        .get(&target)
        .cloned()
        .or_else(|| names.contains(&target).then_some(target))
        .context("encrypted Mach-O has no declared or adjacent SINF")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Control {
        name: String,
        entries: BTreeMap<String, Vec<u8>>,
        accepted: bool,
        mappings: Option<BTreeMap<String, String>>,
    }

    #[test]
    fn manifest_relationships_match_pinned_go_controls() {
        let controls: Vec<Control> = serde_json::from_str(include_str!(
            "../tests/fixtures/fairplay-license-associations-public-vectors.json"
        ))
        .unwrap();
        assert!(controls.len() >= 20);
        for c in controls {
            let names = c.entries.keys().cloned().collect();
            let result = associations(&names, |name| {
                c.entries
                    .get(name)
                    .cloned()
                    .map(Zeroizing::new)
                    .context("missing member")
            });
            assert_eq!(result.is_ok(), c.accepted, "{}: {:?}", c.name, result.err());
            if c.accepted {
                let actual =
                    associations(&names, |name| Ok(Zeroizing::new(c.entries[name].clone())))
                        .unwrap();
                assert_eq!(actual, c.mappings.unwrap(), "{}", c.name);
            }
        }
    }

    #[test]
    fn does_not_guess_a_license_from_elsewhere_in_the_archive() {
        let names = ["Payload/A.app/SC_Info/A.sinf".to_owned()]
            .into_iter()
            .collect();
        assert!(
            image_license("Payload/A.app/PlugIns/B.appex/B", &names, &BTreeMap::new()).is_err()
        );
        for image in [
            "./Payload/A.app/A",
            "Payload//A.app/A",
            "Payload/B/../A.app/A",
            "/Payload/A.app/A",
            "Payload\\A.app\\A",
        ] {
            assert!(adjacent_sinf(image).is_err());
        }
    }
}
