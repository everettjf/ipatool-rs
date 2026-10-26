use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Unknown,
    Iphone,
    Ipad,
    Appletv,
    Watchos,
    Visionos,
    Macos,
}

impl Platform {
    pub fn parse(value: &str) -> Result<Option<Self>> {
        Ok(match value.to_ascii_lowercase().as_str() {
            "" => None,
            "iphone" | "ios" => Some(Self::Iphone),
            "ipad" | "ipados" => Some(Self::Ipad),
            "appletv" | "apple-tv" | "tvos" => Some(Self::Appletv),
            "watch" | "watchos" | "applewatch" | "apple-watch" => Some(Self::Watchos),
            "vision" | "visionos" | "visionpro" | "xros" | "realitydevice" => Some(Self::Visionos),
            "mac" | "macos" | "osx" => Some(Self::Macos),
            _ => bail!("invalid platform {value:?}"),
        })
    }

    pub fn search_entity(self) -> &'static str {
        match self {
            Self::Unknown | Self::Iphone => "software",
            Self::Ipad => "iPadSoftware",
            Self::Appletv => "software,tvSoftware",
            Self::Watchos => "software,watchSoftware",
            Self::Visionos => "xrosSoftware",
            Self::Macos => "macSoftware",
        }
    }

    pub fn lookup_entity(self) -> &'static str {
        match self {
            Self::Unknown | Self::Iphone => "software",
            Self::Ipad => "iPadSoftware",
            Self::Appletv => "tvSoftware",
            Self::Watchos => "watchSoftware",
            Self::Visionos => "xrosSoftware",
            Self::Macos => "macSoftware",
        }
    }

    pub fn search_entity_for(platform: Option<Self>) -> &'static str {
        platform.map_or("software,iPadSoftware", Self::search_entity)
    }

    pub fn lookup_entity_for(platform: Option<Self>) -> &'static str {
        platform.map_or("software,iPadSoftware", Self::lookup_entity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_aliases_and_entities() {
        assert_eq!(Platform::parse("iOS").unwrap(), Some(Platform::Iphone));
        assert_eq!(Platform::parse("xros").unwrap(), Some(Platform::Visionos));
        assert_eq!(
            Platform::parse("apple-watch").unwrap(),
            Some(Platform::Watchos)
        );
        assert_eq!(Platform::search_entity_for(None), "software,iPadSoftware");
        assert_eq!(Platform::Appletv.search_entity(), "software,tvSoftware");
        assert_eq!(Platform::Appletv.lookup_entity(), "tvSoftware");
        assert!(Platform::parse("android").is_err());
    }
}
