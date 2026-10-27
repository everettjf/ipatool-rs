//! Decode App Store buy parameters with Go's `url.ParseQuery` error and first-value behavior.

use std::collections::HashMap;

use anyhow::{Result, bail};

pub(crate) fn parse_buy_params(raw: &str) -> Result<HashMap<String, String>> {
    for field in raw.split('&') {
        if field.as_bytes().contains(&b';') || has_invalid_escape(field.as_bytes()) {
            bail!("invalid buy params query");
        }
    }
    let mut values = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        values
            .entry(key.into_owned())
            .or_insert_with(|| value.into_owned());
    }
    Ok(values)
}

fn has_invalid_escape(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if bytes
                .get(index + 1)
                .is_none_or(|byte| !byte.is_ascii_hexdigit())
                || bytes
                    .get(index + 2)
                    .is_none_or(|byte| !byte.is_ascii_hexdigit())
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_query_and_preserves_first_duplicate() {
        assert!(parse_buy_params("appExtVrsId=%zz").is_err());
        assert!(parse_buy_params("appExtVrsId=1&other=%").is_err());
        assert!(parse_buy_params("appExtVrsId=1;other=2").is_err());
        let values = parse_buy_params("appExtVrsId=1&appExtVrsId=2&title=A+B&escaped=%3B").unwrap();
        assert_eq!(values["appExtVrsId"], "1");
        assert_eq!(values["title"], "A B");
        assert_eq!(values["escaped"], ";");
    }
}
