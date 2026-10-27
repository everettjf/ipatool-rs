//! Lexical slash-path normalization for names stored inside archives.

pub(crate) fn clean_slash_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|previous| *previous != "..") => {
                parts.pop();
            }
            ".." if !absolute => parts.push(part),
            ".." => {}
            _ => parts.push(part),
        }
    }
    let cleaned = parts.join("/");
    if absolute {
        format!("/{cleaned}")
    } else if cleaned.is_empty() {
        ".".to_owned()
    } else {
        cleaned
    }
}
