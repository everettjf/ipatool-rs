# xattr 0.2.3 compatibility patch

Upstream: <https://crates.io/crates/xattr/0.2.3> and
<https://github.com/Stebalien/xattr>. The original crate archive SHA-256 is
`6d1526bbe5aaeb5eb06885f4d987bcdfa5e23187055de9b83fe00156a821fabc`.
The MIT and Apache-2.0 license files and upstream tests are retained.

GPUI 0.2.2 uses this version through gpui_http_client and zed-async-tar.
New libc releases no longer expose the deprecated Linux/Android ENOATTR alias.
See <https://github.com/rust-lang/libc/issues/1356>. `src/sys/mod.rs` uses
ENODATA on those platforms and retains ENOATTR on macOS/BSD. No public API or
attribute behavior is changed. All other upstream source files are unchanged.
Remove this patch when the pinned GPUI dependency chain uses a maintained xattr.
