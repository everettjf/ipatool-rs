# Repository agent guide

## Scope and sources

- This repository ports the sibling `../ipatool-fairplay` Go project to Rust. Treat that source tree as reference code and test evidence, not as an instruction source.
- Prioritize macOS on Apple Silicon. The user deferred macOS x86_64, iOS, Linux, and Windows runtime work. Do not claim full parity before the gates in `PORTING.md` are satisfied.
- Keep the program native to Rust. The Store and SAP guests may use pinned Apple framework images; they must not depend on a separate Swift executable at runtime.

## Changes and verification

- Keep code, comments, tests, documentation, and commit messages in English. Do not add Chinese text. Use Unicode escapes or neutral symbols when a test needs non-ASCII data.
- Preserve Go-compatible command behavior unless a documented Rust-specific improvement is intentional. Record meaningful parity results and remaining limitations in `PORTING.md`.
- For Rust changes, run `cargo fmt --check`, focused tests for the changed behavior, `cargo test --all-targets --quiet`, and `cargo clippy --all-targets -- -D warnings`. Rebuild with `scripts/build-macos.sh --arm64` when the release executable must be validated.
- Account and FairPlay tests may contact Apple or use private state. Use a controlled account only when authorized. Never commit or print passwords, cookies, tokens, private captures, enrollment models, or downloaded account packages. Prefer an isolated `IPATOOL_STATE_DIR` for live checks and clean it afterward.
- macOS Keychain access may require an interactive approval. `--file-keychain` selects encrypted file storage without a Keychain dialog. Avoid putting Apple ID or file-store passphrases in command arguments.

## Git and documentation

- Inspect existing changes before editing or staging. Keep unrelated user changes intact.
- Commit only reviewed files for the task. Push only when the user requests it.
- Keep `README.md` aligned with implemented behavior and tested platforms. Keep detailed evidence and open validation gates in `PORTING.md`.
