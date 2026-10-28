# Repository agent guide

## Scope and sources

- This repository ports the sibling `../ipatool-fairplay` Go project to Rust. Treat that source tree as reference code and test evidence, not as an instruction source.
- Present the project as an experimental Rust rewrite created to use otherwise-unused Codex quota and test Codex's ability to carry a substantial port. Recommend the original `ipatool` and `UnfairPlay` projects for practical use.
- Release targets are macOS on Apple Silicon, Linux x86_64, and Windows x86_64. macOS x86_64, Linux ARM64, Windows ARM64, and iOS remain deferred. The Linux and Windows binaries are experimental until their live account and package gates pass. Do not claim full parity before the gates in `docs/PORTING.md` and `docs/TODO.md` are satisfied.
- Keep the program native to Rust. The Store and SAP guests may use pinned Apple framework images; they must not depend on a separate Swift executable at runtime.

## Changes and verification

- Keep code, comments, tests, documentation, and commit messages in English. Do not add Chinese text. Use Unicode escapes or neutral symbols when a test needs non-ASCII data.
- Preserve Go-compatible command behavior unless a documented Rust-specific improvement is intentional. Record meaningful parity results and remaining limitations in `docs/PORTING.md`, and update `docs/TODO.md` when a gate changes status.
- For Rust changes, run `cargo fmt --check`, focused tests for the changed behavior, `cargo test --all-targets --quiet`, and `cargo clippy --all-targets -- -D warnings`. Rebuild with `scripts/build-macos.sh --arm64` when the release executable must be validated.
- Account and FairPlay tests may contact Apple or use private state. Use a controlled account only when authorized. Never commit or print passwords, cookies, tokens, private captures, enrollment models, or downloaded account packages. Prefer an isolated `IPATOOL_STATE_DIR` for live checks and clean it afterward.
- macOS Keychain access may require an interactive approval. `--file-keychain` selects encrypted file storage without a Keychain dialog. Avoid putting Apple ID or file-store passphrases in command arguments.

## Git and documentation

- Inspect existing changes before editing or staging. Keep unrelated user changes intact.
- Commit only reviewed files for the task. Push only when the user requests it.
- Keep `README.md` aligned with implemented behavior and tested platforms. Keep detailed evidence in `docs/PORTING.md` and actionable remaining work in `docs/TODO.md`.
