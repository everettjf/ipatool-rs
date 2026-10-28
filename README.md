# ipatool-rs

> **An experimental Rust rewrite.** I started this project solely to use Codex quota that would otherwise go unused and to see whether Codex could rewrite these workflows in Rust. It has no other purpose. For practical use, please prefer the original [ipatool](https://github.com/majd/ipatool) and [UnfairPlay](https://github.com/DrWhax/unfairplay) projects.

## Thanks to the original projects

- [ipatool](https://github.com/majd/ipatool) and its contributors for the App Store search, account, purchase, and download workflows.
- [UnfairPlay](https://github.com/DrWhax/unfairplay) and its contributors for the FairPlay enrollment and IPA decryption work.

Thank you to both projects and their maintainers. `ipatool-rs` brings these two areas together in a Rust CLI. The sibling `ipatool-fairplay` Go source tree served as a reference for the port. The CLI implements its command paths, including an MCP server and FairPlay diagnostics. Full parity is still being validated; see the [porting record](docs/PORTING.md) for evidence and the [TODO list](docs/TODO.md) for remaining work.

Version 0.2.0 provides experimental binaries for **macOS on Apple Silicon, Linux x86_64/ARM64, and Windows x86_64/ARM64**. Public catalog behavior is checked on native CI runners for each portable target. Authenticated Store and private FairPlay workflows on Linux and Windows still need end-to-end validation. macOS x86_64 and iOS remain deferred.

## Install the experimental Rust rewrite

On an Apple Silicon Mac, install the release through the project's Homebrew tap:

```sh
brew tap everettjf/tap
brew install everettjf/tap/ipatool-rs
ipatool-rs --version
```

Alternatively, download the matching archive and SHA-256 file from the [v0.2.0 GitHub release](https://github.com/everettjf/ipatool-rs/releases/tag/v0.2.0). The available archives are `macos-arm64.tar.gz`, `linux-x86_64.tar.gz`, `linux-aarch64.tar.gz`, `windows-x86_64.zip`, and `windows-arm64.zip`, each prefixed with `ipatool-rs-0.2.0-`. Verify a tarball with `sha256sum -c FILE.sha256` on Linux or `shasum -a 256 -c FILE.sha256` on macOS. On Windows, compare `Get-FileHash FILE -Algorithm SHA256` with the companion `.sha256` file. Extract the archive and put `ipatool-rs` (or `ipatool-rs.exe`) on your `PATH`. The command can coexist with the original `ipatool`.

The macOS archive is Developer ID signed and notarized. Real 2FA, successful recovery from a rejected Store token, interactive Keychain login and revoke, and private FairPlay decryption still need end-to-end validation. Linux and Windows account, credential-store, and package flows have not yet been validated with a real account. See [remaining work](docs/TODO.md). The 0.2.0 version number does not assert full parity with the reference projects.

## Build and check

```sh
cargo fmt --check
cargo test --all-targets --quiet
cargo clippy --all-targets -- -D warnings
scripts/build-macos.sh --arm64
```

The build script creates a signed `target/release/ipatool-macos-arm64` executable. The signature is ad hoc; it is not Apple notarization. The executable does not launch a separate Go, Python, or Swift binary. Store and SAP operations still run selected, pinned Apple framework code inside the Rust emulator.

Release archives use a Developer ID signature and an Apple notarization check. The release procedure is in [docs/RELEASING.md](docs/RELEASING.md).

The 0.2.0 archives include external copies of the two checked, account-independent FairPlay startup profiles under `assets/fairplay-startup/`. They remain embedded in the executable for automatic recovery. Automatic generation of a new profile during collection is still planned; see [the export design](docs/STARTUP_PROFILE_EXPORT.md).

## Public catalog commands

These commands do not require an Apple account:

```sh
./target/release/ipatool-macos-arm64 search ScriptWidget --platform macos --country US --limit 5
./target/release/ipatool-macos-arm64 lookup --app-id 1555600758 --platform macos --country US
./target/release/ipatool-macos-arm64 latest-version-id --app-id 1555600758 --platform macos --country US
```

Use `--format json` for machine-readable output. The catalog also supports iPhone, iPad, Apple TV, Apple Watch, and visionOS platforms. Public searches default to the US storefront unless `--country` is supplied.

## Account and download commands

Run `auth login` interactively so the Apple ID password and any verification code are entered at prompts rather than in shell history:

```sh
./target/release/ipatool-macos-arm64 auth login
./target/release/ipatool-macos-arm64 auth info
./target/release/ipatool-macos-arm64 list-purchases --platform macos --max-results 2
./target/release/ipatool-macos-arm64 list-versions --app-id 1555600758 --platform macos
./target/release/ipatool-macos-arm64 download --app-id 1555600758 --platform macos --output /tmp/ScriptWidget.pkg
```

The default macOS credential store is Apple Keychain and may require an authorization dialog. Add the global `--file-keychain` flag to each account command to use encrypted file storage with a separate passphrase prompt (for example, `ipatool-rs --file-keychain auth login`). MCP uses standard input for its protocol, so an encrypted file keychain can instead be unlocked with `--keychain-passphrase-file /absolute/private/path` on the MCP command. The file must be readable only by its owner (mode `0600` on macOS) and should be removed after use. `IPATOOL_STATE_DIR` can point to an absolute private directory to isolate its cookies and encrypted account data from existing state. Do not put either passphrase on the command line.

Native Mac App Store apps, including ScriptWidget, download as PKGs. An iPhone or iPad app made available on Apple Silicon Mac can take the separate IPA path when the Store returns a mobile package. TouchLink's Mac offer was downloaded as an IPA with SINF on Apple Silicon, while PhonePad's Mac offer was a PKG. The CLI can also request an iPhone IPA through `download --platform iphone` when the account is entitled to that version; it is a separate platform request.

Other commands include `purchase`, `get-version-metadata`, `mcp`, `fairplay-doctor`, `fairplay-enroll`, `fairplay-decrypt`, and shell `completion`. Run a command with `--help` for its options. Real FairPlay enrollment and decryption require paired private data and remain unverified on this host. The available account tests cover login without a 2FA challenge, free purchases, purchase history, version metadata, authenticated MCP listing and an already owned purchase, real Mac PKG downloads, and one compatible iPhone app's Mac IPA with SINF. A later live MCP run saw Store metadata errors and a download token-expiry response that persisted after refresh; `auth info` succeeded after Keychain approval, while interactive Keychain login and revoke and successful token recovery still need validation.

Keep credentials, cookies, downloaded packages, and private FairPlay captures outside the repository. The project uses the same MIT license as [ipatool](https://github.com/majd/ipatool/blob/main/LICENSE) and [UnfairPlay](https://github.com/DrWhax/unfairplay/blob/main/LICENSE); see [LICENSE](LICENSE). The adapted DarkPhoenix recovery component retains its Apache-2.0 terms and attribution in [NOTICE](NOTICE) and [licenses/LICENSE-DARKPHOENIX.txt](licenses/LICENSE-DARKPHOENIX.txt).
