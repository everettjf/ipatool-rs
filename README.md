# ipatool-rs

## Thanks to the original projects

- [ipatool](https://github.com/majd/ipatool) and its contributors for the App Store search, account, purchase, and download workflows.
- [UnfairPlay](https://github.com/DrWhax/unfairplay) and its contributors for the FairPlay enrollment and IPA decryption work.

Thank you to both projects and their maintainers. `ipatool-rs` brings these two areas together in a Rust CLI. The sibling `ipatool-fairplay` Go source tree served as a reference for the port. The CLI implements its command paths, including an MCP server and FairPlay diagnostics. Full parity is still being validated; see the [porting record](docs/PORTING.md) for evidence and the [TODO list](docs/TODO.md) for remaining work.

The current delivery target is **macOS on Apple Silicon**. Work on macOS x86_64, iOS, Linux, and Windows is deferred at the user's request.

## Build and check

```sh
cargo fmt --check
cargo test --all-targets --quiet
cargo clippy --all-targets -- -D warnings
scripts/build-macos.sh --arm64
```

The build script creates a signed `target/release/ipatool-macos-arm64` executable. The signature is ad hoc; it is not Apple notarization. The executable does not launch a separate Go, Python, or Swift binary. Store and SAP operations still run selected, pinned Apple framework code inside the Rust emulator.

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

The default macOS credential store is Apple Keychain and may require an authorization dialog. Add the global `--file-keychain` flag to each account command to use encrypted file storage with a separate passphrase prompt (for example, `ipatool --file-keychain auth login`). `IPATOOL_STATE_DIR` can point to an absolute private directory to isolate its cookies and encrypted account data from existing state. Do not put either passphrase on the command line.

Native Mac App Store apps, including ScriptWidget, download as PKGs. An iPhone or iPad app made available on Apple Silicon Mac can take the separate IPA path when the Store returns a mobile package. The CLI can request an iPhone IPA through `download --platform iphone` when the account is entitled to that version; it is a separate package from the native Mac release.

Other commands include `purchase`, `get-version-metadata`, `mcp`, `fairplay-doctor`, `fairplay-enroll`, `fairplay-decrypt`, and shell `completion`. Run a command with `--help` for its options. Real FairPlay enrollment and decryption require paired private data and remain unverified on this host. The available account tests cover login without a 2FA challenge, a free purchase, purchase history, version metadata, authenticated MCP listing, and real Mac PKG downloads; default Keychain authorization and token-expiry recovery still need live validation.

Keep credentials, cookies, downloaded packages, and private FairPlay captures outside the repository. The project is MIT licensed; see [LICENSE](LICENSE).
