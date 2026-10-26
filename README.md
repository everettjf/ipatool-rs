# ipatool-rs

This repository is a Rust port of the sibling `ipatool-fairplay` Go project. The port is **in progress**; it is not yet a replacement for the Go program.

## Working commands

```sh
cargo run -- search "notes" --country US --limit 5
cargo run -- --format json search "notes" --platform ipad
cargo run -- lookup --app-id 497799835
cargo run -- latest-version-id --app-id 874139669 --platform iphone
cargo run -- fairplay-doctor --ipa /private/path/app.ipa --model /private/path/model.bin
cargo run -- auth info
cargo run -- auth revoke
```

`search` supports iPhone, iPad, Apple TV, Apple Watch, visionOS and macOS platform aliases. It derives platforms from catalog metadata, filters Watch results, and uses the visionOS storefront when appropriate. `lookup` accepts an app ID or bundle identifier. These read-only commands use the public catalog; `--country` defaults to `US` until account storefront support is ported.

`latest-version-id` resolves the current external version ID for iPhone, iPad, Apple TV, Apple Watch, or visionOS through the public platform catalog. It does not list historical versions. macOS version lookup still requires the authenticated Store and package metadata flow.

On macOS, `auth info` reads the existing Go-compatible account from the system Keychain and prints only its name and email. `auth revoke` removes that account and its KBSync cache. Other credential backends and `auth login` are still pending.

## Port status

| Function in Go program | Rust status |
| --- | --- |
| Public search, including visionOS discovery | Implemented, with offline unit tests |
| Public app lookup by ID or bundle identifier | Implemented, with offline unit tests |
| Latest public external version ID for non-macOS platforms | Implemented, with offline unit tests; iPhone live lookup checked |
| Shared HTTP request/response decoding and state directory migration | Implemented as library modules; account integration pending |
| Authentication URL bag, endpoint validation, 2FA and phone routing helpers | Implemented as library modules; SAP signing and login execution pending |
| FairPlay SINF, IPA SINF and enrollment model inspection | Implemented as library modules; decryption pending |
| `fairplay-doctor` host, capture, IPA and model checks | Implemented; current macOS host output compared with Go |
| Account inspection and revocation through macOS Keychain | Implemented with in-memory tests; existing real credentials not tested |
| Account login and other credential backends | Pending |
| Purchases, owned apps, version history and metadata | Pending |
| iOS and macOS package downloads and SINF replication | Pending |
| FairPlay enrollment, diagnostics and decryption | Pending |
| Store/SAP emulation and runtime profiles | Pending |
| MCP server and completion | Pending |

The Go source is about 88,000 lines including generated code and platform-specific implementations. The Rust port needs separate validation against the Go test suite and real account flows before it can claim feature parity. No account credentials or private enrollment material are embedded in this repository.

## Build and test

```sh
cargo build
cargo test
```

The upstream project is MIT licensed; see `LICENSE`.
