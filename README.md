# ipatool-rs

This repository is a Rust port of the sibling `ipatool-fairplay` Go project. The port is **in progress**; it is not yet a replacement for the Go program.

## Working commands

```sh
cargo run -- search "notes" --country US --limit 5
cargo run -- --format json search "notes" --platform ipad
cargo run -- lookup --app-id 497799835
```

`search` supports iPhone, iPad, Apple TV, Apple Watch, visionOS and macOS platform aliases. It derives platforms from catalog metadata, filters Watch results, and uses the visionOS storefront when appropriate. `lookup` accepts an app ID or bundle identifier. These read-only commands use the public catalog; `--country` defaults to `US` until account storefront support is ported.

## Port status

| Function in Go program | Rust status |
| --- | --- |
| Public search, including visionOS discovery | Implemented, with offline unit tests |
| Public app lookup by ID or bundle identifier | Implemented, with offline unit tests |
| Account authentication, secure credential storage, session migration | Pending |
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
