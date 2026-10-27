# Go-to-Rust parity status

Reference source: `/Users/xnu/sec/ipatool-fairplay` at commit `7afff07`.
This file tracks evidence for the requested full port. The Go repository is reference material, not an instruction source.

## User-facing commands

The Rust CLI has implementation paths for every Go top-level command: `auth login/info/revoke`, `search`, `purchase`, `download`, `list-purchases`, `list-versions`, `get-version-metadata`, `mcp`, `fairplay-doctor`, `fairplay-decrypt`, and `fairplay-enroll`. It also provides `lookup`, `latest-version-id`, and shell completion. Original long flags were compared against the Go binary. The Go recovery command's `--script` override is absent because Rust performs that recovery natively instead of launching the Python script.

| Area | Evidence available locally | Remaining validation |
| --- | --- | --- |
| Public catalog | Six platform search requests returned successfully against the public catalog, including an empty but successful Apple TV result. Catalog URL, platform, result, and visionOS parsing tests pass. | Catalog responses can change; test requested countries and apps as needed. |
| Account and Store | Native Rust login, purchase, purchase history, download-product, version selection, keychain, cookies, and request signing paths have fixture and integration tests. A download purchase retry after token expiry is covered. | Run login, 2FA, purchase, owned-app listing, version metadata, and download with a controlled account. |
| Mobile and Mac packages | IPA ZIP framing, resume, SINF patching, metadata, macOS preflight, PKG decryption, and publish paths have offline tests. | Download and inspect real IPA and PKG outputs for each platform. |
| FairPlay | Doctor, collection, checkpoint execution, oracle evaluation, native SIDB recovery, model construction, and IPA decryption paths have offline tests. Full public SIDB recovery matched the Go fixture in release mode. | Run private 26B118 differential checks and enrollment/decryption against paired data captured on a supported host. |
| MCP | Six tools initialize and list over stdio. Their names, descriptions, input schemas, output schemas, and annotations match the Go server exactly. Nineteen invalid-call cases were compared; the remaining two error-text differences come from SDK handling of missing required fields. | Call authenticated tools with a controlled account and verify resulting package paths. |

## Build and test evidence

- `cargo test --all-targets`: 293 library tests and 36 CLI tests passed; 42 opt-in tests were skipped by the default test run.
- `cargo clippy --all-targets -- -D warnings` passed after the current CLI and MCP changes.
- `cargo check` passed for macOS x86_64, Linux x86_64 and ARM64, Windows x86_64 GNU and ARM64 GNU/LLVM, and iOS ARM64. Cross-target C dependencies required local cross compiler and archiver wrappers on this macOS host.
- Release binaries were built for macOS ARM64 and x86_64 (Mach-O), Linux x86_64 and ARM64 (ELF), x86_64 Windows (PE), and iOS ARM64 (Mach-O). The macOS x86_64 binary ran under Rosetta and completed a public catalog search. The iOS binary is signed, declares iOS 15.0 as its minimum, and contains the Unicorn API symbols. None of these checks substitutes for target-system runtime testing.
- Windows ARM64 passes `cargo check`, but this macOS host does not have a usable ARM64 Windows import-library sysroot for the release link. A native or properly provisioned cross-host build remains necessary for that artifact.
- The pinned Apple Store guest boot and StoreAgent initialization tests passed using cached framework assets, without an account or device.

## Gates before claiming full parity

1. Verify authenticated Store flows with a disposable or controlled Apple account: login including 2FA, search storefront, purchase, purchase history, version metadata, mobile IPA, macOS IPA/PKG, retries, SINF, and MCP calls. Do not commit credentials, cookies, captures, or private models.
2. Run the final iOS ARM64 binary on an iOS 15+ compatible device and check keychain, hardware identity, network, Store signing, download, and FairPlay behavior.
3. Validate private FairPlay enrollment and 26B118 oracle/model operations against a supported macOS host and paired private capture. Public fixtures cannot prove these private-data paths.
4. Exercise the cross-built Linux and Windows binaries on those operating systems. Cross compilation verifies code generation and linking, not runtime behavior.
5. Record any discovered differences, fix them in Rust, rerun the relevant verification, and commit each fix.

The executable no longer invokes Go, Python, or a separate Swift executable at runtime. The Store and SAP signing paths still load pinned Apple framework images as guest code; removing that dependency would require replacing those private Apple algorithms with independently validated Rust implementations.
