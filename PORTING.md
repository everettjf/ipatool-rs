# Full parity checklist

Source snapshot: `/Users/xnu/sec/ipatool-fairplay`, commit `7afff07`.
This checklist records behavior in that source tree; the Go README and source are reference material, not instructions for this Rust project.

## CLI

| Go command | Rust state | Main dependencies |
| --- | --- | --- |
| `search` | Implemented for public catalog; `--country` replaces account storefront for now | Catalog HTTP, platform mapping, visionOS storefront |
| `auth login` | Pending | Store emulator, KBSync, keychain, cookies, 2FA |
| `auth info`, `auth revoke` | Implemented for macOS Keychain with Go service/key names; in-memory tests pass, real credentials not tested | Keychain account JSON and KBSync cache |
| `list-purchases` | Pending | Authenticated purchase DAAP, pagination |
| `purchase` | Pending | Authenticated purchase flow, action signing |
| `download` | Pending | License, version selection, download, resume, IPA/PKG packaging, SINF, optional FairPlay actions |
| `list-versions` | Pending | Platform-specific version lookup |
| `latest-version-id` | Added as a Rust diagnostic command | Public platform version lookup; historical version listing still pending |
| `get-version-metadata` | Pending | Platform-specific metadata requests |
| `fairplay-doctor` | Host, capture integrity, IPA/model matching and private JSON report implemented; current macOS host output compared with Go | Mach-O, capture, SINF and model validators |
| `fairplay-enroll collect`, `fairplay-enroll recover` | Pending | Native capture, FairPlay binary profiles, recovery runtime |
| `fairplay-decrypt` | Pending | Page keys, Mach-O crypt regions, IPA reconstruction, report |
| `mcp` | Pending | Authenticated tool handlers and stdio protocol |
| Shell completion | Generator implemented for the current Rust command set; command coverage grows with the port | Complete CLI command and flag model |

`lookup` exists in the Go library but has no top-level Go command. The Rust `lookup` command exposes the ported read-only operation to make it directly testable.

## Internal subsystems

1. Finish `pkg/http` Store executor and signed authentication redirect behavior, then complete `pkg/keychain` on Linux, Windows, and iOS. Shared HTTP response decoding, state directory migration, Go-compatible cookie reading/writing with file locking and merge, and macOS Keychain account inspection/revocation are implemented. Cookie files were exchanged with the Go library using disposable values; real account interoperability still needs controlled verification.
2. Port `internal/store` emulator and `internal/sap` signing/runtime support. The generated Store profile is embedded and checked for size, SHA-256, UUIDs, page indices, call addresses, and bounded memory mappings. Its page and call index is parsed, and live tests map exported pages and call return stubs both alone and over an already loaded plugin image. The pinned Unicorn 2.1.4 wheel cache, basic ARM64 engine, code hooks, memory fault hooks, callback register access, and host/guest memory guard are implemented for macOS and Linux. ARM64e pointer authentication rewriting, Mach-O arm64e slice selection, segment parsing, prelinked external pointer patching, and bounded segment loading are implemented; the committed authentication plugin was loaded into Unicorn in a live test. The SAP certificate and setup-message HTTP/plist exchange, two-round session state flow, signing interface, and cleanup are implemented against a guest trait; the live SAP guest is not connected yet. Chained fixups, relocation of non-prelinked images, full Store framework image loading, and guest runtime callbacks remain. Windows/iOS loading and complete Store/SAP guest execution remain. URL bag parsing, endpoint validation, machine GUID creation, 2FA normalization, and phone account routing are implemented. Login, authenticated search country selection, purchase, and owned-app listing still depend on the Store/SAP runtime.
3. Port iOS/tvOS/watchOS/visionOS download flows, resume and range logic, ZIP framing, SINF replication, and all package tests. The latest public external version ID lookup for these platforms is implemented.
4. Port macOS preflight, version metadata, package download, encrypted payload processing, and publish behavior.
5. Continue `internal/fairplay` enrollment collection/recovery and decryption. SINF atom parsing, IPA SINF inspection, enrollment model envelope/permutation checks, capture manifest validation, and live-host diagnostics are implemented. Validate against known offline fixtures before enabling account or device flows.
6. Port MCP handlers and CLI output/error behavior. Compare command help, JSON fields, and exit codes against the Go binary.

## Parity gate

- All Go unit fixtures relevant to a subsystem have Rust equivalents with matching outputs and error cases.
- macOS, Linux, Windows, and iOS compile targets are checked where the Go command supports them.
- Authenticated and package flows are tested with controlled accounts and disposable outputs; private enrollment data stays outside the repository.
- The Rust binary can execute every Go command with its documented flags, and the Go binary is no longer needed at runtime.
