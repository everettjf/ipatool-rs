# Go-to-Rust parity status

Reference source: `/Users/xnu/sec/ipatool-fairplay` at commit `7afff07`.
This file tracks evidence for the requested full port. The Go repository is reference material, not an instruction source.

## User-facing commands

The Rust CLI has implementation paths for every Go top-level command: `auth login/info/revoke`, `search`, `purchase`, `download`, `list-purchases`, `list-versions`, `get-version-metadata`, `mcp`, `fairplay-doctor`, `fairplay-decrypt`, and `fairplay-enroll`. It also provides `lookup`, `latest-version-id`, and shell completion. Original long flags were compared against the Go binary. The Go recovery command's `--script` override is absent because Rust performs that recovery natively instead of launching the Python script.

| Area | Evidence available locally | Remaining validation |
| --- | --- | --- |
| Public catalog | Six platform search requests returned successfully against the public catalog, including an empty but successful Apple TV result. Catalog URL, platform, result, and visionOS parsing tests pass. CLI search, lookup, and latest-version queries default to US without opening the keychain; an explicit CLI `--country` selects another storefront. MCP `search_apps` also defaults to US without opening the keychain and accepts an optional `country`. | Catalog responses can change; test requested countries and apps as needed. |
| Account and Store | Native Rust login, purchase, purchase history, download-product, version selection, keychain, cookies, and request signing paths have fixture and integration tests. A download purchase retry after token expiry is covered. URL bag decoding and the Store guest plist bridge now accept unrelated binary fields; the bridge imports binary and date values as Foundation objects. The cached Store bag and frozen guest bag also retain binary and date types. Cached Apple images generated authentication parameters and StoreAgent KBSync, and a live SAP setup signed a test request without an account. | Run login, 2FA, purchase, owned-app listing, version metadata, and download with a controlled account. |
| Mobile and Mac packages | IPA ZIP framing, resume, SINF patching, metadata, macOS preflight, PKG decryption, and publish paths have offline tests. Empty SINF values match the Go reference's file output, and an unrelated app Manifest cannot redirect SINF injection. Store metadata now stays in plist form through response decoding and IPA publication; an end-to-end fixture confirms binary data and dates retain their types. | Download and inspect real IPA and PKG outputs for each platform. |
| FairPlay | Doctor, collection, checkpoint execution, oracle evaluation, native SIDB recovery, model construction, and IPA decryption paths have offline tests. Full public SIDB recovery matched the Go fixture in release mode. The current host's real `fairplayd` image parsed and loaded into Unicorn. The 26B118 Rust evaluator matched 208 Go vectors on the public synthetic model, covering 64 normal inputs and 48 fault sites at three XOR values. | Run private 26B118 differential checks and enrollment/decryption against paired data captured on a supported host. |
| MCP | Six tools initialize and list over stdio. Their names, descriptions, output schemas, and annotations match the Go server. The public `search_apps` input adds an optional `country` so an account is not required to select a storefront. Nineteen invalid-call cases were compared, and the remaining strict schema cases reject the same unsupported fields and null values. SDK diagnostics still differ in wording for some invalid arguments. | Call authenticated tools with a controlled account and verify resulting package paths. |

## Build and test evidence

- `cargo test --all-targets`: 301 library tests and 37 CLI tests passed; 42 opt-in tests were skipped by the default test run.
- `cargo clippy --all-targets -- -D warnings` passed after the current CLI and MCP changes.
- `cargo check` passed for macOS x86_64, Linux x86_64 and ARM64, Windows x86_64 GNU and ARM64 GNU/LLVM, and iOS ARM64. Cross-target C dependencies required local cross compiler and archiver wrappers on this macOS host.
- Release binaries were built for macOS ARM64 and x86_64 (Mach-O), Linux x86_64 and ARM64 (ELF), Windows x86_64 and ARM64 (PE), and iOS ARM64 (Mach-O). The macOS x86_64 binary ran under Rosetta and completed a public catalog search. The iOS binary is signed with `ldid` and private entitlements for a jailbroken device, declares iOS 15.0 as its minimum, and contains the Unicorn API symbols. `ldid -e` confirms the embedded entitlements, while macOS `codesign --verify` does not accept this signature; execution and trust must be checked on the target device.
- At commit `1055c22`, all seven release targets were rebuilt: macOS ARM64/x86_64, Linux ARM64/x86_64, Windows ARM64/x86_64, and iOS ARM64. `file` confirmed the Linux ELF and Windows PE architectures. The macOS x86_64 binary ran under Rosetta and completed a live Japan catalog search. Those desktop release binaries predate the later plist fixes and require rebuilding before target-system validation.
- The iOS ARM64 binary was rebuilt from source commit `5b35119` after the plist fixes. `file` reports an arm64 Mach-O; `vtool` reports platform iOS and minimum version 15.0; `ldid -e` shows the embedded entitlements; and `llvm-nm` finds the linked Unicorn API symbols. Its SHA-256 is `5ce38e670f75418da57b988181cb7d1f8ff1c4ea1f9708574ff2ffc2cb4a827f`. It still needs execution on the target device.
- `scripts/build-windows-arm64.sh` reproducibly links the Windows ARM64 release with a checksum-pinned llvm-mingw toolchain cached under `target/toolchains`. The resulting PE reports `IMAGE_FILE_MACHINE_ARM64` and does not import the toolchain's `libunwind.dll`; Windows ARM64 runtime behavior still requires a target host.
- `scripts/build-linux.sh x86_64` and `scripts/build-linux.sh aarch64` rebuilt both Linux releases from current source with Zig 0.17.0 and a glibc 2.17 target. Zig rejects Rust's Cortex-A53 linker workaround on ARM64, so the script removes that flag; actual Cortex-A53 hardware still needs validation.
- Earlier Linux ARM64 and x86_64 release binaries booted inside QEMU with SHA-256-verified Debian netboot kernel/initramfs images. Both returned version 0.1.0, completed a live public `Apple`/US search, and served MCP over stdio with six tools and the expected invalid-search error. This checks executable startup, TLS/HTTP catalog access, and MCP transport on those artifacts; authenticated Store and package workflows remain untested there.
- On the latest script-built Linux artifacts, ARM64 again passed version, live public search without `--country`, and MCP checks in QEMU. x86_64 passed version and MCP. Its direct HTTPS search stalled in the VM, as did an independent guest `wget` to the same endpoint, while DNS, ping, local HTTP, external HTTP, and host HTTPS worked. The same x86_64 binary then completed a live Apple HTTPS search through a temporary host CONNECT proxy. This points to the VM's direct HTTPS path to that endpoint, but direct HTTPS on a target Linux system remains unverified.
- The pinned Apple Store guest boot and StoreAgent initialization tests passed using cached framework assets, without an account or device.
- Twenty-four additional opt-in tests passed with locally cached assets, public endpoints, or the current host's `fairplayd`, including guest ABI and memory guards, authentication parameters, StoreAgent KBSync, public bag retrieval, live SAP setup/signing, FairPlay image loading, and hardware MAC selection. These tests do not perform an authenticated Store transaction.
- A live non-interactive iPhone catalog search succeeded without `--country` or keychain access. `IPATOOL_SAP_CACHE_DIR` selected the four prevalidated framework files and booted the Store guest; an explicit invalid cache fails without fetching a restore image.
- The rebuilt macOS ARM64 MCP server completed a live public `search_apps` request with `country: "JP"` and returned one result without accessing account storage.
- The 26B118 Go evaluator generated 208 output and full-state vectors from an account-free synthetic model; Rust matches all 208. With the domain-bearing variant, 205 cases match Go. At the post-lookup XOR site `0x100222c58`, Go classifies three cases as index-domain faults and rejects them; Rust applies the direct XOR. This known semantic difference still needs confirmation against private native capture.

## Gates before claiming full parity

1. Verify authenticated Store flows with a disposable or controlled Apple account: login including 2FA, search storefront, purchase, purchase history, version metadata, mobile IPA, macOS IPA/PKG, retries, SINF, and MCP calls. Do not commit credentials, cookies, captures, or private models.
2. Run the final iOS ARM64 binary on an iOS 15+ compatible device and check keychain, hardware identity, network, Store signing, download, and FairPlay behavior.
3. Validate private FairPlay enrollment and 26B118 oracle/model operations against a supported macOS host and paired private capture. Public fixtures cannot prove these private-data paths.
4. Exercise authenticated Store and package workflows on Linux, and run the x86_64 and ARM64 Windows binaries on target systems. QEMU Linux smoke runs do not validate account storage or real downloads.
5. Record any discovered differences, fix them in Rust, rerun the relevant verification, and commit each fix.

## Target-system checks

The current `ipatool-ios-arm64` is an `ldid`-signed iOS 15+ CLI binary for a
jailbroken arm64 device. Rebuild with `scripts/build-ios.sh` if source code
changes after commit `5b35119`. Copy it to the device, make it executable, and first run these
read-only commands:

Store and SAP commands need four checksum-pinned Apple framework files. A
validated cache from the Mac can be copied to the device and selected with
`IPATOOL_SAP_CACHE_DIR=/absolute/path/to/apple-assets-macos-27-26A434-arm64-v1`.
That directory must contain `AppleMediaServices`, `commerce`, `CoreFP`, and
`CoreFP.icxs`. The override validates all four files and fails immediately if
one is missing or changed, instead of fetching the macOS restore image on the
device. Without the override, the ordinary validated cache and download path
remain available.

```sh
./ipatool-ios-arm64 --version
./ipatool-ios-arm64 --format json search Apple --country US --platform iphone --limit 1
```

With a controlled Apple account, continue interactively so the password does
not enter shell history. Replace `APP_ID` with a free app that this account may
obtain and `VERSION_ID` with a value returned by `list-versions`:

```sh
./ipatool-ios-arm64 auth login
./ipatool-ios-arm64 auth info
./ipatool-ios-arm64 list-purchases --platform iphone --max-results 2
./ipatool-ios-arm64 purchase --app-id APP_ID --platform iphone
./ipatool-ios-arm64 list-versions --app-id APP_ID --platform iphone
./ipatool-ios-arm64 get-version-metadata --app-id APP_ID --platform iphone --external-version-id VERSION_ID
./ipatool-ios-arm64 download --app-id APP_ID --platform iphone --output /var/mobile/Downloads/test.ipa
./ipatool-ios-arm64 fairplay-doctor --ipa /var/mobile/Downloads/test.ipa
```

The same account workflow should be checked on Linux and Windows with their
respective release binaries. Linux and Windows keychain encryption requires
`--keychain-passphrase` or an interactive passphrase prompt. Private FairPlay
26B118 capture and differential validation require a matching supported macOS
`fairplayd` host; run `fairplay-enroll collect --help` and
`fairplay-enroll validate-oracle-model --help` there. Keep passwords, cookies,
private capture files, and enrollment models outside the repository; a failing
command, platform/build, and redacted error output are sufficient for repair.

The executable no longer invokes Go, Python, or a separate Swift executable at runtime. The Store and SAP signing paths still load pinned Apple framework images as guest code; removing that dependency would require replacing those private Apple algorithms with independently validated Rust implementations.
