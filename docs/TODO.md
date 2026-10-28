# Remaining work

Status as of 2026-10-27. The current delivery target is macOS on Apple Silicon. Detailed implementation history and test evidence are in [PORTING.md](PORTING.md).

Linux and Windows support is being explored on `codex/linux-windows-support`. Cross-builds are available for Linux ARM64/x86_64 and Windows ARM64/x86_64. The two Linux binaries passed account-free version and public-search smoke checks in Debian 13 QEMU guests. No Windows runtime was available locally. These targets have not been released.

## Verified so far

- Controlled-account login without a 2FA challenge, an already owned purchase, a new free-app purchase, purchase history, version metadata, and authenticated MCP `list_purchases` and `purchase_app`.
- Real native Mac PKG downloads, including ScriptWidget, with package and application inspection. ScriptWidget's Mac offer was a PKG.
- A compatible iPhone app's Mac offer: TouchLink downloaded as a valid IPA with a nonempty SINF on Apple Silicon. PhonePad's Mac offer was a PKG, while its iPhone offer downloaded as an IPA.
- The published `v0.1.0` Apple Silicon macOS archive is Developer ID signed and Apple notarization returned `Accepted` with zero issues. Its signed executable is byte-identical to the notarized ZIP payload and passed a public catalog search and controlled-account purchase-history request. The Homebrew tap fetched and installed the archive, passed style, strict audit, and `brew test`, retained a valid signature, and completed an account-backed purchase-history request. Preview.2 previously passed TouchLink version listing, version metadata, and IPA download. Preview.1's hardened runtime blocked the cached Unicorn library and its JIT; later versions include the two required runtime entitlements. The 0.1.0 release does not close the gates below.
- The macOS ARM64 release build and signature check, 421 active library tests, 45 CLI tests, and Clippy. Three affected pinned Store guest tests also passed explicitly. The 69 ignored library tests are opt-in checks, not a count of known failures.

## Current macOS Apple Silicon gates

- [ ] Complete an interactive default macOS Keychain approval flow for `auth login` and `auth revoke` in a local user session. `auth info` succeeded after the user approved its Keychain dialog on October 27; the encrypted `--file-keychain` path also worked.
- [ ] Complete an actual 2FA challenge during account login. The controlled-account logins did not trigger one.
- [ ] Resolve the live Store token rejection and verify successful expired-token recovery in purchase and download flows. An earlier October 27 MCP download triggered refresh but still returned `password token is expired` afterward; the later signed preview.2 CLI download succeeded with a valid saved account, which does not establish expired-token recovery. Fixture retry tests pass.
- [ ] Verify successful authenticated MCP `list_app_versions`, `get_version_metadata`, and `download_app` outputs with a controlled account. `list_purchases` and `purchase_app` passed. In a later isolated run, version requests returned Apple's generic metadata error for multiple apps, and downloads for TouchLink and PhonePad failed after session refresh.
- [ ] Validate private FairPlay enrollment and real IPA decryption with matched device, app, SINF, and private enrollment data on a supported macOS host. The current unprivileged process cannot read the required private FairPlay state.
- [ ] Add build-specific, account-independent pre-request `fairplayd` startup tracing and candidate profile generation to the FairPlay collection workflow. `collect` currently has only application and private state files, which cannot reconstruct a new startup overlay. Validate a new profile's binary hash, deterministic memory, once tokens, and absence of private data before placing it in `assets/fairplay-startup`; then validate the new build's request entry and recovery model. Copying the two embedded profiles into a release archive does not satisfy this gate.
- [ ] If matched 26B118 private data becomes available, compare its oracle/model results with the Go reference. Public synthetic vectors already matched; they do not establish private-data parity.
- [ ] Determine whether the remaining live Store workflows reach the Swift preawaited continuation flag rejected by the current Go and Rust guests; implement and verify immediate suspension only if one does.
- [ ] Investigate Air Sketch Free's repeated HTTP 403 download-product responses after a successful free purchase, and ScriptWidget's intermittent 403 responses if they recur. Earlier successful TouchLink and PhonePad downloads show the 403 was not a universal account failure at that time; its cause remains unproven.
- [ ] Fix any differences found in the above checks, rerun focused and full verification, and update this list and [PORTING.md](PORTING.md).

Do not commit credentials, cookies, downloaded packages, private captures, or enrollment models. Use an isolated state directory for live account tests.

## Linux and Windows investigation

- [x] Cross-build Linux ARM64/x86_64 and Windows ARM64/x86_64; add a repeatable Windows x86_64 build script.
- [x] Run account-free version and public-search smoke checks for both Linux architectures in Debian 13 QEMU guests.
- [ ] Run Windows x86_64 and ARM64 binaries on their target systems and verify public catalog behavior.
- [ ] Validate real authenticated Store, account migration, and package workflows in Linux desktop sessions and on Windows. Existing Linux QEMU and synthetic Secret Service checks do not cover a real account.
- [ ] Decide whether to package Linux/Windows builds only after the target runtime checks and release limitations are reviewed.

## Deferred targets and package offers

- [ ] Validate the final iOS ARM64 binary on a compatible device, including authenticated Store and package flows.
- [ ] Resume macOS x86_64 release and runtime verification.
- [ ] Inspect real IPA and PKG outputs for the remaining platform offers, beyond the TouchLink Mac IPA and Mac PKGs already checked.
