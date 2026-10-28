# Remaining work

Status as of 2026-10-27. The current delivery target is macOS on Apple Silicon. Detailed implementation history and test evidence are in [PORTING.md](PORTING.md).

## Verified so far

- Controlled-account login without a 2FA challenge, an already owned purchase, a new free-app purchase, purchase history, version metadata, and authenticated MCP `list_purchases` and `purchase_app`.
- Real native Mac PKG downloads, including ScriptWidget, with package and application inspection. ScriptWidget's Mac offer was a PKG.
- A compatible iPhone app's Mac offer: TouchLink downloaded as a valid IPA with a nonempty SINF on Apple Silicon. PhonePad's Mac offer was a PKG, while its iPhone offer downloaded as an IPA.
- The `v0.1.0-preview.1` Apple Silicon macOS prerelease is Developer ID signed and Apple notarization returned `Accepted` with zero issues. Its SHA-256 archive and `everettjf/tap/ipatool-rs` Homebrew formula passed local install, test, and public catalog checks.
- The macOS ARM64 release build and signature check, 421 active library tests, 45 CLI tests, and Clippy. Three affected pinned Store guest tests also passed explicitly. The 69 ignored library tests are opt-in checks, not a count of known failures.

## Current macOS Apple Silicon gates

- [ ] Complete an interactive default macOS Keychain approval flow for `auth login`, `auth info`, and `auth revoke` in a local user session. The unattended run could only confirm that `--non-interactive` returns an actionable authorization error; the encrypted `--file-keychain` path worked.
- [ ] Complete an actual 2FA challenge during account login. The controlled-account logins did not trigger one.
- [ ] Resolve the live Store token rejection and verify successful expired-token recovery in purchase and download flows. An October 27 MCP download triggered refresh but still returned `password token is expired` afterward; fixture retry tests pass.
- [ ] Verify successful authenticated MCP `list_app_versions`, `get_version_metadata`, and `download_app` outputs with a controlled account. `list_purchases` and `purchase_app` passed. In a later isolated run, version requests returned Apple's generic metadata error for multiple apps, and downloads for TouchLink and PhonePad failed after session refresh.
- [ ] Validate private FairPlay enrollment and real IPA decryption with matched device, app, SINF, and private enrollment data on a supported macOS host. The current unprivileged process cannot read the required private FairPlay state.
- [ ] If matched 26B118 private data becomes available, compare its oracle/model results with the Go reference. Public synthetic vectors already matched; they do not establish private-data parity.
- [ ] Determine whether the remaining live Store workflows reach the Swift preawaited continuation flag rejected by the current Go and Rust guests; implement and verify immediate suspension only if one does.
- [ ] Investigate Air Sketch Free's repeated HTTP 403 download-product responses after a successful free purchase, and ScriptWidget's intermittent 403 responses if they recur. Earlier successful TouchLink and PhonePad downloads show the 403 was not a universal account failure at that time; its cause remains unproven.
- [ ] Fix any differences found in the above checks, rerun focused and full verification, and update this list and [PORTING.md](PORTING.md).

Do not commit credentials, cookies, downloaded packages, private captures, or enrollment models. Use an isolated state directory for live account tests.

## Deferred until those targets are requested

- [ ] Validate the final iOS ARM64 binary on a compatible device, including authenticated Store and package flows.
- [ ] Resume macOS x86_64 release and runtime verification.
- [ ] Validate real authenticated Store, account migration, and package workflows in Linux desktop sessions. Existing QEMU and synthetic Secret Service checks do not cover a real account.
- [ ] Run Windows x86_64 and ARM64 binaries on their target systems and validate account and package workflows.
- [ ] Inspect real IPA and PKG outputs for the remaining platform offers, beyond the TouchLink Mac IPA and Mac PKGs already checked.
