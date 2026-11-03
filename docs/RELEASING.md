# Releasing for macOS, Linux, and Windows

The 0.3.0 distribution targets are macOS ARM64, Linux x86_64, and Windows x86_64. Linux ARM64 and Windows ARM64 were published in v0.2.0 but are no longer release targets. Keep the CLI name `ipatool-rs` so it can coexist with the original `ipatool`. Do not publish account state, cookies, downloaded app packages, enrollment material, or credentials. Portable binaries are experimental until real account and package flows are checked on their target systems. Version 0.3.0 also distributes a native Apple Silicon desktop ZIP, separately from the CLI archives and Homebrew formula.

## Prepare and validate

1. Update the version in `Cargo.toml` and `Cargo.lock`, the release links in `README.md` and `web/index.html`, and the release limitations in `docs/TODO.md`.
2. Run `cargo fmt --check`, `cargo test --all-targets --quiet`, and `cargo clippy --all-targets -- -D warnings` locally. Require all five platform jobs in `.github/workflows/platform-ci.yml` to pass on the exact release tree, including the macOS application bundle and portable GUI fixtures. Run the GUI-test all-target suite and strict GUI/GUI-test Clippy for desktop changes. Clean CI runners omit 20 pinned Apple image tests that need a checked local cache; `scripts/test-portable.sh` names those skips explicitly.
3. Set `IPATOOL_CODESIGN_IDENTITY` to a local Developer ID Application identity and run `scripts/package-macos.sh`. The script rebuilds the ARM64 executable, signs it with the hardened runtime, `scripts/macos-release.entitlements`, and a secure timestamp, and creates a tarball, a SHA-256 file, and a ZIP for notarization under `dist/`. The two runtime entitlements allow the checksum-pinned Unicorn library from the user cache to load and execute its JIT code.
4. Check the archive with `shasum -a 256 -c dist/ipatool-rs-VERSION-macos-arm64.tar.gz.sha256`. Confirm it contains `LICENSE`, `NOTICE`, `licenses/LICENSE-DARKPHOENIX.txt`, and both checked files under `assets/fairplay-startup/`. These account-independent profiles are optional external copies of profiles already embedded in the executable; this package change applies to releases after `v0.1.0`. Extract it into a temporary directory, run `codesign --verify --strict` on `ipatool-rs`, verify both runtime entitlements with `codesign -d --entitlements -`, and exercise `--version` and a public catalog search. With a controlled account, run `list-purchases --platform macos --max-results 1` from the signed archive to catch dynamic-library or JIT signing failures before publication.
5. Submit the ZIP with `xcrun notarytool submit dist/ipatool-rs-VERSION-macos-arm64-notary.zip --keychain-profile PROFILE --wait`. Create the profile with `xcrun notarytool store-credentials PROFILE` and use its interactive credential prompts. Do not pass passwords in command arguments or commit them. Verify an accepted result and inspect the submission log for issues before publishing. The ZIP is only for notarization; attach the tarball and its checksum to the release. A standalone CLI executable cannot have the ticket stapled directly, so macOS retrieves its ticket online.

## Signed desktop package

1. Use the same clean source tree as the release CLI. Set the existing local
   `IPATOOL_CODESIGN_IDENTITY` and public `IPATOOL_AUTHORIZATION_TEAM`, then run
   `scripts/build-gui-macos.sh target/distribution/IPATOOL-RS.app`. The helper and
   GUI must share the configured Developer ID team. The bundle records its source
   commit, includes licenses and the fixed-input helper, and must not contain
   `LSEnvironment`, test state, captures, account packages or models.
2. Create an app-only notarization ZIP with
   `ditto -c -k --keepParent target/distribution/IPATOOL-RS.app target/distribution/desktop-notary.zip`.
   Submit it using the existing interactive Keychain notary profile. Require an
   accepted result with no issues, then run
   `xcrun stapler staple target/distribution/IPATOOL-RS.app`.
3. Run `scripts/package-gui-macos.sh target/distribution/IPATOOL-RS.app dist`.
   It verifies the version, architecture, absence of environment overrides,
   Developer ID signatures for both executables, stapled ticket and Gatekeeper
   before creating `ipatool-rs-VERSION-gui-macos-arm64.zip` and its checksum.
4. Extract the ZIP into a clean directory and repeat signature, stapler and
   Gatekeeper checks. Launch through the native desktop, exercise public browsing
   and FairPlay navigation, and confirm it does not silently register collection
   access. Keep controlled private-model acceptance separate from public captures.
5. Publish the ZIP and checksum alongside the signed CLI. Add or update
   `Casks/ipatool-rs-gui.rb` in `everettjf/homebrew-tap`, requiring Apple Silicon
   and macOS 12 or later. Protected collection requires macOS 13 or later.
   Install through the actual tap, repeat trust checks on the installed app,
   and preserve user state. Advise removing collection access in the app before
   uninstalling; do not add model deletion to cask uninstall or zap actions.

## Publish through CI

1. Merge the reviewed source, then tag that exact `main` commit with `vVERSION` and push the tag.
2. Create a draft GitHub release with release notes, the notarized macOS CLI tarball and stapled desktop ZIP, each with its SHA-256 file. State the tested targets and remaining live-validation gaps. The macOS notarization ZIP stays local.
3. Dispatch `.github/workflows/release.yml` with the tag. Native GitHub runners run tests, build Linux and Windows executables, exercise version and public-search smoke checks, and package two archives with SHA-256 files. A macOS runner verifies both staged signed archives, the desktop/helper signatures, architecture, version, lack of environment overrides, stapled ticket and Gatekeeper assessment. The final CI job uploads all portable assets and publishes the draft release. Check every job and every published checksum. Version `v0.1.0` was released before this CI workflow and contained only the macOS archive.
4. Update `everettjf/homebrew-tap` with `Formula/ipatool-rs.rb` pointing at the exact macOS release asset and its SHA-256 digest. Also update `Casks/ipatool-rs-gui.rb` with the desktop ZIP checksum. Run style and strict audits, CLI installation/upgrade and `brew test`, cask installation and installed-app trust checks.
5. Confirm the GitHub Pages install link and release links, and compare the Homebrew-installed binary version with the release tag.

Developer ID signing and notarization are release steps. The ordinary `scripts/build-macos.sh --arm64` development build remains ad hoc signed.

The first preview (`v0.1.0-preview.1`) passed signing, notarization, and public catalog checks, but its authenticated Store workflows failed at runtime because the hardened executable could not load the cached Unicorn library; a library-validation exception alone then exposed a JIT entitlement failure. `v0.1.0-preview.2` signs with both required exceptions and passed authenticated Store requests from the extracted signed archive. Always test a signed package with an account-backed emulator path before publishing. These checks do not validate real 2FA, expired-token recovery, or private FairPlay decryption.

The `v0.1.0-preview.3` archive passed checksum, contents, strict code-signature, entitlement, public catalog, and controlled-account purchase-history checks. The notarization service accepted submission `6762df5b-3e2a-425f-a04a-3e46775bc3ba` with zero issues; the executable in the archive matched the submitted ZIP payload byte for byte.

The requested `v0.1.0` archive passed the same checks. The notarization service accepted submission `f3c915cc-4d04-4e88-9d0f-e2127665c4a4` with zero issues. GitHub published it as the latest regular release with the archive and checksum. The Homebrew tap passed style, strict audit, installation, `brew test`, code-signature verification, and an account-backed request. GitHub Pages linked to the release after a successful deployment. Its release notes and README keep the outstanding live-validation gates explicit.

Version `v0.2.0` was published by the [release CI workflow](https://github.com/everettjf/ipatool-rs/actions/runs/40631088067) after all four native portable jobs, macOS archive verification, and four portable checksum checks succeeded. The signed macOS archive matched its notarization ZIP executable; submission `67827331-5eb0-42bb-9140-13a1c273a606` was accepted with no issues. The public release has five archives and five checksum files. The Homebrew tap upgraded and passed strict audit, `brew test`, signature verification, and public search. The platform-specific live account gaps remain in [TODO.md](TODO.md).

Version `v0.2.1` was published by the [release CI workflow](https://github.com/everettjf/ipatool-rs/actions/runs/40638453544) with two native x86_64 portable jobs and the macOS archive check. The public release has exactly three archives and three SHA-256 files; all three downloaded checksums passed. Apple notarization accepted the final macOS ZIP submission `ece034ff-f6b2-4777-a086-986974aded18` with no issues. The Homebrew tap upgraded to v0.2.1 and passed strict audit, `brew test`, signature verification, and public search. The account-backed Linux and Windows workflows remain untested.


Version `v0.3.0` adds the signed/notarized Apple Silicon desktop ZIP and Homebrew
cask to the three CLI archives. All five [main CI jobs](https://github.com/everettjf/ipatool-rs/actions/runs/41711635219)
passed on the tagged merge commit `9368505`. The [release workflow](https://github.com/everettjf/ipatool-rs/actions/runs/41715373642)
passed and published four archives and four checksum files, independently checked
after download. A first hosted ticket-service connection loss was resolved by
retrying only failed/dependent jobs while retaining every trust check. CLI
notarization `43c39097-bfb6-4d43-abe0-1790bdf53f80` and desktop notarization
`31f4b74e-6bf6-4260-9661-1cc85a98650f` were accepted with zero issues. The actual
Homebrew formula upgrade and cask installation passed strict audits, CLI tests,
byte identity, signatures, desktop stapler/Gatekeeper checks and native launch.
A controlled real model import was preserved across installation/relaunch without
re-enabling collection. The detailed [release record](PORTING.md#version-030-desktop-and-homebrew-release-2026-11-03)
keeps the account, accessibility and portable private-data limitations explicit.
