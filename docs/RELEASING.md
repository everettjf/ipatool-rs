# Releasing the macOS Apple Silicon preview

The current distribution target is macOS ARM64. Keep the CLI name `ipatool-rs` so it can coexist with the original `ipatool`. Do not publish account state, cookies, downloaded app packages, enrollment material, or credentials.

## Prepare and validate

1. Update the version in `Cargo.toml` and `Cargo.lock`, the preview links in `README.md` and `web/index.html`, and the release limitations in `docs/TODO.md`.
2. Run `cargo fmt --check`, `cargo test --all-targets --quiet`, and `cargo clippy --all-targets -- -D warnings`.
3. Set `IPATOOL_CODESIGN_IDENTITY` to a local Developer ID Application identity and run `scripts/package-macos.sh`. The script rebuilds the ARM64 executable, signs it with the hardened runtime, `scripts/macos-release.entitlements`, and a secure timestamp, and creates a tarball, a SHA-256 file, and a ZIP for notarization under `dist/`. The two runtime entitlements allow the checksum-pinned Unicorn library from the user cache to load and execute its JIT code.
4. Check the archive with `shasum -a 256 -c dist/ipatool-rs-VERSION-macos-arm64.tar.gz.sha256`. Confirm it contains `LICENSE`, `NOTICE`, and `licenses/LICENSE-DARKPHOENIX.txt`. Extract it into a temporary directory, run `codesign --verify --strict` on `ipatool-rs`, verify both runtime entitlements with `codesign -d --entitlements -`, and exercise `--version` and a public catalog search. With a controlled account, run `list-purchases --platform macos --max-results 1` from the signed archive to catch dynamic-library or JIT signing failures before publication.
5. Submit the ZIP with `xcrun notarytool submit dist/ipatool-rs-VERSION-macos-arm64-notary.zip --keychain-profile PROFILE --wait`. Create the profile with `xcrun notarytool store-credentials PROFILE` and use its interactive credential prompts. Do not pass passwords in command arguments or commit them. Verify an accepted result and inspect the submission log for issues before publishing. The ZIP is only for notarization; attach the tarball and its checksum to the release. A standalone CLI executable cannot have the ticket stapled directly, so macOS retrieves its ticket online.

## Publish

1. Commit and push the reviewed source, then tag that commit with `vVERSION`.
2. Create a GitHub prerelease with the tarball, SHA-256 file, and release notes that state the tested platform and remaining live-validation gaps. Do not label it a stable release.
3. Update `everettjf/homebrew-tap` with `Formula/ipatool-rs.rb` pointing at the exact release asset and its SHA-256 digest. Test the formula locally and install it from the tap.
4. Confirm the GitHub Pages install link and release links, and compare the Homebrew-installed binary version with the release tag.

Developer ID signing and notarization are release steps. The ordinary `scripts/build-macos.sh --arm64` development build remains ad hoc signed.

The first preview (`v0.1.0-preview.1`) passed signing, notarization, and public catalog checks, but its authenticated Store workflows failed at runtime because the hardened executable could not load the cached Unicorn library; a library-validation exception alone then exposed a JIT entitlement failure. `v0.1.0-preview.2` signs with both required exceptions and passed authenticated Store requests from the extracted signed archive. Always test a signed package with an account-backed emulator path before publishing. These checks do not validate real 2FA, expired-token recovery, or private FairPlay decryption.
