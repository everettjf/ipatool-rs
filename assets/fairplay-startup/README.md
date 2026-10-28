# FairPlay startup profiles

These two compressed profiles contain deterministic, account-independent startup state for the checked `fairplayd` arm64e builds 26A428 and 26B118. The Rust executable embeds both files and selects one by the captured binary hash during `fairplay-enroll recover`. An explicit `--startup-profile` can override that selection.

`scripts/package-macos.sh` copies the files into the release archive under `assets/fairplay-startup/` for inspection or explicit use. They are not needed beside the executable for ordinary recovery.

Collection does not generate a new startup profile. It copies installed app and private FairPlay state, but it does not capture the daemon's pre-request startup memory. Do not derive a new profile from an account request checkpoint. A new build requires a validated pre-request startup checkpoint, exact-build startup emulation, and a review that excludes account identifiers, SINF, SIDB, SUPF, IPA data, hardware identifiers, credentials, and recovered keys before a profile is committed or distributed. The new build's request entry address and recovery model also need validation before the profile can be used.
