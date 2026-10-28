# FairPlay startup profile export design

## User workflow

Add an opt-in `--export-startup-profile` flag to `fairplay-enroll collect`. With the flag, collection should run an account-independent startup trace for the exact `fairplayd` arm64e slice and write `startup/profile.candidate.json.gz` inside the private capture directory. The capture manifest should record the candidate's relative path, binary hash, trace status, and validation result. The command should either finish with a verified candidate or fail with a specific unsupported-build or unmodeled-import diagnostic; it must never present a copied bundled profile as newly generated.

The CLI should not write directly into the source tree's `assets/fairplay-startup/`. Installed users may not have that tree, and a newly traced memory overlay requires review before distribution. `assets/fairplay-startup/` remains the maintainer-published location. A later explicit promotion step can add a reviewed candidate there.

## Generation boundary

Run startup tracing from the `fairplayd` image alone, before reading the app, SINF, IPA, hardware identity, or private state directories. Use fixed synthetic host values, and stop at the build's pre-request run-loop boundary. Reuse the Mach-O loader and external-call models in `src/fairplay_checkpoint_run.rs` where their startup semantics match; add a dedicated startup runner rather than trying to fabricate a request checkpoint from captured account files. A new build may need additional import models or a reviewed entry/stop address. On an unknown call or stop condition, fail closed and retain no candidate.

Export the existing `ipatool-fairplay-startup-cache-v1` fields only: `schema`, arm64e `binary_sha256`, sorted unique address/byte `memory`, and sorted unique `once_tokens`. Bound the memory and token counts, use deterministic gzip metadata, and atomically create the candidate with mode `0600` under a mode `0700` capture directory. A trace report can hold the exact build, input hash, entry address, stop reason, instruction count, and modeled import inventory without embedding account data or memory bytes.

## Validation and promotion

1. Re-run startup from a clean emulator with the same binary and compare canonical profile bytes. A third-party or local file must not be accepted as a trace result without this provenance.
2. For the two checked builds, regenerate profiles and compare their decoded memory and once-token maps with the existing embedded profiles. Record any difference and resolve it before enabling export for that build.
3. Verify the candidate schema, hash, address ordering and bounds, stop boundary, and absence of account or app inputs by construction. Treat any profile derived after request handling as private and ineligible for promotion.
4. Add support for a new build's request entry, external-call behavior, and recovery model separately. A startup profile alone does not make enrollment recovery or IPA decryption work on a new `fairplayd` build.
5. Only after review, copy a candidate to `assets/fairplay-startup/`, add its hash to regression tests, and update the supported-build registry and porting evidence. Do not commit the private capture directory or raw trace.

## Current code gaps

`src/fairplay_collect.rs` currently copies installed app, license, state, hardware, IPA, and exact `fairplayd` bytes into a private capture. It does not emulate daemon startup. `src/fairplay_startup.rs` consumes two embedded overlays and has request entry addresses only for their hashes. The reference project's startup tracer has build-specific entry and host-call behavior; its profile builder requires a pre-request checkpoint or trace cache. Porting that startup behavior to Rust and validating it are the main implementation tasks.
