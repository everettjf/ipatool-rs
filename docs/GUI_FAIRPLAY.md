# Desktop FairPlay workflows and CLI disposition

The desktop exposes primary workflows through the shared Rust application
layer. It does not invoke the CLI or parse terminal output. This is experimental
exact-build research software; prerequisite checks do not authenticate plaintext.
For practical use, prefer the original ipatool and UnfairPlay projects.

## Primary journeys

1. **Inspect materials:** choose an IPA, model, or capture. Native pickers and
   single-file/directory drops populate inputs without starting work. Results
   and actionable errors appear in Downloads. Detailed diagnostic data is
   transient unless an explicit private report path was selected.
2. **Decrypt with model:** use an existing matching model. Default output is a
   separate `.decrypted.ipa` and JSON report; existing files are preserved.
3. **Collect enrollment:** select an installed application and matching host
   material. Collection requires authorized access to private state and does
   not elevate the GUI. Hardware/interface and build overrides are advanced
   controls. Captures must remain private.
4. **Recover capture:** select a supported capture and any required matching
   compatibility/startup/IOKit material. Phase timeout is 1–3600 seconds;
   differential checks remain enabled.

Installed-application, IPA, capture-directory, decrypted-file, and capture/recovery
output-directory controls retain independent meanings when modes change. The
inspection result offers explicit collection/recovery/decryption input-review
actions. A completed inspection is labeled Check complete, including when
prerequisites need attention.

Completed IPA, capture, and model artifacts can populate the next appropriate
form. Handoff does not start another operation. Output fields are reset for
review. Retry restores editable parameters; interrupted jobs never auto-start.
Cancelled recovery may leave private intermediate files inside the selected
output directory. Choose a new directory or inspect them through the expert
checkpoint commands before attempting continuation.

## Command disposition

This inventory was checked against Clap and the locally built CLI's help.
CLI-only entries remain available; their presence does not establish private
data or arbitrary-build parity.

| CLI entry | Desktop disposition |
| --- | --- |
| `fairplay-doctor` | Inspect materials and optional private report. |
| `fairplay-decrypt` | Decrypt with a checked model into new output/report paths. |
| `fairplay-enroll collect` | Collect enrollment with explicit paths and supported overrides. |
| `fairplay-enroll recover` / `recover-capture` | Guided capture recovery with matching inputs and bounded phases. |
| `recover-from-account`, `recover-from-sinf-copy` | CLI-only expert checkpoint entry points. |
| `seed-request-checkpoint`, `continue-checkpoint` | CLI-only checkpoint preparation and execution. |
| `export-oracle-model`, `learn-index-domains`, `validate-oracle-model` | CLI-only oracle research and differential analysis; guided recovery retains its required internal checks. |
| `evaluate-state`, `evaluate-frame`, `evaluate-whitebox`, `raw-source` | CLI-only state/frame/kernel evaluation. |
| `recover-state`, `recover-state-checkpoints`, `recover-oracle`, `recover-whitebox` | CLI-only recovery primitives. |
| `build-model`, `build-model-v2-checkpoints`, `build-model-v3`, `build-model-v3-checkpoints` | CLI-only model construction/conversion primitives. |
| Download `--fairplay-capture-dir` and combined download/decrypt flags | CLI-only advanced download options; the ordinary GUI keeps download and subsequent FairPlay processing as separate tasks. Saved advanced request fields are retained during retry. |
| Force, native 26B118 research, skipped differential checks | CLI-only expert policy; the primary GUI retains conservative build/output checks. |
| Startup-candidate exporter in draft PR #6 | Separate unimplemented project gate, not a dependency of this delivery. |

Authorized live account and private recovery/decryption checks remain open.
Synthetic fixtures and UI captures do not close them. See
[GUI_TEST_MATRIX.md](GUI_TEST_MATRIX.md), [PORTING.md](PORTING.md), and
[TODO.md](TODO.md).
