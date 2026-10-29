# Desktop FairPlay workflows and CLI disposition

The desktop exposes primary workflows through the shared Rust application
layer. It does not invoke the CLI or parse terminal output. This is experimental
exact-build research software; prerequisite checks do not authenticate plaintext.
For practical use, prefer the original ipatool and UnfairPlay projects.

## Primary journeys

The default page is **Decrypt IPAs**, with saved-model readiness, a persisted
Automatic decryption switch (on by default), and an optional existing IPA input.
Advanced output/report paths and expert tools are collapsed. Main actions and
View results stay in a fixed footer while the form scrolls at 900×650.

### Prepare once

**First-time preparation** follows the setup/reuse pattern in
[UnfairPlay](https://github.com/DrWhax/unfairplay#usage). A model is reusable
FairPlay authorization data, not an AI model or a separate model for each app.
Reuse follows an App Store enrollment; the same Apple ID alone does not prove
that an IPA and model belong together.

1. **Prepare this Mac:** sign in to the Mac App Store with the account that owns
   the IPA, install an offered iPhone/iPad app, and open it once. Download the same
   app/version's personalized IPA. Signing in only inside IPATOOL-RS does not
   prepare the Mac's authorization. Current recovery assumes a fresh account
   enrolled through this Mac's App Store; older/migrated profiles are unsupported,
   and a fresh account alone does not guarantee success. The system build and
   readable private authorization data must also be supported. The GUI does not
   grant permissions or elevate itself.
2. **Choose sample files:** select the installed `.app` and matching IPA. The app
   creates a private disposable working directory automatically. Under Advanced
   options, an existing selector-bound model can instead be imported with a
   matching IPA; import skips collection and does not require an installed app.
   System-image/profile/state overrides, interface, build/version and the
   1–3600-second phase timeout remain advanced.
3. **Review and prepare:** review the selected filenames and explicitly start.
   Fresh setup collects, recovers with differential checks enabled, validates the
   sample's processing report, and saves the model. Import runs the same sample
   processing/structure gate before saving. Merely changing steps never starts
   private work. A model without a binding selector is not eligible for managed
   reuse; the manual expert workflow remains available.

The sample gate requires processed encrypted images/pages, zero final cryptids,
exact mutation scope, plausible ARM64 first-page structure, and complete matching
embedded CodeDirectory page audits. It is conservative and can reject unsupported
samples. Passing it does **not** authenticate plaintext or Apple's signature.
Original inputs are preserved. Temporary captures and sample plaintext are
removed after normal completion, failure, or cooperative cancellation. A hard
process crash may leave hidden private staging directories; they are ignored,
never activated as models, and never replayed on restart.

### Download and reuse

Each new download captures the Automatic decryption preference when enqueued.
A successful IPA download queues an independent saved-model decryption task with
a parent link; duplicate completion delivery does not create another task.
PKGs and already decrypted results do not trigger it. Cancellation or quitting
suppresses the follow-up. Full task history explains how to retry manually.
Restart restores history for review without inventing or replaying operations.

The downloaded IPA remains a successful, separate artifact even if decryption
cannot run. No model, a different enrollment, ambiguous candidates, or invalid
storage produces an actionable failure. Missing/mismatched models offer
**Prepare reusable decryption**, with the IPA prefilled. Collection still requires
an explicit final review and start. Completed IPA downloads also offer **Decrypt
IPA...**, which opens automatic matching with stale model/output/report fields
cleared; it does not start another task. Missing files produce a notice.

Matching uses the IPA's SINF authorization selectors, not the account display
name or application title. Every selector must have exactly one validated saved
candidate. Default outputs are separate `.decrypted.ipa` and `.decrypted.json`
files beside the original. Existing files cause a stop, never replacement.
Custom paths stay under Advanced options. Results and reports appear in Downloads.

### Private saved models

Managed models live in `IPATOOL_STATE_DIR/fairplay-models/<model-sha256>/`.
Directories are mode 0700 and files 0600 on Unix. A model and bounded receipt are
published together from private staging. Reuse rechecks the envelope, SHA-256,
selector, receipt schema and permissions, and rejects symlinked/tampered entries
or conflicting models. Receipts record sample processing and structural validation;
they are not cryptographic attestations of plaintext. Model bytes, captures,
sample plaintext, and raw private errors are excluded from preferences/history;
reviewable request paths remain there.

Managed storage/reuse is disabled on Windows until equivalent private ACL support
is implemented. Unix storage is not evidence that collection/recovery works on
arbitrary Linux hosts or macOS builds. No private platform parity gate is closed.

### Expert tools

**Advanced tools** retains manual Check files, Collect files, Create model and
Choose model workflows plus access to the private model folder. Inspection explains
prerequisites and never decrypts an IPA. Raw diagnostic details are collapsed and
transient. Explicit output paths, file/directory pickers, artifact handoff and
editable retry remain available. Legacy manual recovery may retain private
intermediates in its explicitly selected output directory after cancellation;
use a new output or inspect it with the CLI checkpoint tools before continuation.

## Command disposition

This inventory was checked against Clap and the locally built CLI's help.
CLI-only entries remain available; their presence does not establish private
data or arbitrary-build parity.

| CLI entry | Desktop disposition |
| --- | --- |
| `fairplay-doctor` | Check files and optional private report. |
| `fairplay-decrypt` | Saved-model reuse by default; Choose model under Advanced tools retains explicit model decryption. |
| `fairplay-enroll collect` | One-time preparation internally; explicit collection under Advanced tools. |
| `fairplay-enroll recover` / `recover-capture` | One-time preparation internally; explicit model creation under Advanced tools. |
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
