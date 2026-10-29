# Desktop FairPlay workflows and CLI disposition

The desktop exposes primary workflows through the shared Rust application
layer. It does not invoke the CLI or parse terminal output. This is experimental
exact-build research software; prerequisite checks do not authenticate plaintext.
For practical use, prefer the original ipatool and UnfairPlay projects.

## Primary journeys

The four numbered steps follow the user's material preparation order, not the
CLI command order. Existing materials allow direct entry to step 3 or 4; selecting
a step never starts work. Each step explains prerequisites, how to select inputs,
what is optional, and the output or next action. Primary actions and View results
stay in a fixed footer while the form scrolls at 900×650.

1. **Check files:** choose a downloaded IPA and any existing decryption model or
   collected materials folder. At least one input is required. A model is a
   FairPlay parameter file, not an AI model. Native pickers and single-item drops
   only populate inputs. Inspection does not decrypt the IPA. Report selection
   is under Advanced options; without a report path, detailed results are transient.
2. **Collect files:** choose the installed `.app`, an optional matching IPA, and
   a new materials output folder. An IPA alone is insufficient. The supported
   Mac must have readable local FairPlay data; the GUI cannot grant permissions.
   Host/build overrides stay under Advanced options. Keep collected files private.
3. **Create model:** choose the complete collected materials folder and a new
   output folder. Run step 1 if support is unknown. Any matching system files
   requested by diagnostics are selected under Advanced options. The phase
   timeout remains 1–3600 seconds and differential checks remain enabled.
4. **Decrypt IPA:** choose the downloaded IPA and matching model file or folder.
   A separate `.decrypted.ipa` and `.decrypted.json` are created by default.
   Existing files are preserved. An optional custom report path is advanced.

Results appear in Downloads. Inspection is labeled Check complete even when
requirements need attention; a successful IPA-only check explicitly says a model
is still needed. Check names, warnings, and common input errors are presented as
plain-language explanations. Raw protocol details are available under Show task
details. Finding a matching model prioritizes the decryption review action over
unnecessary collection. Inspection is not plaintext authentication.

Installed-application, IPA, materials-folder, decrypted-file, and output-folder
controls retain independent meanings when steps change. The inspection result
offers explicit step 2/3/4 input-review actions. Successful collection provides
Create decryption model; model output provides Use for decryption. These actions
populate forms without starting another task.

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
| `fairplay-doctor` | Check files and optional private report. |
| `fairplay-decrypt` | Step 4: decrypt with a checked model into new output/report paths. |
| `fairplay-enroll collect` | Step 2: collect files with explicit paths and supported overrides. |
| `fairplay-enroll recover` / `recover-capture` | Step 3: create a model with matching inputs and bounded phases. |
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
