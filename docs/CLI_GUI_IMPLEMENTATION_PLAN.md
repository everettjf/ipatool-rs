# CLI and GPUI implementation plan

Status: implementation and local validation in progress, 2026-10-28.
Checkboxes record implemented and locally verified work; each milestone's exit
evidence remains a separate acceptance gate. Current validation is recorded in
`docs/PORTING.md` and `docs/GUI_TEST_MATRIX.md`; fixture evidence does not establish
live account, private FairPlay, or portable desktop completion.

Continue on `codex/gpui-catalog` and PR #7. The immediate objective is a shared
Rust application layer supporting a compatible CLI and a usable GPUI desktop
application. Publishing a Rust package is deferred.

The project remains an experimental Rust rewrite created to use otherwise-unused
Codex quota and test a substantial port. Recommend the original ipatool and
UnfairPlay projects for practical use. GUI integration does not establish full
protocol, platform, or FairPlay parity.

## Scope decisions

- Keep the existing Cargo package, library, CLI binary, and optional GUI binary.
  Do not introduce a workspace, new public package name, or SDK stability promise.
- Reuse native Rust catalog, Store, package, and FairPlay implementations. Do not
  wrap CLI commands, parse terminal output, or introduce a Swift runtime helper.
- Preserve CLI flags, defaults, output contracts, and Go-compatible behavior.
  Preserve MCP schemas and non-interactive behavior when shared workflows move.
- Deliver the complete desktop experience on macOS Apple Silicon first. Preserve
  existing Linux x86_64 and Windows x86_64 CLI checks. GUI validation on those
  hosts is a separate gate; other deferred targets remain deferred.
- Include login, 2FA handling, credential unlock, account information and revoke,
  purchased applications, versions, free licenses, IPA/PKG downloads, task
  recovery, FairPlay diagnostics, collection, capture recovery, and model-based
  decryption. Keep expert FairPlay commands available in the CLI while adding
  the supported desktop workflows; do not represent every research flag as a
  required desktop control.
- Defer package publication, multiple simultaneous accounts, paid-app checkout,
  automatic startup-profile generation, and unrestricted task concurrency.
- The current desktop targets one dark theme. Keep navigation compact with
  left-aligned icon/label columns, an icon-only sidebar toggle, and no project
  recommendation copy in the primary workspace. Account/settings/sidebar controls
  belong at the bottom of navigation, without a separate top toolbar. Narrow
  windows use an icon rail. Project positioning stays in the README and documentation.

## Current implementation anchors

| Existing location | Reuse or extraction required |
| --- | --- |
| `src/lib.rs` | Add an application-layer entry point without reorganizing all existing low-level modules. |
| `src/main.rs` | Extract login orchestration, app resolution, download retry, capture handling, and optional FairPlay post-processing. Keep argument parsing, prompts, formatting, and exit behavior in the CLI. |
| `src/mcp.rs` | Reuse shared operations as relevant while retaining existing schemas, error envelopes, and retry policy. |
| `src/gui/main.rs`, `src/gui/catalog.rs` | Split the current catalog-only view into a shell, pages, account interaction, and task presentation. Move reusable query validation to the application layer. |
| `src/credentials.rs`, `src/file_keychain.rs` | Add explicitly configured store construction/unlock without GUI terminal prompts. Preserve existing CLI initialization and stored item compatibility. |
| `src/catalog.rs`, `src/store_owned.rs`, `src/store_login.rs`, `src/store_purchase.rs`, `src/store_download_product.rs` | Reuse protocol operations; allow shared state and credential dependencies to be supplied instead of silently reopening global defaults. |
| `src/download_file.rs`, `src/mac_package.rs`, `src/ipa_patch.rs` | Propagate progress and cancellation through transfers, package processing, and final publication. |
| `src/fairplay.rs`, `src/fairplay_collect.rs`, `src/fairplay_recover_capture.rs`, `src/fairplay_ipa.rs` | Adapt existing diagnostics and processing to structured jobs; retain build matching, private input checks, and output safeguards. |

## Shared application boundary

Add a focused `src/application/` module. Proposed files are responsibilities,
not a requirement to add empty scaffolding before the first usable operation:

- `context.rs`: state directory, credential provider, transport/backend
  construction, front-end interaction policy, and operation ownership.
- `account.rs`: saved-account status, login attempts and challenges, unlock,
  reauthentication, and revoke.
- `catalog.rs`: search, app identity resolution, platform and storefront checks.
- `library.rs`: purchase history, version identifiers, and version metadata.
- `download.rs`: license policy, bounded retries, transfer and package workflow,
  output selection rules, and optional follow-on FairPlay operations.
- `fairplay.rs`: diagnose, collect, recover, and decrypt adapters.
- `operation.rs`: operation identity, progress events, cancellation, outcomes,
  artifacts, and actionable errors.

Use concrete request/result types at this boundary. Add provider interfaces only
for dependencies that need substitution, such as credential storage and fixture
backends. Keep implementation helpers private; these interfaces can evolve as
the CLI and GUI exercise them.

Application operations must not read stdin, print progress, open a GPUI dialog,
write directly to the clipboard, or terminate the process. Front ends own those
actions. Keep synchronous protocol code initially and execute it on bounded
background workers. Do not require an unrelated async rewrite.

Separate common mechanisms from front-end policy. In particular, extraction must
not silently make CLI download retries and MCP account retries identical when
their existing contracts differ. Tests must preserve their existing limits and
failure behavior.

### Credentials and interactive continuation

The GUI receives a non-secret account summary, never a serializable `Account`.
Distinguish no saved account, locked store, saved-but-unverified account,
authenticated operation, expired session, and access denied.

Use an explicit credential provider shared by account and Store clients. The
current process-global `OnceLock` configuration cannot be treated as a mutable
GUI settings model. Preserve existing store formats and default selection. A
storage change must not silently migrate or delete credentials.

Represent a required verification code, file-store passphrase, or re-login as an
operation that needs input. Keep only the minimum continuation state in memory,
with cancellation and expiration. Never persist passwords or challenge codes in
task records. Do not park a worker or hold a guest-execution lock while waiting
for someone to type. Reserve the account operation so conflicting mutations
cannot proceed during a challenge.

Keep the current CLI prompt and non-interactive adapters. MCP must return its
existing actionable failure instead of opening a window or prompting on stdin.
Audit password control undo/history behavior and clear transient secret buffers;
a masked text field alone does not meet this requirement.

### Jobs, progress, and cancellation

Each operation has an ID and an immutable request snapshot. Snapshot application,
version, offer platform, storefront, output locations, and account generation;
editing UI controls must not change a running operation.

Use explicit states: queued, running, awaiting input, cancellation requested,
cancelled, succeeded, failed, and interrupted. Ignore obsolete search responses
using request IDs. Search can supersede an earlier query without waiting for its
blocking request to stop.

Events describe stages, completed/total bytes or units when available, artifact
availability, and actionable errors. Coalesce progress updates rather than
allowing an unbounded event queue. Unknown totals use stage/activity indicators;
do not invent percentages or estimated completion times.

Cancellation must reach transfer reads, package loops, and bounded FairPlay
execution. Provide bounded I/O waits and describe the observed cancellation
latency. Show cancellation requested until the worker acknowledges a safe stop.
Do not cancel in the middle of final output publication or claim that hiding a
view stopped the work. Retain existing temporary-file and rollback guarantees.

Initially run one account/Store job and one heavy FairPlay job at a time, subject
to any shared guest-runtime exclusion required by the implementation. Public
catalog browsing remains independent. Verify runtime/thread assumptions before
allowing overlapping guest execution. If testing demonstrates process-fatal
guest faults, use an isolated worker mode of the same Rust executable; do not
introduce an external language runtime.

Persist a minimal, versioned task journal: safe request metadata, stage,
timestamps, outcome, and artifact paths. Never persist credentials, signed URLs,
cookies, secret continuation state, or raw protocol responses. On restart, mark
unfinished jobs interrupted and offer explicit retry after revalidating inputs.
Do not restart account-changing or private-data operations automatically.

Resume downloads only when application/version/offer identity and server range
validation still match. Restart safely when partial-file identity is uncertain.
Do not expose Pause until retained transfer state and resumption are validated.

## Desktop structure and journeys

Use four primary pages: Explore, Library, Downloads, and FairPlay. Keep account
status and its action in the top-level shell. Settings hold non-secret
preferences such as default output directory and last-used catalog filters.
Use resizable list/detail regions and a collapsible navigation pane. Narrow
windows automatically use an icon rail with navigation, account and settings
actions. Keep primary actions visible without scrolling the metadata panel.
All product strings remain English.

### Explore and application details

- Provide one search field with clear scope, clear action, and manual mode
  override. Numeric ID and bundle-identifier recognition is a convenience that
  can be corrected, not an irreversible guess.
- Keep platform and searchable country controls compact. Remember the last
  selection; initial offer-platform behavior remains consistent with the CLI.
- Once an account is loaded or signed in, default browsing to its storefront.
  Apply that default again if the account identity or storefront changes. Keep
  manual region switching available, preserve an override during same-account
  refresh, and show a persistent cross-region download warning with an explicit
  return-to-account-region action. Preserve any pending download's original
  application/region snapshot when login changes the browsing default.
- Allow editing while loading. Retain appropriate prior results and expose the
  new query's loading state without showing obsolete results as current.
- Display the selected application's identity, version, supported offers, and
  primary Download action above the fold. Place JSON and CLI-copy actions in a
  secondary menu. Only show price with reliable currency information.
- Check availability in the account storefront before a Store operation when
  public browsing used a different country. Do not equate search country with
  the authenticated account's storefront.

### Account

- Browsing does not require login. Download and Library offer an in-context
  login sheet and return to the pending action after success.
- Show Apple ID/password, necessary storage information, preparation stages,
  verification-code continuation, and distinct field/access errors.
- Explain system Keychain interaction before the expected OS prompt. File-store
  unlock uses a GUI secret input rather than a terminal passphrase prompt.
- Keep operation parameters when reauthentication is needed. Do not retry
  account-changing actions indefinitely or lose duplicate-license handling.
- Revoke is local credential removal with an accurate explanation of its scope.
  Resolve active account jobs before logout/account replacement.

### Library and download

- List purchased applications with pagination, filtering, and preserved
  selection. Version metadata failures leave a usable latest-version option
  and manual external-version-ID entry where the backend supports it.
- A download sheet shows application, account storefront, offer platform,
  version, and destination. Use native file/directory pickers.
- When a free license is required, present an explicit acquire-and-download
  action. Catalog price alone is not an entitlement or pricing authority.
- Actual Store metadata determines IPA versus PKG output. Do not promise an IPA
  from every macOS offer or allow IPA-only post-processing on a PKG.
- Downloads shows queued/running/failed/completed jobs, real progress,
  cancellation acknowledgement, retry, and artifact reveal actions. A transfer
  reaching 100 percent is not success until patching/publication completes.
- A completed IPA can enter FairPlay with its path prefilled. Download success
  remains visible even if an optional later FairPlay operation fails.

### FairPlay

Provide three guided entries: Inspect materials, Decrypt with an existing model,
and Collect/recover enrollment. Accept appropriate drag-and-drop inputs and
native file selection. Carry outputs from one step to the next.

Map the doctor report into passed/missing/incompatible/unsupported checks and
specific next actions. A ready report means prerequisite checks passed; it is
not evidence that decryption already succeeded or that arbitrary builds work.

Show exact-build requirements and permissions before collection. Handle denied
private-state access without launching the entire GUI as root. Existing capture
recovery must remain usable when fresh collection is unavailable.

Default to a new decrypted IPA and a report, preserving the original. Validate
input/model compatibility and destination collisions before a long run. Keep
supported recovery selection, timeouts, and expert inputs discoverable without
exposing hidden research paths as ordinary supported options. Report actual
completed stages and output verification, not just worker termination.

Inventory the remaining checkpoint/model-building CLI commands and document their
desktop disposition. They remain CLI-accessible in this delivery; a complete
graphical research console is not required for the primary FairPlay workflow.
The unimplemented startup-candidate exporter in draft PR #6 is not a dependency.

## Implementation sequence

Each milestone ends with a runnable CLI and GUI. Use small, reviewable commits
on the current branch; add tests for new behavioral contracts, not layout-only
snapshots that merely mirror implementation.

### M0: Baseline and interaction specification

- [x] Record current CLI/MCP compatibility checks and current GUI limitations.
- [x] Specify the four page layouts, fixed primary actions, account sheet,
  download sheet, and FairPlay step layouts before adding more controls.
- [x] Enumerate loading, empty, awaiting-input, failed, cancelled, and completed
  states, and the recovery action for each expected error category.
- [x] Exercise keyboard focus and the pinned GPUI accessibility capabilities
  early. Record what requires upstream/platform work instead of postponing it.

Exit evidence: page/state specification and clearly labeled design mockups,
plus a test matrix linked to the existing parity gates.

### M1: Extract account and download workflows for the CLI

- [x] Introduce application context and explicit credential construction.
- [x] Extract login/challenge handling, app resolution, license policy, retry,
  and result composition without changing CLI output or prompt behavior.
- [x] Add an operation event/cancellation contract and CLI progress adapter.
- [x] Preserve MCP contracts when redirecting overlapping helpers.

Exit evidence: existing CLI/MCP contracts pass; fixture-backed workflow tests
cover login challenge continuation, refresh limits, missing/owned licenses, and
credential-store failures. No GUI dependency enters the default CLI graph.

### M2: Deliver the first complete GUI login/download journey

- [x] Replace the single catalog view with the shell and reusable detail view.
- [x] Add account status, login/2FA/unlock sheets, and pending-action resumption.
- [x] Add download destination/version selection and one real background task.
- [x] Wire progress, typed failure/recovery, cancellation, and reveal output.
- [x] Validate single-account ownership and runtime isolation assumptions.

Exit evidence: search -> select -> login if needed -> download -> reveal output
is usable without a terminal. Fixtures exercise every challenge/failure branch;
authorized live testing records exactly which account-backed paths ran.

### M3: Library, versions, and durable task recovery

- [x] Add purchase-history pagination and version/metadata operations.
- [x] Add free-license acquisition, account-storefront availability checks, and
  safe duplicate task/output handling.
- [x] Add the task journal, interrupted-state recovery, validated partial-file
  resumption, bounded progress updates, and explicit retry.

Exit evidence: IPA and PKG paths preserve correct outcomes; network interruption,
missing entitlement, expired session, denied output, and application restart do
not lose task context or mislabel incomplete output as successful.

### M4: FairPlay application adapters and desktop workflows

- [x] Extract diagnostics/collect/recover/decrypt orchestration used by the CLI.
- [x] Propagate stage events, safe cancellation, artifact results, and errors.
- [x] Add material checks, model decryption, and collection/recovery pages.
- [x] Connect completed IPA tasks to the appropriate FairPlay entry point.
- [x] Inventory expert CLI commands and document exclusions accurately.

Exit evidence: synthetic fixtures prove compatible/mismatched material handling,
unsupported builds, output collision protection, interrupted work, and verified
output/report publication. Private live end-to-end gates remain open until
authorized matched inputs are available and actually pass.

### M5: Desktop interaction and visual verification

- [ ] Complete keyboard navigation, focus restoration, accessible names,
  selection behavior, clear actions, and shortcut/menu handling.
- [x] Check the dark theme, contrast, window resizing, dense content,
  long identifiers/paths, and large purchased-app/result lists.
- [x] Separate persistent task errors, inline validation, and short copy/success
  notices; add concise recovery actions and redacted technical details.
- [x] Verify close-window/quit behavior for active jobs and cancellation.

Keyboard traversal, primary-button activation, modal focus restoration and
shortcuts now have native walkthrough evidence. The first item remains open
because pinned GPUI does not expose custom controls through macOS AX; keyboard
success does not establish accessible names or screen-reader support.

Exit evidence: observed end-to-end task walkthroughs and screenshots of the
actual implemented states, with accessibility gaps explicitly recorded.

### M6: Packaging, CI, and final evidence

- [x] Add a repeatable macOS application-bundle build with necessary resources.
- [ ] Verify Finder launch and credential behavior for the bundle's identity.
- [ ] Validate existing guest/JIT entitlements and signing requirements when
  preparing a distributable GUI. Local ad hoc signing is not notarization.
- [x] Extend GUI CI beyond catalog validation to fixture-backed workflows.
- [x] Build/check the GUI on Linux x86_64 and Windows x86_64, recording desktop
  and account checks separately. Keep unverified support labeled experimental.
- [x] Update README, PORTING, TODO, and PR #7 around the actual final scope.

Exit evidence: reproducible macOS bundle, current CI results, local verification
record, screenshots, and an accurate list of unverified live/platform gates.
Public release publication and Rust package publication are separate actions.

## FairPlay completion workstream (2026-11-01)

This is an implementation plan, not a record of completed recovery. The native
desktop walkthrough reached collection with a matching installed-app/IPA
selection. Its compatibility check could read the IPA and identify a bundled
host recovery profile, but could not read the local FairPlay state. No real
model recovery or plaintext validation has passed through this desktop.

The newer upstream comparison is pinned to
[UnfairPlay b3a7a432da2047a0d4f1ed5a3152c538a5497183](https://github.com/DrWhax/unfairplay/tree/b3a7a432da2047a0d4f1ed5a3152c538a5497183).
It supplements, rather than silently replaces, the sibling Go port baseline.
Its production recovery parses the current SIDB format and authenticates the
selected enrollment route without executing a native image. Its decryption
checks available CodeDirectory pre-encryption hashes. Rust currently uses
exact-build checkpoint recovery and encrypted-source page audits plus structural
plausibility checks. These are material differences, not missing GUI labels.

### F1: Make collection possible and failures actionable

- Preflight installed-app identity/version, sample IPA, readable authorization
  state and recovery prerequisites before starting expensive recovery. Distinguish
  unreadable state, missing enrollment, mismatched sample, unsupported format,
  denied authorization and recovery failure using typed, redacted errors.
- Separate "IPA readable", "host profile recognized", "collection permitted"
  and "model validated" in diagnostics. Recognizing an image hash must not be
  presented as proof that this enrollment can be recovered.
- Add a macOS authorization design and packaging spike for a narrowly scoped
  native helper, using supported Service Management APIs. The normal GUI must
  remain unprivileged. Before shipping, prove helper registration, peer/code
  identity checks, user approval, denial, cancellation and removal with the
  actual signed bundle. An ad hoc debug launch is not distribution evidence.
- The privileged boundary may read only the required system authorization
  inputs. Do not accept arbitrary privileged source paths, shell commands or
  output paths. Validate the requesting process, bound input sizes, reject
  symlinks and races, and deliver a private snapshot to the requesting user.
  Recovery, IPA processing and model publication run as that user. Never grant
  the entire GUI root privileges or make system state world-readable.
- Keep terminal-based explicit collection/import available as a diagnostic
  fallback; it does not close the terminal-free desktop gate. Administrator
  authentication stays in macOS UI and cannot be supplied through chat.

Exit evidence: the authorized desktop creates a readable private snapshot;
denial and interruption leave no usable partial capture or root-owned model.
No model-generation claim follows merely from successful collection.

### F2: Port current recovery into the shared Rust service

- Implement bounded canonical capture normalization, current SIDB container and
  state derivation, deterministic slot/root/tagged-tree selection, selected-value
  authentication, and selector-bound model construction from the pinned source.
- Use native Rust implementations and reviewed public algorithm constants.
  Do not invoke a downloaded Go binary, Python script or separate Swift runtime.
  Keep the existing exact-build recovery as an explicitly selected legacy path;
  do not retry unrelated slots, records or legacy engines after authentication
  failure in the current path.
- Treat support as format/route support after parsing and authentication. Unknown
  versions and malformed routes fail closed. Remove the blanket fresh-account
  prerequisite only when the replacement path and relevant controls pass;
  do not promise every older or migrated enrollment will work.
- Expose bounded progress and cooperative cancellation through the existing
  operation service. CLI and GUI call the same normalizer/recovery service.

Exit evidence: public differential vectors agree with the pinned Go reference;
an authorized local capture recovers and validates a model without native guest
execution. Raw captures, selectors, hardware identities and model hashes stay
in private local evidence, never in public PR logs.

### F3: Validate decrypted bytes and report coverage honestly

- Audit every available CodeDirectory pre-encryption hash slot intersecting each
  encrypted range. A malformed present table or any mismatch rejects publication,
  including a wrong final page after a plausible first page.
- Keep encrypted-source integrity checks separate from plaintext checks. Do not
  use instruction plausibility or clearing cryptid as proof of correct plaintext.
- Preserve an explicit "validation unavailable" result for older executables
  without pre-encryption tables; never label them plaintext-verified. Embedded
  hash consistency does not establish Apple CMS signature trust.
- Cover all encrypted images in the IPA, including extensions and frameworks;
  audit license association and page-table selection against upstream. Classify
  unsupported architectures or SUPF/SUPP variants explicitly rather than silently
  omitting images. Older 32-bit/watch layouts need their own controls before a
  broad parity claim.
- Version the decryption report and model receipt validation policy. Keep older
  receipts visibly structure-checked until revalidated; do not silently upgrade
  their assurance or reinterpret their existing fields.

Exit evidence: first-page/final-page corruption, malformed tables and ambiguous
license associations fail; valid synthetic outputs and normalized reports agree
with the pinned reference. Missing coverage remains visible in CLI and GUI.

### F4: Finish the one-time setup and reuse journey

- The primary flow is: check this Mac, obtain required macOS authorization,
  select matching installed app and IPA, prepare and validate, save privately.
  Keep model paths, build overrides and raw diagnostics under advanced tools.
- Publish a model only after selected-license authentication and complete sample
  processing with applicable validation. Save assurance/coverage separately from
  the fact that recovery completed. Preserve the original IPA on every outcome.
- After relaunch, downloaded IPAs match saved models by enrollment selector.
  Reuse is per enrollment, not per app name or visible Apple ID. A new or
  unmatched enrollment offers preparation without modifying existing models.
- Downloads remain successful if their independent decryption task fails.
  Provide distinct "downloaded", "decrypted and verified", "decrypted with
  validation unavailable" and actionable failure states. Resolve output collisions
  without redownloading or overwriting the original.
- Cancellation and relaunch must not replay authorization requests, repeat a
  completed child task, or activate an incomplete model. Clean private temporary
  work on normal failure/cancellation and define crash cleanup explicitly.

### F5: Real acceptance and PR delivery

Run the required Rust/default/GUI/gui-test suites and strict Clippy, rebuild the
CLI and signed GUI, and exercise the native normal/narrow layouts. Then use the
already authorized controlled account and private local materials:

1. From no saved model, complete collection, recovery, sample processing and
   private publication on this Mac. Record each stage separately.
2. Quit and relaunch. Download a different IPA from the same enrollment and
   confirm automatic model selection and decryption without another model picker.
3. Check every encrypted image and all available plaintext hash coverage. At
   least one real control with complete pre-encryption coverage must pass before
   claiming verified plaintext. If neither supplied app provides it, report that
   specific remaining gate rather than assuming success.
4. Exercise wrong enrollment, denied authorization, output collision, cancellation
   and restart; preserve original packages and existing valid models throughout.
5. Compare real outputs with the pinned reference only in private local evidence.
   Publish a redacted outcome, not app identities, private file measurements or
   captured data. Update README, PORTING, TODO and PR #7 on the same branch;
   do not merge or publish a release as part of this workstream.

macOS Apple Silicon is the first live completion target. Linux x86_64 model
reuse needs separate runtime evidence. Windows managed recovery/decryption
remains gated on equivalent private-file ACL enforcement. Passing this Mac's
controls does not establish universal enrollment or cross-platform parity.

## Verification and evidence

For Rust changes run `cargo fmt --check`, focused behavioral tests,
`cargo test --all-targets --quiet`, and
`cargo clippy --all-targets -- -D warnings`. Also exercise the GUI feature with
focused workflow/view tests and `cargo clippy --features gui --all-targets -- -D warnings`.
Run `scripts/build-macos.sh --arm64` when validating the release CLI, and the
new bundle build when validating the desktop artifact. Preserve existing
portable CI and MCP protocol checks.

Use deterministic providers/localhost fixtures for the default test suite.
Cover challenge state, bounded retries, account-generation changes, stale search
completion, output collisions, partial transfer identity, cancellation at each
safe boundary, and task-journal recovery. Do not make ordinary tests depend on
an Apple account or private files.

Account-backed tests require an authorized controlled account and isolated
`IPATOOL_STATE_DIR`; private FairPlay tests additionally require matched,
authorized materials. Never print or commit passwords, cookies, tokens, private
captures, enrollment models, or downloaded account packages. Use mock/redacted
data for login screenshots and redact diagnostic exports.

Capture implemented Explore/detail, login and 2FA, Library, transfer progress,
recoverable failure, completed output, FairPlay mismatch/ready/processing/report,
and narrow/normal dark layouts. Label mockups, simulated states, and real runs
separately. Keep screenshots and their state descriptions in the PR evidence;
they do not substitute for behavioral tests.

## Completion criteria

The delivery is complete when both CLI and GUI use the shared workflows, the
desktop supports the primary account/download/FairPlay journeys without terminal
interaction, cancellation and recovery have tested semantics, and the default
CLI/MCP contracts still pass. A successfully drawn page or a simulated happy path
does not satisfy a live-validation gate. Remaining accessibility, platform, and
private-data limitations must be visible in the evidence and product where they
affect an operation.

No Rust package publication, workspace split, new automatic startup-profile
generation, or broad claim of parity is required to finish this delivery.
