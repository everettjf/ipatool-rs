# Shared application and desktop validation matrix

Status: local implementation in progress, 2026-10-28. Keep this matrix aligned
with [the implementation plan](CLI_GUI_IMPLEMENTATION_PLAN.md). A test proves
only the behavior it exercises; fixture and public-catalog evidence do not close
account/private-data gates. All work remains on `codex/gpui-catalog` / PR #7.

## Architecture and compatibility

| Requirement | Current evidence | Remaining work |
| --- | --- | --- |
| Shared account, library, download, FairPlay services | `src/application/`; CLI and GUI call the shared functions directly. | Review complete diff and final CLI output/MCP contracts. |
| Default build does not depend on GPUI | Optional `gui` feature; separate GUI binary. Normal dependency graph excludes GPUI and its optional controller-test support dependencies. | Recheck if feature wiring changes. |
| Explicit credential configuration, compatible storage | Instance-scoped construction; encrypted-store wrong-unlock and revoke fixtures. | System Keychain interaction through signed app; portable credential UX. |
| Store request bytes unaffected by GUI features | Three pinned guest request comparisons passed after deterministic object serialization. | Include both complete feature configurations in final test run. |
| CLI replacement behavior preserved; GUI avoids overwrites | Desktop IPA and PKG collision fixtures passed. | Final queue/output interaction walkthrough. |
| Account/storefront ownership | Generation and external credential-replacement fixtures; typed account-change failure. | Verify refresh identity guard and reauthentication task continuation. |

## Interaction and recovery

| Requirement | Current evidence | Remaining work |
| --- | --- | --- |
| Four pages, stable primary actions | Actual Explore/FairPlay captures at normal and 900×650 sizes; native account error scrolling; rendered footer bounds tests. | Populated Library/task-state native walkthrough and final captures. |
| Public search, automatic/manual identity modes | Catalog recognition/override fixtures; 20-schedule stale-response/clear controller test; live Mac / US search returned 17 results at both window sizes. | Final keyboard/focus walkthrough. |
| Keyboard list selection and download entry | Native Down / Enter / cancel journey passed. | Tab traversal, focus restoration, new challenge field subscriptions. |
| Dark appearance and compact navigation | Scope narrowed to one dark theme at the user's request. Sidebar toggle uses a compact icon; navigation aligns left; recommendation copy is removed from the workspace. Historical light captures are not current supported behavior. | Signed release capture verifies the revised normal layout; latest 900×650 fixture captures verify compact navigation, Library, unlock and FairPlay. White primary-button text has approximately 5.17:1 contrast. |
| Login, verification, unlock, reauthentication | Shared protocol and GPUI fixtures; native fake-password/code focus/submit flow and same-account queue resumption passed. Code challenge cannot be replaced by Load saved account. | Dedicated native passphrase-only unlock and primary-action continuation passed with synthetic services; controlled-account live check remains last. |
| Library pagination/filter/offer and selection | Native six-page fixture: filter, next page with no matches, clear, Home/End selection and scroll passed. Native version 119 selection/metadata passed; all 20 IDs visible. Narrow footer test includes 200 version choices and an error. | Latest populated 900×650 Library capture passed; portable native interaction remains open. |
| Immutable queued request and bounded progress | Native version-100 pause followed by independent Latest enqueue; same-account continuation ran first once, cancellation acknowledged, second completed. Original version/license choices remained separate. | Real Store/package processing gate remains open. |
| Safe transfer cancellation | Stalled localhost body stopped in under two seconds; verified received bytes retained. | Recheck final build and account/package processing latency. |
| Verified download resume | Account/request/URL digest, file digest, ETag/Last-Modified, validated ranges; localhost fixtures passed. | Changed-total and final restart/retry UI checks. |
| Safe guest cancellation | Explicit opt-in synthetic active-guest test passed against pinned Unicorn. | No claim of arbitrary private guest cancellation coverage. |
| Safe processing/publication | Cooperative copy/hash/page/checkpoint loops; cancellation-aware ZIP writer; protected publication; destination collision tests. First-time range/FCS waits have stalled-header/body cancellation fixtures. Recovery fixtures passed 113 active tests; resource fixtures passed 27. | Real private processing remains a separate gate. |
| Durable task recovery | Interrupted/schema/privacy fixtures; native relaunch preserved cancelled and completed tasks without executing them. Explicit retry restored version 119, then a new version-118/license-opt-in task completed. | Native failed-inspection retry restored editable IPA/model/report parameters and completed with a new report path. Crash interruption remains fixture/controller evidence. |
| No secret state in task journal | Allowlisted failures; transient doctor details skipped; privacy fixture passed. | Review final screenshots/logs/files before staging. |
| Quit with active work | Native Command-Q/decline/continue/confirm stopped a fixture download and persisted Cancelled; inventory verified termination. Native account and download completion before confirmation preserved the prompt. Global lifecycle bindings work in modal focus. GPUI regressions cover deferred pending-download continuation and missing-worker race. | Native Library/version/revoke completion callbacks also preserved the quit prompt; declining after revoke closed stale account sheets. System credential prompts remain a live check. TestPlatform quit is a no-op. |
| Accessibility | Native AX exposes window chrome, not the custom controls. | Document upstream gap; do not claim screen-reader support. |

## FairPlay and delivery

| Requirement | Current evidence | Remaining work |
| --- | --- | --- |
| Inspect, collect, recover, model decryption | Shared application adapters; native forms and task results. | Mode-specific App/IPA/capture/file-output/directory-output regression passed. Native synthetic selector mismatch and matched prerequisites, report collision, explicit retry and decryption-input handoff passed. Real private processing remains open. |
| Private report and output preservation | Doctor reports now stage privately and publish without replacement; existing FairPlay tests passed. | Re-run final output/report rollback and collision fixtures. |
| Pickers/drop inputs and artifact handoff | Native path pickers, typed drop targets, completed IPA to inspection. | Native model file and directory selection passed. Checked IPA/model handoff to decryption review passed without starting work. Private capture processing remains open. |
| Expert command disposition | [GUI_FAIRPLAY.md](GUI_FAIRPLAY.md) inventories supported journeys, all retained expert CLI commands, combined download flags, and startup-profile exclusions. | Reconcile with final PR scope. |
| Native macOS bundle | Debug and release bundles built; Info.plist linted; strict ad hoc signatures passed; actual launch succeeded; application icon decoded natively. | Final debug/release rebuilds and strict signatures passed. Public release launch and native controls passed. Guest execution under the bundle identity still needs the controlled-account gate. |
| Release CLI | Apple Silicon release script built a signed executable returning 0.2.1. | Current source rebuilt; signed executable returns 0.2.1. |
| Portable desktop builds | Linux/Windows GUI build and fixture jobs added locally; Windows GNU x86_64 GUI cross-check, linked PE executable build, and strict all-targets Clippy passed on macOS. | Native Linux/Windows execution and interaction, MSVC release target, and Linux linking; execute CI after submission. Cross-build is not native execution evidence. |
| Complete local regression | Current default suite: 453 library + 45 CLI passed, 70 ignored. Current gui-test suite adds 31 passing GUI tests. Strict default, production-GUI, and gui-test all-targets Clippy passed. | Final-source Windows GNU GUI build and strict all-targets Clippy, macOS bundles, formatting and whitespace checks passed. Repeat affected checks if source changes. |
| Reviewable PR, no main merge | Existing branch and PR retained; shared workflows and desktop changes are recorded separately. | Publish the reviewed branch/update PR after local verification; keep remaining gates explicit and never merge main. |
| Final controlled-account/private gates | Not run through this desktop. | Ask for only the remaining authorized manual checks after all autonomous work. |
