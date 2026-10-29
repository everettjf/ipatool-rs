# Shared application and desktop validation matrix

Status: final local and CI validation, 2026-10-28. Keep this matrix aligned
with [the implementation plan](CLI_GUI_IMPLEMENTATION_PLAN.md). A test proves
only the behavior it exercises; fixture and public-catalog evidence do not close
account/private-data gates. All work remains on `codex/gpui-catalog` / PR #7.

## Architecture and compatibility

| Requirement | Current evidence | Remaining work |
| --- | --- | --- |
| Shared account, library, download, FairPlay services | `src/application/`; CLI and GUI call shared functions directly. Current CLI retry/output/parser and MCP schema/error fixtures pass; MCP retains its own retry policy. | Live CLI/GUI account comparison remains a controlled-account gate. |
| Default build does not depend on GPUI | Optional `gui` feature; separate GUI binary. Final locked normal dependency graph excludes GPUI and its optional controller-test support dependencies. | Recheck if feature wiring changes. |
| Explicit credential configuration, compatible storage | Instance-scoped construction; encrypted-store wrong-unlock and revoke fixtures. | System Keychain interaction through signed app; portable credential UX. |
| Store request bytes unaffected by GUI features | Three pinned guest request comparisons pass in both final default and GUI-test suites after deterministic object serialization. | Private Store operation under the signed bundle identity remains open. |
| CLI replacement behavior preserved; GUI avoids overwrites | Desktop IPA and PKG collision fixtures pass. Native synthetic queue/cancellation/completion and inspection-report collision/retry passed. | Real IPA/PKG output verification remains a live gate. |
| Account/storefront ownership | Generation, external credential-replacement and refresh-identity fixtures pass. Native same-account reauthentication resumed the original queue once. | Controlled-account storefront and expired-session checks. |

## Interaction and recovery

| Requirement | Current evidence | Remaining work |
| --- | --- | --- |
| Four pages, stable primary actions | Actual normal/narrow captures; populated Library and task-state native fixture walkthroughs; rendered account/download/FairPlay/detail footer bounds tests. | Native portable desktop interaction and private processing remain separate gates. |
| Public search, automatic/manual identity modes | Catalog recognition/override fixtures; 20-schedule stale-response/clear and rapid platform/region refresh controller tests. Public Mac / US searches and the rebuilt signed CLI iOS / US lookup passed. Native 900×650 fixtures verified region name/code search, exact code priority, Enter/Escape, account-region browsing, and platform-triggered refresh without another Search click. | No remaining account-free search gate identified. |
| Keyboard list selection and download entry | Native Down/Enter/cancel passed. Final signed release verified Tab/Shift-Tab, Enter on mode/download/Cancel buttons, restored download-button focus, Command-F, Command-Comma, Escape and Command-W. Challenge subscriptions/focus and secret-input replacement pass controller tests and native synthetic walkthroughs. | Full screen-reader support remains an upstream gap; portable keyboard interaction is unverified. |
| Dark appearance and compact navigation | One neutral graphite palette and a full-height workspace, without a top toolbar. Sidebar/dialog surfaces are brighter than the content, selections and hover states are gray, and primary actions/focus retain blue. Account/settings/sidebar controls are anchored at the bottom of navigation; narrow/collapsed windows retain a 56-point icon rail with tooltips. Native signed-release search, empty account/settings sheets, FairPlay navigation and collapse/restore passed. White primary-button text has approximately 5.65:1 contrast; secondary text on selected rows has 4.95:1. | Historical light, blue-tinted dark captures and earlier toolbar layouts are superseded; platform rendering remains a separate gate. The GPUI palette is an opaque approximation, not native dynamic AppKit material. |
| Login, verification, unlock, reauthentication | Shared protocol and GPUI fixtures; native fake-password/code focus/submit flow and same-account queue resumption passed. Code challenge cannot be replaced by Load saved account. | Dedicated native passphrase-only unlock and primary-action continuation passed with synthetic services; controlled-account live check remains last. |
| Library pagination/filter/offer and selection | Native six-page fixture: filter, next page with no matches, clear, Home/End selection and scroll passed. Native version 119 selection/metadata passed; all 20 IDs visible. Narrow footer test includes 200 version choices and an error. | Latest populated 900×650 Library capture passed; portable native interaction remains open. |
| Download platform and account region | Initial login/load and changed identity/storefront select the account region and refresh results. Same-account refresh preserves an explicit override. Cross-region catalog and download warnings explain possible download failure; the catalog provides a return action. Login retains a pending download's original source-region snapshot. Download sheets expose all six targets; changing target clears prior version IDs/metadata while retaining the output. The queued request uses the reviewed platform. Account-region catalog preflight errors retain only a validated region code, without private error context. Native narrow screenshots show browsing/account-region differences and the fixed footer. | Real Store availability/entitlement and successful package transfer remain live gates. |
| Immutable queued request and bounded progress | Native version-100 pause followed by independent Latest enqueue; same-account continuation ran first once, cancellation acknowledged, second completed. Original version/license choices remained separate. | Real Store/package processing gate remains open. |
| Safe transfer cancellation | Stalled localhost body stopped in under two seconds; verified received bytes retained. | Recheck final build and account/package processing latency. |
| Verified download resume | Account/request/URL and file digests, ETag/Last-Modified and validated ranges pass localhost fixtures, including changed-validator/total rejection before partial bytes are overwritten. Native synthetic restart/retry preserved editable request choices. | Real Store URLs and server validators remain a live gate; synthetic UI downloads do not exercise HTTP resumption. |
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
| Private report and output preservation | Doctor reports stage privately and publish without replacement. Final full suites include output/report rollback/collision fixtures. Native synthetic report collision preserved the file; edited-path retry succeeded and reports had mode 0600. | Private processing outputs still require matched live inputs. |
| Pickers/drop inputs and artifact handoff | Native path pickers, typed drop targets, completed IPA to inspection. | Native model file and directory selection passed. Checked IPA/model handoff to decryption review passed without starting work. Private capture processing remains open. |
| Expert command disposition | [GUI_FAIRPLAY.md](GUI_FAIRPLAY.md) inventories supported journeys, all retained expert CLI commands, combined download flags, and startup-profile exclusions. | Reconcile with final PR scope. |
| Native macOS bundle | Debug and release bundles built; Info.plist linted; strict ad hoc signatures passed; actual launch succeeded; application icon decoded natively. | Final debug/release rebuilds and strict signatures passed. Public release launch and native controls passed. Guest execution under the bundle identity still needs the controlled-account gate. |
| Release CLI | Apple Silicon release script built a signed executable returning 0.2.1. | Current source rebuilt; signed executable returns 0.2.1. |
| Portable desktop builds | Native Linux x86_64 and Windows MSVC x86_64 CI passed shared fixtures, deterministic GUI controllers, strict Clippy and GUI linking. macOS CI also passed its app-bundle build/signature checks. Windows GNU GUI cross-build and strict all-targets Clippy passed locally. See the exact run in PORTING. | Native Linux/Windows desktop and account interaction remain open. GUI CI builds are debug executables; GUI distribution/release packaging is separate. |
| Complete local regression | Current default suite: 454 library + 45 CLI passed, 70 ignored. Current gui-test suite adds 39 passing desktop tests, including account-region defaults, preserved overrides, platform/region refresh, region search/cancellation, target/version reset and narrow layout. Strict default, production-GUI, and gui-test all-targets Clippy passed; debug/release signed bundles rebuilt. The earlier graphite source passed Windows GNU linking/Clippy. Runtime source `db63141` passed [all five native CI jobs](https://github.com/everettjf/ipatool-rs/actions/runs/40811697728), including all 36 desktop tests on each GUI host. That run predates the subsequent account-first default/warning revision; its new CI is tracked separately in PR #7. | Native desktop interaction, account checks and distribution remain distinct gates. Formatting and whitespace checks passed. Repeat affected checks if source changes. |
| Reviewable PR, no main merge | Reviewed changes and current native screenshot pushed to `codex/gpui-catalog` / PR #7 after local verification. Shared workflows and desktop changes are recorded separately. | Keep remaining gates explicit; never merge main in this task. |
| Final controlled-account/private gates | User manual testing reached a signed-in account and reported catalog-preflight misses. Public-only diagnosis reproduced the relevant region difference; no authenticated package transfer or private FairPlay success has been reported. | Continue only the remaining authorized manual checks after autonomous verification. User-reported sign-in does not close live 2FA, entitlement, package, or private processing gates. |

## Final controlled-account checks

These are the remaining manual gates, not evidence of completed live validation.
Use a controlled account and the native production GUI with a private state and
output directory. Select **Use encrypted file storage** before sign-in to keep
test credentials in that directory. A state-directory override does not isolate
the system Keychain's existing shared ipatool service; test that storage option
separately and only with the user's authorization. Enter secrets directly in the
GUI, never in a command, screenshot, PR, or test report.

1. Start from a public result's **Sign in to download...** action. Complete login
   and any actual verification challenge; confirm the pending app/offer survives.
   If Apple does not request 2FA, leave the live 2FA gate open.
2. Browse a purchased app and its versions. Download an already owned IPA and a
   Mac offer that actually returns a PKG into new paths. Check artifact identity,
   completion, reveal, cancellation acknowledgement, and explicit retry. Do not
   infer package type from the public catalog or use a paid checkout.
3. Quit/relaunch, load the encrypted saved account, try an incorrect passphrase,
   then unlock correctly. Confirm task history remains usable and no interrupted
   job starts automatically. Test real expired-session continuation only when a
   genuine expiration can be observed; synthetic coverage does not close it.
4. In a separately authorized system-Keychain check, verify the signed bundle's
   OS approval, account access and local credential removal. Removal affects the
   shared saved credentials; it is not an Apple server-session revocation.
5. With authorized exact-build app/SINF/capture/model materials, inspect, collect
   or recover, and decrypt into new outputs/reports. Verify resulting content and
   report permissions. Record denied private-state access or unsupported builds
   accurately; do not run the entire GUI as root or treat a prerequisite check as
   successful decryption.

Report only the affected step, non-secret error title and observed outcome.
Keep credentials, downloaded account packages, captures, models and detailed
private reports outside Git and public issue/PR attachments. Native Linux and
Windows desktop interaction and screen-reader support remain distinct platform
gates; they are not established by the macOS walkthrough above.

## Guided FairPlay follow-up

The four steps now explain preparation, optional versus required inputs, outputs,
and explicit result handoff. Native normal/narrow fixture captures are in the
[screenshot gallery](screenshots/fixtures/README.md). The 900×650 controller test
checks both footer actions in all four steps and proves step/results navigation
and an empty-input check do not enqueue private work. Readiness presentation tests
distinguish IPA-only inspection, matched models, and requirements needing attention.
A synthetic IPA without authorization data also exercised the shared diagnostic adapter: the result explained the missing data, kept technical details collapsed, and opened step 2 without collecting private files. Restarted history explained that detailed diagnostics are transient.
Final local checks passed 454 library + 45 CLI + 39 desktop tests, strict Clippy
for default/GUI/GUI-test, formatting, and signed GUI debug/release builds.

Run 40819067700 for the previous account-region revision passed four jobs and
failed only the Windows account-region fixture's missing backend setup. That
fixture now selects the synthetic backend explicitly. This does not change the
production Windows encrypted-store default; new CI must verify the correction.
Private processing and distribution gates remain open.
