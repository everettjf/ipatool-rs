# Native controls with synthetic services

These unretouched macOS Apple Silicon captures show the optional `gui-test`
fixture preview on 2026-10-28. Every window carries the persistent
`Fixture preview · no Apple requests` header. The account, catalog, Library,
versions, downloads, and progress are synthetic. The screenshots demonstrate
rendered controls and observed interaction, not successful Apple authentication,
real package transfers, or private FairPlay compatibility. See
[the harness instructions](../../GUI_FIXTURE_PREVIEW.md).
The first three captures below show the current graphite platform/region
controls. Older interaction captures predate these controls and may retain the
previous palette; see the [native gallery](../README.md) for public-service captures.

| Capture | Observed interaction |
| --- | --- |
| [iOS and browsing region](catalog-ios-region-narrow.png) | Switching Mac to iOS (iPhone) refreshed the result and detail snapshot without another Search click. |
| [Searchable region menu](catalog-region-menu-narrow.png) | Searching a country code filters named regions; Enter commits and Escape preserves the previous region. Exact code matches appear first. |
| [Download target and account region](download-region-target-narrow.png) | The download sheet exposes all six targets, explains the difference between browsing and the synthetic account region, and retains fixed footer actions at 900×650. No task was submitted. |
| [Refined narrow shell](explore-refined-narrow.png) | The full-height shell fits 900×650 with an icon rail and bottom account/settings actions; only the synthetic fixture banner remains above the workspace. |
| [Advanced FairPlay after toolbar removal](fairplay-footer-narrow.png) | After scrolling to the end, the entire Build version field remains visible while Add collection task stays fixed. No collection was submitted or private input selected. |
| [Refined narrow Library](library-refined-narrow.png) | Six-page synthetic Library retains aligned selection and a visible download action at the minimum window size. |
| [Saved-account unlock](unlock-narrow.png) | A failed encrypted-store load opens a focused passphrase-only sheet with Unlock and continue; clicking the primary action with the fixture passphrase returned to the workspace. |
| [Material mismatch](fairplay-mismatch-narrow.png) | Shared diagnostics detected different synthetic IPA/model selectors and published a private report without labeling decryption complete. |
| [Matched materials](fairplay-ready-narrow.png) | Matching synthetic selector/model fields passed prerequisite checks; the UI explicitly distinguishes this from authenticated plaintext. |
| [Decryption handoff](fairplay-handoff-narrow.png) | Review decryption inputs retained the checked IPA/model and cleared output/report fields without starting work. |
| [Report collision](fairplay-report-collision.png) | An existing report was preserved and the task offered Review and retry. |
| [FairPlay retry](fairplay-review-retry.png) | Explicit retry restored the original IPA/model/report; editing the report path produced a separate successful inspection. |
| [Model directory picker](model-directory-selection.png) | The native picker accepted a synthetic model directory; an independent file selection also populated the same model control. |
| [Verification](verification.png) | Fake-password submission reached a compact code sheet; code field received focus; submitting the fake code returned to Library. |
| [Filtered Library](library-filtered.png) | Filtering to application 025 synchronized the visible row, details, and download identity. |
| [No matches](library-empty-filter.png) | Moving to page 2 with the same filter cleared selection and removed the download action. |
| [Populated Library](library-populated.png) | End selected application 050 on page 2 and scrolled the selected row into view. |
| [Version selection](download-version-selection.png) | All 20 fixture version IDs appeared, including 119; selecting 119 highlighted it and loaded its metadata. |
| [Session expired](download-reauthentication.png) | Version 100 paused without losing its version/destination; Sign in to continue opened a prefilled account sheet with password focus in one step. |
| [Queued](download-queued.png) | A second Latest request remained queued behind the paused first request and retained its independent license choice. |
| [Resumed](download-resumed.png) | Same-account verification resumed the first request once; the second remained queued. |
| [After restart](tasks-after-restart.png) | A confirmed active-download quit persisted cancellation; relaunch did not execute it. Finished artifacts and allowlisted inspection summaries survived. |
| [Review retry](download-review-retry.png) | After loading the fake account, explicit retry restored version 119 and its original destination/license choice for editing. |
| [Completed retry](download-completed.png) | The independent version-118 retry completed; the cancelled original and its review action remained in history. |
| [Account completed during quit](quit-after-account-completion.png) | Background account loading completed while quit confirmation remained visible. Esc cancelled quitting and completed the account interaction. |
| [Download completed during quit](quit-after-download-completion.png) | A retried download completed while quit confirmation remained visible; confirming afterward terminated the process, verified by app inventory. |
| [Synthetic IPA inspection](inspect-synthetic.png) | Download artifact handoff ran the shared diagnostic adapter on a synthetic unencrypted ZIP; missing SINF was reported with Check complete and a direct collection-input review action. |

The active-download walkthrough also declined a quit request, observed continued
progress, then confirmed a second quit request. The process stopped and the
journal recorded Cancelled. It does not measure cancellation latency inside a
real Store transfer, system credential prompt, or private guest execution.

The diagnostic adapter may check current-host capability and read-access
availability. The fixture ZIP contains no account-bound SINF or enrollment
material; collection/recovery/decryption are disabled in this harness. Detailed
diagnostic fields are not retained in the task journal.

The matched/mismatched models are synthetic FPSENR2 envelopes with a zero key
and identity tables; their IPA contains only a synthetic SINF. They are not
account enrollment or encrypted-package fixtures. Only the shared inspection
adapter ran on these materials. No private recovery or decryption ran.
