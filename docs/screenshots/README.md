# Native desktop captures

These are actual, unretouched captures of the locally built GPUI application on
macOS Apple Silicon on 2026-10-28. The top-level images below use native services
for public browsing and empty-form validation. The separate
[fixture captures](fixtures/README.md) show the same native controls with
explicitly synthetic account, Library, version, and download services. They are
not live account evidence. The refined dark and collapsed captures show the
current `🦀IPATOOL-RS 🦀` native title and neutral graphite palette. The refined dark capture is the current
visual reference. Earlier images are
historical interaction evidence and may show superseded controls. Light/system
themes are no longer supported; subsequent interaction changes require refreshing
affected captures.

| Capture | Observed state | Evidence limit |
| --- | --- | --- |
| [Explore, refined dark](explore-refined-dark.png) | Signed release app with neutral gray content, brighter sidebar, gray selections and blue primary actions; no top toolbar. Full-height details and 17 real public Mac / US results. | Public browsing only; no account operation. |
| [Collapsed sidebar](explore-footer-collapsed.png) | The same signed release app retains navigation, account, settings and expand controls in a narrow icon rail. | Public browsing and empty account/settings sheets only; no account request. |
| [Sign in, graphite](sign-in-graphite.png) | The current neutral gray dialog is raised above the content, with inset inputs and a blue primary action. | Empty fields; no authentication request or credential access. |
| [FairPlay, graphite](fairplay-graphite.png) | Current neutral surfaces, gray mode selection and blue primary action. | No private input was selected and no processing ran. |
| [Explore, dark](explore-dark.png) | Public ScriptWidget search, Mac / US, 17 results; real public artwork; keyboard-selected Widgy details; fixed sign-in/download action. | No account or download was exercised. |
| [Explore release build, dark](explore-release-dark.png) | Signed release app, real public Mac / US search and artwork; metadata scrolled to the end with all copy actions visible inside the window. | Launch and public browsing evidence only. |
| [Historical light appearance](explore-light.png) | Superseded appearance option, captured before the dark-only scope decision. | Historical evidence; no longer a supported mode. |
| [Sign in](sign-in.png) | Empty account sheet reached from the desktop. | No credentials were entered and no authentication request was submitted. |
| [FairPlay inspection](fairplay-inspect.png) | Updated compact toolbar and material-selection entry with model/capture/report controls. | No private files were selected or inspected. |
| [Explore, narrow](explore-narrow.png) | Real public Mac / US search at 900×650; compact page navigation and list/detail regions. | No account operation ran. |
| [Sign in, narrow](sign-in-narrow.png) | Encrypted-file-store options expanded at 900×650 with both footer actions visible. | Empty fields; no credential storage was opened. |
| [Sign-in validation, narrow](sign-in-narrow-error.png) | Empty-submit validation appears at the top; content scrolls while Cancel and Continue remain visible. | Validation returns before authentication; no credentials were entered. |
| [FairPlay, narrow](fairplay-narrow.png) | Inspection inputs and fixed primary action fit the narrow viewport. | No private inputs or processing were exercised. |
| [FairPlay advanced, narrow](fairplay-advanced-narrow.png) | Collection form scrolled to the last Build version field; the complete final input and fixed Add collection task action remain visible. | No private input was selected and no collection task ran. |

The observed keyboard journey was: select a public result, press Down to select
the next application, press Enter to open its account interaction, cancel back
to the retained selection, and use Command-Comma to open desktop settings.
Appearance changes and native navigation icons were verified in the running app.
The current release build repeated the Down/Enter/Command-W journey after the
viewport fixes: changing selection reset detail scroll, Enter opened the empty
account sheet, and Command-W returned to the retained application. Command-Q then
terminated the app, verified from process inventory without reopening a window.

The narrow captures use the optional `gui-test` build's initial-size hint and
an isolated temporary state directory. They still use the real native service
implementation: the build does not inject simulated account results. The hint
is ignored by ordinary GUI and release builds. Native settings remained usable
through Command-Comma after cancelling empty-form account validation.

The fixture walkthrough now includes challenge continuation, populated Library,
filtering, pagination, version metadata, expired-session continuation, serial
queue cancellation/completion, restart/retry, and active-worker quit decisions.
Still required: remaining FairPlay mismatch/processing/report interactions and
the final account/private-data gates.
Captures alone do not prove those behaviors. See the implementation plan and
the current validation record in [PORTING.md](../PORTING.md).

The refined release build repeated Down/Enter/Command-W, icon-only sidebar
collapse/restore, clear-search, and Command-Comma checks. Clearing removed both
the query and its previous results; returning from sign-in retained selection.
The final 900×650 fixture captures include the revised dark shell, populated
Library, dedicated saved-account unlock, and FairPlay mismatch/matched-material
diagnostics with report publication and decryption-input handoff. Their synthetic
materials do not establish private FairPlay or live account support.
