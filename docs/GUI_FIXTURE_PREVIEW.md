# Native desktop fixture preview

The optional `gui-test` build provides a native interaction harness in addition
to deterministic GPUI controller tests. Its persistent header says
`Fixture preview · no Apple requests`. Account, catalog, Library, version and
download services are synthetic. No Keychain or Apple account service is used.
The ordinary GUI/release build rejects the fixture-preview environment flag.

This harness checks actual control layout, focus, navigation, task state,
restart/retry, and quit behavior. It does not prove Store authentication, signed
requests, package decryption, transfer speed/resumption, or private FairPlay
compatibility. Keep those protocol and live-account gates separate.

Build with `cargo build --locked --features gui-test --bin ipatool-gui`. Run in
an isolated, disposable `IPATOOL_STATE_DIR` containing a `.ipatool-gui-fixtures`
file whose complete contents are `local-only` followed by a newline. Set
`IPATOOL_GUI_PREVIEW=fixtures`. A missing/invalid marker fails startup rather
than selecting native account services. `IPATOOL_GUI_TEST_WINDOW_SIZE=900x650`
can select the minimum supported viewport in this test build.

Only the fixture harness accepts the documented synthetic account:

- Account: `fixture@example.invalid`; password: `fixture-password`.
- Verification code: `123456`.
- File-store unlock passphrase: `fixture-store-passphrase`.
- Library: six pages of 25 synthetic applications.
- Version `100` produces a session-expired failure once per preview process,
  allowing same-account continuation to be inspected. Other versions complete.
- Downloads emit synthetic progress for about 20 seconds, then publish a small
  unencrypted fixture ZIP under the harness's own `fixture-output` directory.
  They ignore the requested output destination and never replace existing files.
- Inspecting the generated IPA uses the real shared diagnostic adapter on the
  synthetic file. An automatic saved-model follow-up returns the safe missing-model
  failure so the original successful download and preparation handoff can be
  tested. Setup/import/collection/recovery and actual decryption are disabled in
  this native harness. Positive model import/reuse uses synthetic encrypted data
  in the shared-service unit suite, separately from native screenshots.

The harness never writes its sample account/password/code to credential storage
or task history. Outputs are test artifacts, not usable downloaded applications.
Delete the isolated state directory after the walkthrough and retain only
explicitly labeled, non-secret evidence. Fixture screenshots live separately
from public-service screenshots in `screenshots/fixtures/`.
