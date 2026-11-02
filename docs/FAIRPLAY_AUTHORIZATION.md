# Scoped macOS authorization collection

This is an implemented boundary with synthetic and local protocol tests, not a
record of successful signed registration or real enrollment recovery. The normal
GUI and all recovery, IPA processing and managed model writes run as the user.

## User journey

On macOS 13 or later, First-time preparation shows the supported SMAppService
status. Opening the page, refreshing status, restoring history and reopening the
app never register or start private collection. Allow local access explicitly
registers the bundled launch daemon; macOS administrator approval stays in System
Settings. Refresh checks the resulting state. Approval does not automatically
start preparation. Remove access unregisters the service without deleting saved
models. Ad hoc builds disable protected access.

Fresh Current setup first checks the installed app and matching IPA: bundle ID,
executable, short version, build version, current license format and an
unambiguous encrypted-image inventory. It then reads the fixed inputs with the
user's existing permissions. A permission failure may request a snapshot from an
already enabled helper; it never registers one from a processing task. Explicit
advanced source overrides use existing user permissions and are never sent to
the helper. Importing a model skips collection.

## Privileged boundary

The independent `ipatool-authorization` workspace package contains only the
bounded snapshot protocol, fixed-file reader and native ServiceManagement/XPC
adapter. Its helper has no Store client, networking, guest execution, model
recovery, IPA parser or decryption engine. No Swift executable is required.

The helper reads only these two files:

- `/private/var/db/fpsd/SC Info/SC Info.sidb`
- `/Users/Shared/SC Info/SC Info.sidb`

It accepts a versioned snapshot operation and a 16-byte nonce, with no caller
paths, commands, output locations, credentials or optional operations. Unknown
fields or versions are rejected. Each input is limited to 2 MiB. Every path
component is opened relative to a retained directory descriptor with no symlink
following. Non-regular files, hard links, untrusted owners, world-writable final
files, changed metadata and unsupported headers are rejected. Only the current
console user may request a snapshot; the console identity is checked again after
reading. Concurrent reads are bounded. No root-owned capture or model is written.

Both XPC peers require the fixed counterpart identifier and the same compiled
Developer ID team. The OS checks the code requirement on messages, including
accepted connections. An unsigned, ad hoc or differently signed peer cannot
supply an identifier or team in the protocol to bypass the policy. Replies are
nonce-bound and copied into bounded zeroizing buffers. Client cancellation and a
15-second timeout cancel the connection; existing private staging cleanup handles
subsequent recovery failures. The daemon does not keep credentials or a model.

## Build and lifecycle

`scripts/build-gui-macos.sh` packages the helper in `Contents/Library/LaunchServices`
and its plist in `Contents/Library/LaunchDaemons`. It signs the helper separately
without the GUI's JIT/library-validation exceptions, then signs the enclosing app.
The default remains local ad hoc signing with protected access disabled.

Developer ID builds require the existing public signing identity selector in
`IPATOOL_CODESIGN_IDENTITY` and the matching public 10-character team in
`IPATOOL_AUTHORIZATION_TEAM`. The team is compiled into the XPC policy and checked
against both signatures by the script. A secure timestamp and notarization are
required before distribution and signed live authorization acceptance. Do not
publish a test release merely to exercise the helper. Use the already configured
notarytool Keychain profile; credentials stay in Keychain and OS dialogs.

SMAppService owns registration and removal. The daemon has no installer shell,
arbitrary privileged copy operation or manual launchctl installation fallback.
If approval is denied, the original IPA and existing models remain unchanged.
If access is removed, saved models can still be used without collecting again.
The helper requires macOS 13; the main GUI's older supported launch target does
not imply protected collection support. Windows/Linux do not register it.

## Evidence and remaining gates

Protocol controls cover fixed operations, nonce binding, unknown fields, bounds,
fixed signing-policy construction and OS policy parsing/rejection of the test
peer. File controls reject symlinks, hard links, non-files and unsafe components.
Collector controls cover a matching synthetic app/IPA without a recovery image
or ADI data, omission of unrelated files and mismatched sample preservation.
GUI controls cover no registration on open, explicit registration, approval
status, settings handoff, removal without model deletion and rejected requests.
The helper's native dependencies contain system frameworks only; no guest engine
or separate Swift runtime is linked.

Still required before F1/F2/F4/F5 acceptance: a notarized bundle's actual
registration and code-bound exchange, denial/cancellation/removal, an authorized
private snapshot, successful real model preparation, complete available plaintext
hash validation, and independent saved-model reuse after restart. None of these
is implied by protocol tests or a successful code signature.

The `02cb19f` preview has since passed Apple notarization with zero issues,
including tickets for the GUI and helper, stapling, strict deep signature and
Gatekeeper validation, and a verified copy installed in Applications. The native
installed preview submitted explicit registration after the operator confirmed
the fixed read-only scope. The GUI reported `RequiresApproval`, opened Login
Items, and the OS requested Touch ID or an administrator password when enabling
this helper's background item. Authentication is still pending; registration is
not proof of an enabled service or successful exchange. Its existing sample
fails the distinct enrollment-match preflight before any protected read. Actual
approval, exchange, denial/cancellation/removal and real recovery/reuse remain
unproven; notarization does not close them. Details are in
[PORTING.md](PORTING.md#notarized-fairplay-preview-acceptance).
