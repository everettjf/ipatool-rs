The three `fairplay-oracle-*-public.model.gz` files are the account-independent,
sanitized 26A428 frame, state, and SIDB models from
`ipatool-fairplay/tools/fairplay-recovery/profiles/`. They contain checked build
state for regression tests, not a user's enrollment. Private oracle models must
never be added here.

`fairplay-current-tag-public-vectors.json` contains 32 synthetic hardware byte
arrays and SHA-256 digests of their 44 big-endian tag words. It was generated
with `internal/recovery/tagengine.GenerateCodebook` at UnfairPlay commit
`b3a7a432da2047a0d4f1ed5a3152c538a5497183`. Input byte `i` of vector `n` is
`(17*n + 37*i) mod 256`; no real hardware identity or enrollment was used.
The Rust differential test covers signed polynomial remainder, wrapped indexed
aliasing, CBC chaining and the final affine tag map. These vectors establish
constructor parity only, not complete enrollment recovery.

`fairplay-current-outer-public-vectors.json` contains 32 complete semantic outer
iteration digests and one content-selected codec/source control from the same
pinned UnfairPlay revision. Iteration `n` uses table word `i` equal to
`((i+1)*0x9e3779b9) XOR (n*0x1234567)` and state word `i` equal to
`((i+1)*0x31415927) XOR (n*0x1b2b3b4b)`, with uint32 wrapping. Hardware byte `i`
is `(17*n+37*i) mod 256`, hardware index is `n mod 6`, and codec/source/tail/writer
byte `i` use `(29*i+13*n)`, `(31*i+19*n)`, `(41*i+3*n)` and `(43*i+5*n)` modulo
256. The control cycles through the three mapped X1 values and starts its seed
at `n*0xf1234567+0x0a782fec` with uint32 wrapping. Digests serialize table words,
state words, hardware bytes/index, codec, source, tail, writer, optional word,
X1 and seed in that order, with little-endian words. The codec control comes
from upstream's `syntheticNativeSIDB(t, 64)` helper. It contains invented bytes,
not a real system database. Regenerate the reviewed Rust arithmetic with
`go run scripts/port_current_math.go /path/to/pinned/unfairplay`, then rustfmt.
The development generator refuses another upstream commit or edited selected
source files; Cargo and the shipped executable do not require Go.

`fairplay-current-recovery-public-vectors.json` contains two entirely synthetic,
authenticated SIDB/SINF controls created with upstream's `syntheticNativeSIDBMatching`
and `syntheticProductionRoute`, including a selected slot above the old 14-slot
limit and extended rights. Model and decoded-state hashes and all selected-route
fields were produced by the pinned Go implementation. Each control also includes
a trap SINF that accepts a different metadata record: both implementations must
reject it instead of changing the selected route. The 32 class-key controls use
the same invented hardware formula, user `n*0x12345678` and key identifier
`n*0x87654321+1`, with uint32 wrapping. No account, Mac identity, actual SIDB,
downloaded IPA or private enrollment model contributed to either fixture file.

To reproduce the latter two fixtures, copy the two Go test files from
`scripts/reference-current-vectors/` into `internal/recovery/` in a temporary
checkout of the pinned upstream commit. Create an empty output directory, set
`IPATOOL_PUBLIC_VECTOR_DIR` to its absolute path, and run
`go test ./internal/recovery -run '^TestRust(Outer|Recovery)PublicVectors$' -count=1`.
The exporters refuse existing output files. Checked-in numeric arrays are
reformatted for review; compare decoded JSON values, not whitespace. This
optional development procedure is not part of Cargo or the shipped runtime.

`mac-xar-extra-synthetic.pkg` is a 386-byte synthetic XAR with extra XML
elements in its TOC, file, and data records, plus symlink and FIFO entries.
The Go XAR reader accepted its single checksummed payload and skipped the
special entries. It contains no account or package data.

`mac-xar-no-regular-synthetic.pkg` is a 274-byte XAR containing only a
directory, a symlink, and a FIFO. The Go reader reports zero regular files,
so macOS package validation rejects it. It contains no account data.

`mac-xar-directory-payload-synthetic.pkg` is a 448-byte XAR with a regular
`PackageInfo` and a timestamped directory named `Payload`. The Go reader
exposes only `PackageInfo`, so version metadata has no payload timestamp.
It contains no account data.

`mac-xar-mismatched-toc-synthetic.pkg` is a 387-byte XAR with a SHA1 header
checksum ID and a TOC that declares MD5. Its stored checksum still matches
the SHA1 digest of the compressed TOC; Go rejects the conflicting algorithm
declarations. It contains no account or package data.

`mac-xar-invalid-extracted-synthetic.pkg` is a 384-byte XAR with a valid
archived payload checksum but a non-hexadecimal extracted checksum (`gg`).
The Go reader rejects this file record while opening the archive. It contains
no account or package data.

`fairplay-oracle-raw-source-synthetic.model.gz` extends the account-free
26A428 synthetic model with zero-filled pages so the six checked raw-source
kernels can run one iteration. Expected state hashes were cross-checked with
the original Go recovery executable. It contains no enrollment or account data.

`fairplay-26b118-go-vectors.txt` contains 64 ordinary inputs and 144 fault
cases generated by the original Go 26B118 evaluator at commit `7afff07` from
the public synthetic model. Each line records the input, output, and SHA-256
of all registers, flags, and mapped pages. The 18-domain synthetic model
matches Go on 205 outputs and the three index-domain rejections at
`0x100222c58`. The checked 17-domain variant omits that extra post-lookup
domain and exercises the direct XOR for those three cases. These fixtures
contain no enrollment or account data.

`fairplay-checkpoint-schema2-synthetic.pkl.gz` is a generated Python protocol-5
checkpoint with two patterned pages. It contains no enrollment or account data.

`fairplay-checkpoint-run-schema1-synthetic.pkl.gz` is a protocol-5 schema-1
variant of the synthetic checkpoint-run fixture. Its byte-addressed memory and
two once tokens exercise lossless conversion to a resumable schema-2 snapshot.
