The three `fairplay-oracle-*-public.model.gz` files are the account-independent,
sanitized 26A428 frame, state, and SIDB models from
`ipatool-fairplay/tools/fairplay-recovery/profiles/`. They contain checked build
state for regression tests, not a user's enrollment. Private oracle models must
never be added here.

`fairplay-oracle-raw-source-synthetic.model.gz` extends the account-free
26A428 synthetic model with zero-filled pages so the six checked raw-source
kernels can run one iteration. Expected state hashes were cross-checked with
the original Go recovery executable. It contains no enrollment or account data.

`fairplay-checkpoint-schema2-synthetic.pkl.gz` is a generated Python protocol-5
checkpoint with two patterned pages. It contains no enrollment or account data.

`fairplay-checkpoint-run-schema1-synthetic.pkl.gz` is a protocol-5 schema-1
variant of the synthetic checkpoint-run fixture. Its byte-addressed memory and
two once tokens exercise lossless conversion to a resumable schema-2 snapshot.
