#!/usr/bin/env python3
"""Translate a checked generated raw-source kernel into Rust source.

This is a development-only source generator. The Rust runtime uses the
generated source directly and never invokes Python or Go.
"""

import sys
from pathlib import Path

from port_26a428_oracle import translate


FUNCTIONS = {
    "generated_raw_source_cycle.go": (
        "runRawSourceCycleBoundary",
        "run_raw_source_cycle_boundary",
    ),
    "generated_raw_source_digest.go": (
        "runRawSourceDigestKernel",
        "run_raw_source_digest_kernel",
    ),
    "generated_raw_source_digest_prologue.go": (
        "runRawSourceDigestPrologue",
        "run_raw_source_digest_prologue",
    ),
    "generated_raw_source_even.go": (
        "runRawSourceEvenKernel",
        "run_raw_source_even_kernel",
    ),
    "generated_raw_source_odd.go": (
        "runRawSourceOddKernel",
        "run_raw_source_odd_kernel",
    ),
    "generated_raw_source_outer.go": (
        "runRawSourceOuterIteration",
        "run_raw_source_outer_iteration",
    ),
    "generated_raw_source_optional.go": (
        "runRawSourceOptionalKernel",
        "run_raw_source_optional_kernel",
    ),
    "generated_raw_source_tail.go": (
        "runRawSourceTailKernel",
        "run_raw_source_tail_kernel",
    ),
    "generated_raw_source_writer.go": (
        "runRawSourceWriterKernel",
        "run_raw_source_writer_kernel",
    ),
}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: port_raw_source.py generated_raw_source_KERNEL.go output.rs")
    source = Path(sys.argv[1])
    go_function, rust_function = FUNCTIONS[source.name]
    rendered = translate(
        source.read_text(),
        go_function,
        rust_function,
        "scripts/port_raw_source.py",
    )
    Path(sys.argv[2]).write_text(rendered)
