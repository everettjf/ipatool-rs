//! Offline execution of the checked 26A428 FairPlay raw source kernels.

use anyhow::{Result, bail};
use serde_json::Value as JsonValue;
use zeroize::Zeroizing;

use crate::{
    fairplay_frame::{
        BUILD_HASH, add_offset, bool_value, extract_pair, insert_bits, rotate_right, select_value,
        shift_left, shift_right, sign_extend32,
    },
    fairplay_oracle_model::{OracleFault, OracleModel, OracleState},
};

pub struct RawSourceResult {
    pub iterations: usize,
    pub state_sha256: String,
    pub report: Option<JsonValue>,
    pub output: Option<Zeroizing<Vec<u8>>>,
}

const SOURCE_OUTPUT_ADDRESS: u64 = 0x7000_000f_b304;

fn finish_result(
    state: &OracleState<'_>,
    iterations: usize,
    include_report: bool,
    output_size: Option<usize>,
) -> Result<RawSourceResult> {
    Ok(RawSourceResult {
        iterations,
        state_sha256: state.digest(),
        report: include_report.then(|| state.raw_source_report()),
        output: output_size
            .map(|size| {
                state
                    .read_bytes_at(SOURCE_OUTPUT_ADDRESS, size)
                    .map(Zeroizing::new)
            })
            .transpose()?,
    })
}

fn unsigned_divide(left: u64, right: u64, width: u32) -> u64 {
    if width == 32 {
        let divisor = right as u32;
        return u64::from((left as u32).checked_div(divisor).unwrap_or(0));
    }
    left.checked_div(right).unwrap_or(0)
}

fn run_raw_source_kernel_loop(state: &mut OracleState<'_>, kernel: &str) -> Result<usize> {
    let kernel = if kernel == "digest-natural" {
        run_raw_source_digest_prologue(state, OracleFault::NONE)?;
        "digest"
    } else {
        kernel
    };
    for iteration in 1..=256 {
        if kernel_iteration(state, kernel)? {
            return Ok(iteration);
        }
    }
    bail!("raw source kernel loop did not reach its bounded exit")
}

fn kernel_iteration(state: &mut OracleState<'_>, kernel: &str) -> Result<bool> {
    let exit = match kernel {
        "writer" => {
            let exit = (state.registers[1] as u32).wrapping_add(0x9fce_627e) > 0xc7;
            run_raw_source_writer_kernel(state, OracleFault::NONE)?;
            exit
        }
        "tail" => {
            let exit = (state.registers[3] as u32).wrapping_add(0x9fce_627e) >= 0x12c;
            run_raw_source_tail_kernel(state, OracleFault::NONE)?;
            exit
        }
        "even" => {
            let exit = (state.registers[12] as u32).wrapping_add(2) > 0x63;
            run_raw_source_even_kernel(state, OracleFault::NONE)?;
            exit
        }
        "odd" => {
            let exit = (state.registers[1] as u32).wrapping_add(0x9fce_627f) > 0x64;
            run_raw_source_odd_kernel(state, OracleFault::NONE)?;
            exit
        }
        "digest" => {
            run_raw_source_digest_kernel(state, OracleFault::NONE)?;
            let exit = state.flags[1];
            if !exit {
                run_raw_source_digest_prologue(state, OracleFault::NONE)?;
            }
            exit
        }
        "cycle" => {
            run_raw_source_cycle_boundary(state, OracleFault::NONE)?;
            state.registers[8] != 0x1005_b7438
        }
        "outer-primary" => {
            run_raw_source_outer_iteration(state, OracleFault::NONE)?;
            state.registers[12] != 0x1005_b7438
        }
        "outer" => {
            run_raw_source_outer_iteration(state, OracleFault::NONE)?;
            if state.registers[12] == 0x1007_822cc {
                run_raw_source_cycle_boundary(state, OracleFault::NONE)?;
                state.registers[8] != 0x1005_b7438
            } else {
                state.registers[12] != 0x1005_b7438
            }
        }
        _ => bail!("unknown or unported raw source kernel {kernel:?}"),
    };
    Ok(exit)
}

/// Run one iteration, a bounded natural loop, or an exact iteration count.
/// The model is private enrollment data from the checked 26A428 build.
pub fn run_kernel(
    model: &OracleModel,
    kernel: &str,
    loop_mode: bool,
    exact_iterations: usize,
    include_report: bool,
    output_size: Option<usize>,
) -> Result<RawSourceResult> {
    if model.binary_hash != BUILD_HASH {
        bail!("raw source model does not match checked 26A428 fairplayd");
    }
    if exact_iterations > 4096 || (loop_mode && exact_iterations != 0) {
        bail!("raw source iterations must be 0..4096 and cannot be combined with --loop");
    }
    if !matches!(
        kernel,
        "writer" | "tail" | "even" | "odd" | "digest" | "cycle" | "outer-primary" | "outer"
    ) {
        bail!("unknown or unported raw source kernel {kernel:?}");
    }
    if output_size.is_some_and(|size| !matches!(size, 192 | 224))
        || (output_size.is_some() && (kernel != "outer" || !loop_mode))
    {
        bail!("raw source output requires the complete outer loop and 192 or 224 bytes");
    }
    let mut state = model.state();
    let limit = if exact_iterations != 0 {
        exact_iterations
    } else if loop_mode {
        256
    } else {
        1
    };
    for index in 0..limit {
        let exit = kernel_iteration(&mut state, kernel)?;
        if loop_mode && exit {
            return finish_result(&state, index + 1, include_report, output_size);
        }
    }
    if loop_mode {
        bail!("raw source kernel loop did not reach its bounded exit");
    }
    finish_result(&state, limit, include_report, output_size)
}

include!("fairplay_raw_source_writer_generated.rs");
include!("fairplay_raw_source_tail_generated.rs");
include!("fairplay_raw_source_even_generated.rs");
include!("fairplay_raw_source_odd_generated.rs");
include!("fairplay_raw_source_digest_generated.rs");
include!("fairplay_raw_source_digest_prologue_generated.rs");
include!("fairplay_raw_source_cycle_generated.rs");
include!("fairplay_raw_source_optional_generated.rs");
include!("fairplay_raw_source_outer_generated.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernels_require_matching_build_and_bounded_loop() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-26b118-synthetic.model.gz"
        ))
        .unwrap();
        assert!(run_kernel(&model, "writer", false, 0, false, None).is_err());
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-26a428-synthetic.model.gz"
        ))
        .unwrap();
        assert!(run_kernel(&model, "writer", true, 1, false, None).is_err());
        assert!(run_kernel(&model, "writer", false, 4097, false, None).is_err());
        assert!(run_kernel(&model, "unknown", false, 0, false, None).is_err());
        assert!(run_kernel(&model, "writer", false, 0, false, Some(192)).is_err());
    }

    #[test]
    fn six_kernels_match_go_on_account_free_synthetic_memory() {
        let model = OracleModel::parse_gzip(include_bytes!(
            "../tests/fixtures/fairplay-oracle-raw-source-synthetic.model.gz"
        ))
        .unwrap();
        for (kernel, expected) in [
            (
                "writer",
                "cc71e33f1d52db22e5e786770110aec9ad2fd399476f7b6d884ce673f255fcbe",
            ),
            (
                "tail",
                "aa535bf97123ee4137b7d3902fa814b297932845fe7126afc0aebb0539511daa",
            ),
            (
                "even",
                "0a36d18624a80ef32d7f97e9b6845b45da786023d86f6ff75cbf1a0e1ed92f8e",
            ),
            (
                "odd",
                "032c42f4a9ad5f1c4831c84bb46b3f9f7f7ec8c07f8a3b3bcc199bfe5fc61b9e",
            ),
            (
                "digest",
                "cf85e1fade533e792b35adc4b7da5c794c2fb51a3aa850dd586134e50bc713ba",
            ),
            (
                "cycle",
                "a5fccdf2d55c72243cc8b8b30fa90fe7d0e9053b3ce38fa1083f66dc48ef972d",
            ),
        ] {
            let result = run_kernel(&model, kernel, false, 0, true, None).unwrap();
            assert_eq!(result.iterations, 1, "{kernel}");
            assert_eq!(result.state_sha256, expected, "{kernel}");
            let report = result.report.unwrap();
            assert_eq!(report["schema"], "ipatool-fairplay-raw-source-state-v1");
            assert_eq!(report["state_sha256"], expected);
            assert!(
                report["dirty_page_bytes"]
                    .as_object()
                    .is_some_and(|map| !map.is_empty())
            );
        }
        let looped = run_kernel(&model, "even", true, 0, false, None).unwrap();
        assert_eq!(looped.iterations, 50);
        assert_eq!(
            looped.state_sha256,
            "39c880cc5ecc94bf5da53fc5a30f2140bbb141c0506ced8726fa96c873d129b2"
        );
    }
}
