use crate::{Io, OK};

/// The annotated example configuration, also tested to be valid.
pub const EXAMPLE: &str = include_str!("../../../examples/gate.toml");

pub fn run(args: &[String], io: &mut Io<'_>) -> i32 {
    if !args.is_empty() {
        return crate::usage_error(io, "init takes no arguments");
    }
    let _ = io.out.write_all(EXAMPLE.as_bytes());
    OK
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use crate::tests::run_captured;
    use crate::USAGE;

    #[test]
    fn the_example_is_a_valid_configuration() {
        let c = gate_infra::config_file::parse_config(EXAMPLE).unwrap();
        assert!(
            c.policy.read_only,
            "the example ships with sending disabled"
        );
        assert!(c.server.is_loopback());
        assert!(c.warnings().is_empty(), "{:?}", c.warnings());
    }

    #[test]
    fn init_prints_it() {
        let (code, out, _) = run_captured(&["init"], "");
        assert_eq!(code, OK);
        assert_eq!(out, EXAMPLE);
        assert_eq!(run_captured(&["init", "extra"], "").0, USAGE);
    }
}
