//! Command line parsing: a command, flags with or without a value, and nothing implicit.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy)]
pub struct FlagSpec {
    pub name: &'static str,
    pub takes_value: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub values: BTreeMap<String, String>,
    pub switches: BTreeSet<String>,
    pub positional: Vec<String>,
}

impl Parsed {
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    pub fn has(&self, name: &str) -> bool {
        self.switches.contains(name)
    }
}

/// Parses `args` against `spec`. Both `--name value` and `--name=value` are accepted; a flag
/// that is given twice, an unknown flag and a missing value are errors.
pub fn parse(args: &[String], spec: &[FlagSpec]) -> Result<Parsed, String> {
    let mut parsed = Parsed::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(flag) = arg.strip_prefix("--") else {
            parsed.positional.push(arg.clone());
            continue;
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag, None),
        };
        let Some(flag_spec) = spec.iter().find(|s| s.name == name) else {
            return Err(format!("unknown option --{name}"));
        };
        if flag_spec.takes_value {
            let value = match inline {
                Some(v) => v,
                None => iter
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("--{name} needs a value"))?,
            };
            if parsed.values.insert(name.to_string(), value).is_some() {
                return Err(format!("--{name} was given twice"));
            }
        } else {
            if inline.is_some() {
                return Err(format!("--{name} takes no value"));
            }
            if !parsed.switches.insert(name.to_string()) {
                return Err(format!("--{name} was given twice"));
            }
        }
    }
    Ok(parsed)
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

    const SPEC: [FlagSpec; 2] = [
        FlagSpec {
            name: "config",
            takes_value: true,
        },
        FlagSpec {
            name: "force",
            takes_value: false,
        },
    ];

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn values_switches_and_positionals() {
        let p = parse(&args(&["a", "--config", "x.toml", "--force", "b"]), &SPEC).unwrap();
        assert_eq!(p.value("config"), Some("x.toml"));
        assert!(p.has("force") && !p.has("other"));
        assert_eq!(p.positional, ["a", "b"]);
        let p = parse(&args(&["--config=y=z"]), &SPEC).unwrap();
        assert_eq!(p.value("config"), Some("y=z"));
        assert_eq!(p.value("force"), None);
    }

    #[test]
    fn errors() {
        for (input, expect) in [
            (vec!["--nope"], "unknown option --nope"),
            (vec!["--config"], "needs a value"),
            (vec!["--config", "a", "--config", "b"], "given twice"),
            (vec!["--force", "--force"], "given twice"),
            (vec!["--force=1"], "takes no value"),
        ] {
            let e = parse(&args(&input), &SPEC).unwrap_err();
            assert!(e.contains(expect), "{input:?}: {e}");
        }
    }

    #[test]
    fn single_dash_arguments_are_positional() {
        let p = parse(&args(&["-x", "-"]), &SPEC).unwrap();
        assert_eq!(p.positional, ["-x", "-"]);
    }
}
