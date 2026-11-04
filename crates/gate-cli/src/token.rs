use gate_domain::auth::{token_from_entropy, Scope, TokenHash, TokenId};
use gate_domain::glob::Glob;
use gate_domain::json::quote;
use gate_infra::system::random_bytes;

use crate::args::{parse, FlagSpec};
use crate::{usage_error, Io, FAILED, OK};

pub fn run(args: &[String], io: &mut Io<'_>) -> i32 {
    match args.split_first() {
        Some((sub, rest)) if sub == "new" => new(rest, io),
        Some((sub, rest)) if sub == "hash" => hash(rest, io),
        _ => usage_error(
            io,
            "usage: token new [--id NAME] [--scopes ...] [--tools ...] | token hash",
        ),
    }
}

fn csv(text: &str) -> Vec<&str> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

fn new(args: &[String], io: &mut Io<'_>) -> i32 {
    let spec = [
        FlagSpec {
            name: "id",
            takes_value: true,
        },
        FlagSpec {
            name: "scopes",
            takes_value: true,
        },
        FlagSpec {
            name: "tools",
            takes_value: true,
        },
    ];
    let parsed = match parse(args, &spec) {
        Ok(p) if p.positional.is_empty() => p,
        Ok(_) => return usage_error(io, "token new takes only options"),
        Err(e) => return usage_error(io, &e),
    };
    let id = parsed.value("id").unwrap_or("client");
    if TokenId::new(id).is_none() {
        return usage_error(
            io,
            "--id must be 1 to 64 characters of letters, digits, _, . or -",
        );
    }
    let scopes: Vec<&str> = match parsed.value("scopes") {
        None => vec![Scope::ToolsList.as_str(), Scope::ToolsCall.as_str()],
        Some(list) => csv(list),
    };
    if scopes.is_empty() || scopes.iter().any(|s| Scope::parse(s).is_none()) {
        return usage_error(
            io,
            "--scopes is a comma separated list of tools:list and tools:call",
        );
    }
    let tools = parsed.value("tools").map(csv);
    if let Some(t) = &tools {
        if t.is_empty() || t.iter().any(|p| Glob::new(p).is_err()) {
            return usage_error(
                io,
                "--tools is a comma separated list of tool name patterns",
            );
        }
    }
    let entropy = match random_bytes() {
        Ok(e) => e,
        Err(e) => {
            let _ = writeln!(io.err, "cannot read random bytes: {e}");
            return FAILED;
        }
    };
    let token = token_from_entropy(&entropy);
    let hash = TokenHash::of_token(&token).to_config_string();
    let list = |items: &[&str]| {
        items
            .iter()
            .map(|s| quote(s))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(io.out, "token: {token}");
    let _ = writeln!(io.out);
    let _ = writeln!(io.out, "[[token]]");
    let _ = writeln!(io.out, "id = {}", quote(id));
    let _ = writeln!(io.out, "hash = {}", quote(&hash));
    let _ = writeln!(io.out, "scopes = [{}]", list(&scopes));
    if let Some(t) = tools {
        let _ = writeln!(io.out, "tools = [{}]", list(&t));
    }
    let _ = writeln!(io.err, "The token above is shown once and stored nowhere. Give it to the client; paste the [[token]] block (it holds only the hash) into gate.toml.");
    OK
}

fn hash(args: &[String], io: &mut Io<'_>) -> i32 {
    if !args.is_empty() {
        return usage_error(
            io,
            "token hash takes no arguments; it reads the token from standard input",
        );
    }
    let mut line = String::new();
    if io.stdin.read_line(&mut line).is_err() {
        return usage_error(io, "cannot read the token from standard input");
    }
    let token = line.trim();
    if token.is_empty()
        || token.starts_with("sha256:")
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        return usage_error(io, "standard input must hold one token");
    }
    let _ = writeln!(io.out, "{}", TokenHash::of_token(token).to_config_string());
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
    fn a_new_token_comes_with_a_matching_hash_block() {
        let (code, out, err) = run_captured(&["token", "new", "--id", "desktop"], "");
        assert_eq!(code, OK);
        let token = out
            .lines()
            .next()
            .unwrap()
            .strip_prefix("token: ")
            .unwrap()
            .to_string();
        assert!(token.starts_with("mrg_") && token.len() == 47, "{token}");
        assert!(
            !err.contains(&token),
            "the token is printed once, on standard output"
        );
        let block: String = out.lines().skip(2).collect::<Vec<_>>().join("\n");
        assert!(
            !block.contains(&token),
            "the block that is pasted into the config holds no token"
        );
        assert!(block.contains(&format!(
            "hash = \"{}\"",
            TokenHash::of_token(&token).to_config_string()
        )));
        assert!(
            block.contains("id = \"desktop\"")
                && block.contains("scopes = [\"tools:list\", \"tools:call\"]")
        );
        // the block is valid configuration
        let text = format!("[child]\ncommand = [\"x\"]\n{block}");
        assert!(
            gate_infra::config_file::parse_config(&text).is_ok(),
            "{text}"
        );
    }

    #[test]
    fn every_token_is_different() {
        let a = run_captured(&["token", "new"], "").1;
        let b = run_captured(&["token", "new"], "").1;
        assert_ne!(a.lines().next(), b.lines().next());
        assert!(a.contains("id = \"client\""));
    }

    #[test]
    fn scopes_and_tool_limits() {
        let (code, out, _) = run_captured(
            &[
                "token",
                "new",
                "--id",
                "ro",
                "--scopes",
                "tools:list",
                "--tools",
                "get_*, list_*",
            ],
            "",
        );
        assert_eq!(code, OK);
        assert!(
            out.contains("scopes = [\"tools:list\"]")
                && out.contains("tools = [\"get_*\", \"list_*\"]"),
            "{out}"
        );
    }

    #[test]
    fn bad_options_are_usage_errors() {
        for args in [
            vec!["token"],
            vec!["token", "other"],
            vec!["token", "new", "--id", "bad id"],
            vec!["token", "new", "--scopes", "admin"],
            vec!["token", "new", "--scopes", ""],
            vec!["token", "new", "--tools", ""],
            vec!["token", "new", "--tools", "a\nb"],
            vec!["token", "new", "extra"],
            vec!["token", "new", "--bogus"],
            vec!["token", "hash", "extra"],
        ] {
            assert_eq!(run_captured(&args, "").0, USAGE, "{args:?}");
        }
    }

    #[test]
    fn hashing_a_token_from_standard_input() {
        let (code, out, _) = run_captured(&["token", "hash"], "mrg_abc\n");
        assert_eq!(code, OK);
        assert_eq!(
            out.trim(),
            TokenHash::of_token("mrg_abc").to_config_string()
        );
        for bad in ["", "\n", "sha256:00\n", "a b\n", "é\n"] {
            assert_eq!(run_captured(&["token", "hash"], bad).0, USAGE, "{bad:?}");
        }
    }
}
