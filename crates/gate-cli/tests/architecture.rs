//! Architecture rules, checked on the source tree itself with plain string parsing (no extra
//! crates): the direction of the dependencies between the crates, the closed list of third-party
//! dependencies, `unsafe` in one crate only, no I/O, clock or process access in the pure
//! layers, and the lint configuration that bans `unwrap`, `expect`, `panic` and indexing in
//! production code.
//!
//! ```text
//! gate-domain  <-  gate-app  <-  gate-infra  <-  gate-cli
//!      ^                             |              |
//!      +---- gate-fake-mcp <---------+--------------+ (cli only)
//!                gate-sys (libc, the only unsafe code) <- gate-infra, gate-cli
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::fs;
use std::path::{Path, PathBuf};

const CRATES: [&str; 6] = [
    "gate-domain",
    "gate-app",
    "gate-sys",
    "gate-infra",
    "gate-fake-mcp",
    "gate-cli",
];

/// For each crate: the workspace crates it may depend on (normal and dev dependencies).
fn allowed_workspace_deps(name: &str) -> &'static [&'static str] {
    match name {
        "gate-domain" => &[],
        "gate-app" => &["gate-domain"],
        "gate-sys" => &[],
        "gate-infra" => &["gate-domain", "gate-app", "gate-sys"],
        "gate-fake-mcp" => &["gate-domain"],
        "gate-cli" => &[
            "gate-domain",
            "gate-app",
            "gate-infra",
            "gate-sys",
            "gate-fake-mcp",
        ],
        _ => &[],
    }
}

/// The only crate outside the workspace, and the crate that may use it.
const THIRD_PARTY: [(&str, &str); 1] = [("libc", "gate-sys")];

fn root() -> PathBuf {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .expect("the workspace root exists")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn crate_dir(name: &str) -> PathBuf {
    root().join("crates").join(name)
}

/// The dependency names and the raw text after `=`, from the `[dependencies]`-like tables.
fn dependencies(manifest: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
            continue;
        }
        let is_dep_table = matches!(
            section.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) || section.starts_with("target.");
        if is_dep_table {
            if let Some((name, rest)) = line.split_once('=') {
                out.push((
                    section.clone(),
                    name.trim().to_string(),
                    rest.trim().to_string(),
                ));
            }
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The part of a source file that ships: everything before the first `#[cfg(test)]`, without
/// comment lines.
fn production_code(source: &str) -> String {
    let cut = source.find("#[cfg(test)]").unwrap_or(source.len());
    source[..cut]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_test_support(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with("_tests.rs")
        || name == "testing.rs"
        || name == "testutil.rs"
        || path.components().any(|c| c.as_os_str() == "tests")
}

/// Whether `word` occurs in `text` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

fn banned_in<'a>(code: &str, banned: &[&'a str]) -> Vec<&'a str> {
    banned
        .iter()
        .copied()
        .filter(|b| {
            if b.chars().all(|c| c.is_alphanumeric() || c == '_') {
                has_word(code, b)
            } else {
                code.contains(b)
            }
        })
        .collect()
}

// ---- dependency direction ------------------------------------------------------------------------

#[test]
fn crates_depend_only_on_the_crates_inside_them() {
    for name in CRATES {
        let manifest = read(&crate_dir(name).join("Cargo.toml"));
        for (_, dep, _) in dependencies(&manifest) {
            let workspace_ok = allowed_workspace_deps(name).contains(&dep.as_str());
            let third_party_ok = THIRD_PARTY
                .iter()
                .any(|(d, owner)| *d == dep && *owner == name);
            assert!(
                workspace_ok || third_party_ok,
                "{name} must not depend on {dep}"
            );
        }
    }
}

#[test]
fn the_domain_has_no_dependencies_at_all() {
    let manifest = read(&crate_dir("gate-domain").join("Cargo.toml"));
    assert!(
        dependencies(&manifest).is_empty(),
        "the domain crate is std only"
    );
    let app = read(&crate_dir("gate-app").join("Cargo.toml"));
    let app_deps = dependencies(&app);
    assert_eq!(
        app_deps.len(),
        1,
        "the application layer depends on the domain only: {app_deps:?}"
    );
}

#[test]
fn nothing_depends_on_the_command_line_crate() {
    for name in CRATES {
        let manifest = read(&crate_dir(name).join("Cargo.toml"));
        assert!(
            !dependencies(&manifest)
                .iter()
                .any(|(_, d, _)| d == "gate-cli"),
            "{name} depends on gate-cli"
        );
    }
}

#[test]
fn every_crate_is_in_the_workspace_and_none_is_missing() {
    let manifest = read(&root().join("Cargo.toml"));
    for name in CRATES {
        assert!(
            manifest.contains(&format!("\"crates/{name}\"")),
            "{name} is not a workspace member"
        );
    }
    let members = fs::read_dir(root().join("crates"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .count();
    assert_eq!(
        members,
        CRATES.len(),
        "a crate directory is not covered by these rules"
    );
}

// ---- third-party code ------------------------------------------------------------------------------

#[test]
fn the_only_third_party_crate_is_libc_and_it_is_pinned() {
    for name in CRATES {
        for (_, dep, rest) in dependencies(&read(&crate_dir(name).join("Cargo.toml"))) {
            if dep.starts_with("gate-") {
                assert!(
                    rest.contains("path ="),
                    "{name}: {dep} must be a path dependency"
                );
            } else {
                assert!(
                    rest.starts_with("\"="),
                    "{name}: {dep} must be pinned with an exact version, got {rest}"
                );
            }
        }
    }
    let lock = read(&root().join("Cargo.lock"));
    let packages: Vec<&str> = lock
        .split("[[package]]")
        .skip(1)
        .filter_map(|b| {
            b.lines()
                .find_map(|l| l.strip_prefix("name = \""))
                .and_then(|l| l.strip_suffix('"'))
        })
        .collect();
    for p in &packages {
        assert!(
            p.starts_with("gate-") || *p == "libc",
            "unexpected package in Cargo.lock: {p}"
        );
    }
    assert!(packages.contains(&"libc"));
    assert_eq!(packages.len(), CRATES.len() + 1);
    // no HTTP, async, TLS, serialization or parsing library sneaks in under another name
    for banned in [
        "tokio",
        "hyper",
        "rustls",
        "openssl",
        "serde",
        "toml",
        "reqwest",
        "async-std",
        "mio",
        "regex",
        "sha2",
    ] {
        assert!(
            !packages.contains(&banned),
            "{banned} must not be a dependency"
        );
    }
}

// ---- unsafe code -----------------------------------------------------------------------------------

#[test]
fn unsafe_code_exists_only_in_the_system_crate() {
    for name in CRATES {
        let mut files = Vec::new();
        rust_files(&crate_dir(name), &mut files);
        for file in files {
            let code = read(&file);
            let code: String = code
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            // this file talks about the word in its own test strings
            if name == "gate-sys" || file.ends_with("tests/architecture.rs") {
                continue;
            }
            assert!(
                !has_word(&code, "unsafe"),
                "{} uses unsafe outside gate-sys",
                file.display()
            );
        }
    }
    let root_manifest = read(&root().join("Cargo.toml"));
    assert!(
        root_manifest.contains("unsafe_code = \"forbid\""),
        "the workspace forbids unsafe code"
    );
}

#[test]
fn every_unsafe_block_of_the_system_crate_has_a_safety_comment() {
    let source = read(&crate_dir("gate-sys").join("src/lib.rs"));
    let lines: Vec<&str> = source.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//")
            || !has_word(line, "unsafe")
            || code.starts_with("#![")
            || code.starts_with("#[")
        {
            continue;
        }
        let documented = lines[..i]
            .iter()
            .rev()
            .take(4)
            .any(|l| l.trim_start().starts_with("// SAFETY:"))
            || line.contains("// SAFETY:");
        assert!(
            documented,
            "line {} has unsafe without a SAFETY comment: {line}",
            i + 1
        );
    }
}

#[test]
fn the_lint_configuration_cannot_be_dropped_quietly() {
    for name in CRATES {
        let manifest = read(&crate_dir(name).join("Cargo.toml"));
        if name == "gate-sys" {
            for lint in [
                "unwrap_used",
                "expect_used",
                "indexing_slicing",
                "panic",
                "undocumented_unsafe_blocks",
            ] {
                assert!(
                    manifest.contains(&format!("{lint} = \"deny\"")),
                    "gate-sys lacks the {lint} lint"
                );
            }
        } else {
            assert!(
                manifest.contains("[lints]\nworkspace = true"),
                "{name} must inherit the workspace lints"
            );
        }
    }
    let root_manifest = read(&root().join("Cargo.toml"));
    for lint in ["unwrap_used", "expect_used", "indexing_slicing", "panic"] {
        assert!(
            root_manifest.contains(&format!("{lint} = \"deny\"")),
            "the workspace lacks the {lint} lint"
        );
    }
}

#[test]
fn lint_exceptions_are_few_and_listed() {
    let allowed: [(&str, &str); 2] = [
        ("gate-domain/src/hash.rs", "indexing_slicing"),
        ("gate-infra/src/testutil.rs", "panic"),
    ];
    for name in CRATES {
        let mut files = Vec::new();
        rust_files(&crate_dir(name).join("src"), &mut files);
        for file in files {
            let rel = file
                .strip_prefix(root().join("crates"))
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let code = production_code(&read(&file));
            for lint in ["unwrap_used", "expect_used", "indexing_slicing", "panic"] {
                let attribute = format!("allow(clippy::{lint}");
                if code.contains(&attribute) {
                    assert!(
                        allowed.contains(&(rel.as_str(), lint)),
                        "{rel} allows clippy::{lint}; add it to the reviewed list or remove it"
                    );
                }
            }
        }
    }
}

// ---- purity of the inner layers --------------------------------------------------------------------

/// What the domain and the application layer must not touch: files, sockets, processes, the
/// environment, the clock, the terminal.
const IMPURE: [&str; 15] = [
    "std::fs",
    "std::process",
    "std::env",
    "SystemTime",
    "Instant",
    "TcpListener",
    "TcpStream",
    "UdpSocket",
    "stdin()",
    "stdout()",
    "stderr()",
    "println!",
    "eprintln!",
    "thread::sleep",
    "Command::new",
];

fn check_pure(crate_name: &str) {
    let mut files = Vec::new();
    rust_files(&crate_dir(crate_name).join("src"), &mut files);
    assert!(!files.is_empty());
    for file in files {
        if is_test_support(&file) {
            continue;
        }
        let found = banned_in(&production_code(&read(&file)), &IMPURE);
        assert!(
            found.is_empty(),
            "{} uses {found:?}; the {crate_name} layer must stay free of I/O and clocks",
            file.display()
        );
    }
}

#[test]
fn the_domain_layer_is_pure() {
    check_pure("gate-domain");
}

#[test]
fn the_application_layer_is_pure() {
    check_pure("gate-app");
}

#[test]
fn the_domain_does_not_spawn_threads() {
    let mut files = Vec::new();
    rust_files(&crate_dir("gate-domain").join("src"), &mut files);
    for file in files {
        let found = banned_in(
            &production_code(&read(&file)),
            &["std::thread", "thread::spawn", "std::sync::mpsc"],
        );
        assert!(found.is_empty(), "{} uses {found:?}", file.display());
    }
}

#[test]
fn networking_lives_in_the_infrastructure_crate_only() {
    for name in ["gate-domain", "gate-app", "gate-fake-mcp", "gate-cli"] {
        let mut files = Vec::new();
        rust_files(&crate_dir(name).join("src"), &mut files);
        for file in files {
            if is_test_support(&file) {
                continue;
            }
            let found = banned_in(
                &production_code(&read(&file)),
                &["TcpListener", "TcpStream", "UdpSocket"],
            );
            // the selftest of the command line binds a probe port; everything else must not
            let selftest = file.ends_with("gate-cli/src/selftest.rs");
            assert!(
                found.is_empty() || selftest,
                "{} uses {found:?}",
                file.display()
            );
        }
    }
}

#[test]
fn the_system_crate_stays_small() {
    let source = read(&crate_dir("gate-sys").join("src/lib.rs"));
    let production = production_code(&source);
    assert!(
        production.lines().count() < 220,
        "gate-sys is the unsafe surface of the program; keep it small"
    );
    for banned in ["TcpListener", "gate_domain", "gate_app"] {
        assert!(
            !production.contains(banned),
            "gate-sys must stay free of {banned}"
        );
    }
}

// ---- the checker checks itself --------------------------------------------------------------------

#[test]
fn the_helpers_detect_what_they_claim_to_detect() {
    assert!(has_word("a unsafe { b }", "unsafe"));
    assert!(!has_word("fn unsafe_free()", "unsafe"));
    assert!(!has_word("fn is_unsafe()", "unsafe"));
    assert!(has_word("unsafe", "unsafe"));
    assert_eq!(
        banned_in("let t = std::time::SystemTime::now();", &IMPURE),
        ["SystemTime"]
    );
    assert_eq!(banned_in("std::fs::read(p)", &IMPURE), ["std::fs"]);
    assert!(
        banned_in("let x = 1; // std::fs in a comment\n", &["std::fs"]).len() == 1,
        "raw text matching sees comments; production_code strips them"
    );
    assert!(banned_in(
        &production_code("// std::fs\nfn f() {}\n#[cfg(test)]\nmod t { use std::fs; }"),
        &IMPURE
    )
    .is_empty());
    let deps = dependencies("[package]\nname = \"x\"\n[dependencies]\ngate-domain = { path = \"../gate-domain\" }\nlibc = \"=0.2.190\"\n[dev-dependencies]\nfoo = \"1\"\n");
    assert_eq!(
        deps.iter().map(|d| d.1.as_str()).collect::<Vec<_>>(),
        ["gate-domain", "libc", "foo"]
    );
}
