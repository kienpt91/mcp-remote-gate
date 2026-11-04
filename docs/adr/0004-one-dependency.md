# 4. One third-party crate (libc); SHA-256, JSON and TOML are written here

Status: accepted

## Context
A security gateway benefits from a short dependency list: fewer things to audit, to pin and to be surprised by. The things it needs are well specified and small: a SHA-256 digest, a strict JSON parser, a configuration parser.

## Decision
- **SHA-256** (FIPS 180-4) is implemented in under 300 lines (most of them the table of constants) and checked against the NIST vectors (empty, `abc`, the 448-bit and 896-bit messages, one million `a`), against every split of a message across update calls, and, in the end-to-end tests, against the system `sha256sum`. It is used for token hashes of 256-bit random tokens: nothing there depends on resistance to anything but preimages.
- **JSON** is a strict parser and serializer (`gate-domain::json`) that refuses what two parsers could read differently: duplicate keys, lone surrogates, control characters in strings, leading zeros, trailing data, nesting deeper than 64. The gateway re-serializes every message it forwards, so what it inspects is what the other side receives. Numbers keep their source text.
- **TOML** is a subset parser (`gate-infra::toml`) that rejects everything it does not implement with a line number rather than guessing.
- **libc `=0.2.190`** is the one crate: `setrlimit`, `killpg`, `sigaction`, `prctl`, `waitid` and `geteuid` (and the `O_NOFOLLOW` flag) have no equivalent in `std`, and their struct layouts and constants differ per operating system, so declaring them by hand would be less safe than using the crate every Rust program uses. It has no dependencies of its own. It was published on 2026-10-02, more than 7 days before this was pinned. The architecture test fails if any other package appears in `Cargo.lock`.

## Consequences
About 1,300 lines of production code that a dependency would otherwise provide, all covered by tests, including property tests (round trips, arbitrary input never panics). A bug in them is this project's bug; the benefit is that there is nothing else to audit, no build scripts but libc's, and no transitive updates to review. If a vetted crate becomes preferable for the digest, replacing one function is a small change.
