use std::io::{stderr, stdin, stdout};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // The fake server owns standard input and output for its whole life, so it is started before
    // the streams are wrapped for the other commands.
    if args.first().map(String::as_str) == Some("fake-mcp") {
        std::process::exit(gate_fake_mcp::run_stdio(args.get(1..).unwrap_or_default()));
    }
    let mut input = stdin().lock();
    let (mut out, mut err) = (stdout(), stderr());
    let code = gate_cli::run(
        &args,
        &mut gate_cli::Io {
            stdin: &mut input,
            out: &mut out,
            err: &mut err,
        },
    );
    std::process::exit(code);
}
