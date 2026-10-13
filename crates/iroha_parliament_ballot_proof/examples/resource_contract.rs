//! Standalone, one-invocation charged verifier with a bounded allocation arena
//! and explicitly supplied native stack. This is not a production record API or
//! a whole-process resource certificate. Run in a dedicated child process.

#[path = "resource_contract/budget.rs"]
mod budget;

#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[allow(unsafe_code)]
#[path = "resource_contract/arena.rs"]
mod arena;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[allow(unsafe_code)]
#[path = "resource_contract/native.rs"]
mod native;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[allow(unsafe_code)]
#[path = "resource_contract/workspace.rs"]
mod workspace;

#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
fn main() {
    use iroha_parliament_ballot_proof::profile::{Role, Row};
    fn usage() -> ! {
        eprintln!(
            "Usage: resource_contract candidate|comparator registration|vote RECORD_FILE [--heap-limit N] [--units N] [--input-bytes N]"
        );
        std::process::exit(3)
    }
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() < 4 || (args.len() - 4) % 2 != 0 {
        usage();
    }
    let row = match args[1].to_str() {
        Some("candidate") => Row::Candidate,
        Some("comparator") => Row::Comparator,
        _ => usage(),
    };
    let role = match args[2].to_str() {
        Some("registration") => Role::Registration,
        Some("vote") => Role::Vote,
        _ => usage(),
    };
    let mut options = workspace::Options {
        row,
        role,
        path: std::path::Path::new(&args[3]),
        heap_limit: arena::HEAP_BYTES,
        units: budget::VERIFICATION_UNITS,
        input_bytes: budget::MAX_INPUT_BYTES as u64,
    };
    for pair in args[4..].chunks_exact(2) {
        let value = pair[1]
            .to_str()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_else(|| usage());
        match pair[0].to_str() {
            Some("--heap-limit") => {
                options.heap_limit = usize::try_from(value).unwrap_or_else(|_| usage())
            }
            Some("--units") => options.units = value,
            Some("--input-bytes") => options.input_bytes = value,
            _ => usage(),
        }
    }
    match workspace::run(options) {
        Ok((report, exit)) => {
            println!(
                "{}",
                norito::json::to_json(&report).expect("fixed worker report serializes")
            );
            std::process::exit(exit);
        }
        Err(native::NativeError(operation, code)) => {
            eprintln!("resource worker setup failed: {operation} ({code})");
            std::process::exit(4);
        }
    }
}

#[cfg(not(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
)))]
fn main() {
    eprintln!("resource worker supports only 64-bit Linux or macOS; no unbounded fallback");
    std::process::exit(4);
}
