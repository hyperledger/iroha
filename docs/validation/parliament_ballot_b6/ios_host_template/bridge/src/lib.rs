//! Temporary standalone device benchmark bridge; never part of a wallet or node.
use std::{ffi::CStr, fs::OpenOptions, io::Write, os::raw::c_char};
#[path = "@IROHA_REPO@/crates/iroha_parliament_ballot_proof/examples/qualification/mod.rs"]
mod qualification;

fn arguments(samples: u32, row: &str) -> Vec<String> {
    vec!["--samples".into(), samples.to_string(), "--row".into(), row.into(),
         "--source-id".into(), option_env!("PARLIAMENT_B6_SOURCE_ID").unwrap_or("unrecorded").into(),
         "--run-id".into(), if cfg!(feature = "accel") { "ios-accel" } else { "ios-portable" }.into()]
}

/// Run serialized benchmark work with public deterministic test credentials only.
///
/// # Safety
/// Both pointers must address NUL-terminated UTF-8 strings alive for this call.
/// The host calls this once on a dedicated worker; calls must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn parliament_qualification_run(path: *const c_char, samples: u32, row: *const c_char) -> i32 {
    if path.is_null() || row.is_null() { return 2; }
    let result = std::panic::catch_unwind(|| {
        // SAFETY: the trusted UIKit host satisfies the documented string contract.
        let path = unsafe { CStr::from_ptr(path) }.to_str().map_err(|_| 3)?;
        // SAFETY: as above, for the row string.
        let row = unsafe { CStr::from_ptr(row) }.to_str().map_err(|_| 3)?;
        let mut output = OpenOptions::new().create_new(true).write(true).open(path).map_err(|_| 4)?;
        match qualification::run(&arguments(samples, row), &mut output) {
            Ok(()) => { output.flush().map_err(|_| 5)?; Ok(()) },
            Err(error) => {
                #[derive(norito::json::JsonSerialize)]
                struct BridgeError { kind: &'static str, error: String, profile_qualified: bool }
                let record = BridgeError { kind: "bridge_error", error: error.to_string(), profile_qualified: false };
                if let Ok(line) = norito::json::to_json(&record) { let _ = writeln!(output, "{line}"); }
                Err(6)
            }
        }
    });
    match result { Ok(Ok(())) => 0, Ok(Err(code)) => code, Err(_) => 7 }
}

#[cfg(test)]
mod tests {
    #[test]
    fn arguments_bind_sample_count_and_row() {
        let args = super::arguments(31, "candidate");
        assert_eq!(&args[..4], ["--samples", "31", "--row", "candidate"]);
    }
    #[test]
    fn null_host_pointers_are_rejected_without_access() {
        // SAFETY: null pointers are explicitly rejected before dereference.
        assert_eq!(unsafe { super::parliament_qualification_run(std::ptr::null(), 31, std::ptr::null()) }, 2);
    }
}
