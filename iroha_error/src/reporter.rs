//! Module with panic and error reporters

#![allow(clippy::print_stdout)]

use std::env;
use std::fmt::{self, Debug, Display, Formatter};
use std::panic::{self, PanicInfo};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{error::Error as StdError, ptr};

use owo_colors::OwoColorize;

use super::Error;

#[derive(Clone, Copy, Debug)]
struct Backtrace;

impl Display for Backtrace {
    #[allow(clippy::unwrap_used)]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        macro_rules! try_writeln {
            ($res:expr, $dst:expr, $($arg:tt)*) => {
                if let Err(e) = writeln!($dst, $($arg)*) {
                    $res = Err(e);
                    return;
                }
            }
        }

        const SKIPPED: &[&str] = &[
            "backtrace::backtrace::",
            "iroha_error::reporter",
            "std::panicking::",
            "std::sys_common::backtrace",
            "std::panic::catch_unwind",
            "std::rt::",
            "_main",
            "rust_begin_unwind",
            "<std::panic",
            "core::panicking",
            "<iroha_error::reporter::Backtrace as core::fmt::Display>",
            "core::fmt::",
            "alloc::fmt::",
            "core::ops::function",
            "<core::future::from_generator::GenFuture<T>",
            "std::thread::local::",
        ];

        let mut out = Ok(());
        let mut i = 0;

        backtrace::trace(|frame| {
            backtrace::resolve_frame(frame, |symbol| {
                let name = symbol
                    .name()
                    .map_or_else(|| "<unknown_name>".to_owned(), |name| name.to_string());
                if SKIPPED.iter().any(|skip| name.starts_with(skip)) {
                    return;
                }

                let addr = symbol.addr().unwrap_or(ptr::null_mut());
                let filename = symbol
                    .filename()
                    .and_then(|name| {
                        let buf = name.to_path_buf();
                        buf.strip_prefix(env::current_dir().ok()?)
                            .ok()
                            .map(Path::to_path_buf)
                    })
                    .map_or_else(
                        || "<unknown_file>".to_owned(),
                        |name| name.into_os_string().into_string().unwrap(),
                    );
                let lineno = symbol.lineno().unwrap_or(0);
                let colno = symbol.colno().unwrap_or(0);

                let file = format!("{}:{}:{}", filename, lineno, colno);

                try_writeln!(out, f, "{:6}: {}", i.red(), name.yellow());
                try_writeln!(out, f, "{:12}at {}", "", file.green());
                try_writeln!(out, f, "{:12}at addr {:p}", "", addr.blue());

                i += 1;
            });

            true
        });

        out
    }
}

/// Error reporter. Can be used like this:
/// ```rust,should_panic
/// use iroha_error::{Reporter, error, Result};
///
/// fn always_error() -> Result<()> {
///     Err(error!("Will always panic"))
/// }
///
/// fn main() -> Result<(), Reporter> {
///     always_error()?;
///     Ok(())
/// }
/// ```
pub struct Reporter(pub Error);

impl<E: StdError + Send + Sync + 'static> From<E> for Reporter {
    fn from(error: E) -> Self {
        Self(Error::new(error))
    }
}

impl From<Error> for Reporter {
    fn from(error: Error) -> Self {
        Self(error)
    }
}

impl Debug for Reporter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Reporter(error) = &self;
        print_error(error, f)
    }
}

impl Display for Reporter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Reporter(error) = &self;
        print_error(error, f)
    }
}

fn print_error(error: &Error, f: &mut Formatter) -> fmt::Result {
    writeln!(f, "{}\n", error.green())?;
    let mut error = error.source();
    let mut indent = 0;

    while let Some(err) = error {
        writeln!(f, "{:>4}: {}", indent.red(), err.yellow())?;
        indent += 1;
        error = err.source();
    }
    Ok(())
}

fn panic_hook(info: &PanicInfo<'_>) {
    let payload = info.payload();
    let location = if let Some(location) = info.location() {
        format!(
            "{}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        )
    } else {
        "Error at <unknown>".to_owned()
    };
    #[allow(clippy::option_if_let_else)]
    let payload = if let Some(error) = payload.downcast_ref::<String>() {
        error.red().to_string()
    } else {
        "".to_owned()
    };

    println!("{} {}:\n", "Error at".green(), location.red());
    println!("\t{}", payload);
    println!(
        "\n{}\n{:>4}",
        "Backtrace:".underline().yellow(),
        Backtrace.to_string().red()
    );
}

/// Hook that signals that panic hook is set. (it should be set once)
static HOOK_SET: AtomicBool = AtomicBool::new(false);

/// Failed to install error reporter
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InstallError;

impl Display for InstallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to install panic hook.")
    }
}

impl StdError for InstallError {}

/// Installs panic hook for printing errors. Usually set up at the beginning of program.
pub fn install() {
    if HOOK_SET
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    panic::set_hook(Box::new(panic_hook));
}
