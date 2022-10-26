//! Ergonomic log-and-ignore syntax.

/// Trait used to pipeline the common log-and-ignore pattern by
/// providing better handling of the process, and a clearer more
/// expressive syntax.
pub trait Logged {
    /// Log the provided value. Useful for logging objects in a chain
    /// of events, or before the `?` operator.
    #[must_use]
    fn logged(self) -> Self;

    /// Ignore the provided error.
    ///
    /// # Motivation
    ///
    /// Sometimes errors cannot be sensibly handled, they can only be
    /// reported to the user. If the error isn't handled further this
    /// allows one to cheaply explain to the user of the debug build
    /// **why** a particular error cannot be ignored.  More
    /// importantly when one sees an explicit
    /// ```rust
    /// err.logged().ignore("I can't handle this error because of X")
    /// ```
    /// the reader of the code doesn't need to be provided
    /// with a comment as to why the error message was ignored
    #[inline]
    fn ignored(self, reason: &str)
    where
        Self: Sized,
    {
        #[cfg(debug_assertions)]
        crate::debug!(reason, "Ignored");
    }

    /// Promote the error from a lower log level to `ERROR`.
    ///
    /// # Motivation
    ///
    /// The implementation of `Logged` assumes that most errors have a
    /// log level that's strictly between `DEBUG` and `ERROR`, in most
    /// cases, but in some contexts, while they can still only be
    /// logged and ignored, they signal a configuration issue and call
    /// for the user's attention.
    #[inline]
    fn promoted(self) -> ImportantError<Self>
    where
        Self: Sized + core::fmt::Debug,
    {
        ImportantError(self)
    }
}

impl<T, E: Logged> Logged for core::result::Result<T, E> {
    #[inline]
    fn logged(self) -> Self {
        self.map_err(E::logged)
    }
}

impl<T> Logged for tokio::sync::broadcast::error::SendError<T> {
    #[inline]
    fn logged(self) -> Self {
        crate::warn!("Some `{}` Failed to send", std::any::type_name::<T>());
        self
    }
}

impl<T> Logged for tokio::sync::mpsc::error::SendError<T> {
    #[inline]
    fn logged(self) -> Self {
        crate::error!("Some `{}` Failed to send", std::any::type_name::<T>());
        self
    }
}

#[must_use]
/// An instance of `Logged` temporarily promoted to an important
/// error. This object deliberately has neither logic nor standard
/// trait implementations as it's only meant for printing.
pub struct ImportantError<T: Logged + core::fmt::Debug>(T);

impl<T: Logged + core::fmt::Debug> ImportantError<T> {
    /// Log part of the log-and-ignore
    #[inline]
    pub fn logged(self) -> Self {
        crate::error!("{:?}", self.0);
        self
    }

    /// ignore part of the log-and-ignore.
    #[inline]
    pub fn ignored(self, message: &str) {
        crate::info!("HELP: {message}");
    }
}

// TODO: this should really be a `derive`.

/// Derive macro substitute for implementing `Logged`.
#[macro_export]
macro_rules! impl_logged {
    (%$typ:ty => $lvl:ident) => {
        impl $crate::error::Logged for $typ {
            #[inline]
            fn logged(self) -> Self {
                $crate::$lvl!("{self}");
                self
            }
        }
    };
    (?$typ:ty => $lvl:ident) => {
        impl $crate::error::Logged for $typ {
            #[inline]
            fn logged(self) -> Self {
                #[cfg(debug_assertions)]
                $crate::$lvl!("{self:?}");
                #[cfg(not(debug_assertions))]
                $crate::$lvl!("{self}");
                self
            }
        }
    };
}

impl_logged!(?color_eyre::eyre::Report => warn);
impl_logged!(?tokio::task::JoinError => error);

impl Logged for std::vec::Vec<color_eyre::eyre::Report> {
    #[inline]
    fn logged(self) -> Self {
        crate::warn!("The following {} errors have occurred:", self.len());
        self.into_iter().map(Logged::logged).collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    pub fn setup_logger() {
        let config = iroha_config::logger::Configuration {
            max_log_level: crate::Level::TRACE.into(),
            telemetry_capacity: 100,
            compact_mode: true,
            log_file_path: None,
            terminal_colors: true,
        };
        crate::init(&config).unwrap().unwrap();
    }

    #[test]
    fn test_name() {
        setup_logger();
        color_eyre::eyre::eyre!("eyre::hello world")
            .wrap_err("Some traceback")
            .logged()
            .ignored("Not an error");
    }
}
