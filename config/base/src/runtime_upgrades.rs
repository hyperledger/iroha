//! Module handling runtime upgrade logic.

use std::{
    fmt::Debug,
    sync::{MutexGuard, PoisonError},
};

pub use serde::{Deserialize, Serialize};
use thiserror::*;

type Result<T, E = ReloadError> = std::result::Result<T, E>;

/// Error which occurs when reloading a configuration fails.
#[derive(Clone, Copy, Debug, Error)]
pub enum ReloadError {
    /// The resource held by the handle was poisoned by a panic in
    /// another thread.
    #[error("Resource poisoned.")]
    Poisoned,
    /// The resource held by the handle was dropped.
    #[error("Resource dropped.")]
    Dropped,
    /// If the reload handle wasn't properly initialized (using
    /// [`handle::Singleton::set`]), there's nothing to reload with.
    #[error("Cannot reload an uninitialized handle.")]
    NotInitialized,
    /// Error not specified by the implementer of the [`Reload`]
    /// traits. Use as last resort.
    #[error("Unspecified reload failure.")]
    Other,
}

type PoisonErr<'grd, T> =
    PoisonError<MutexGuard<'grd, Option<Box<(dyn ReloadMut<T> + Send + Sync)>>>>;

impl<T> From<PoisonErr<'_, T>> for ReloadError {
    fn from(_: PoisonErr<'_, T>) -> Self {
        Self::Poisoned
    }
}

/// The field needs to be mutably borrowed to be reloaded.
pub trait ReloadMut<T>: Debug {
    // TODO: When negative traits/specialisation, remove Debug

    /// Reload `self` using provided `item`.
    ///
    /// # Errors
    /// Fails with an appropriate variant of
    /// [`ReloadError`]. [`ReloadError::Other`] can be used as a
    /// **temporary** placeholder.
    fn reload(&mut self, item: T) -> Result<()>;
}

/// The field can be immutably borrowed and reloaded.
pub trait Reload<T> {
    /// Reload `self` using provided `item`.
    ///
    /// # Errors
    /// Fails with an appropriate variant of [`ReloadError`].
    /// [`ReloadError::Other`] can be used as a **temporary** placeholder.
    fn reload(&self, item: T) -> Result<()>;
}

/// Contains [`handle`] types: opaque wrappers around a reloadable
/// configuration, used to embed reloading functionality into
/// various [`iroha_config_derive::Configurable`] types.
///
/// # Architecture.
///
/// ## Desired behaviour
///
/// Given a value of type (`<T = LogLevel>` in this module), need to
///
/// -  Embed a handle into the configuration options, replacing a Value
/// of type <T> with a handle.
///
/// - The handle gets (de)serialized as if it were `<T>`: no extra
/// fields, no extra initialisation.
///
/// - The configuration as a whole is immutable. This is to ensure
/// that you don't accidentally re-assign the handle.
///
/// - The last object that got instantiated from the configuration
/// file is modified when we call [`Reload::reload`].
///
/// - The value used to [`Reload::reload`] the value, must be reflected in the
/// configuration.
///
/// ## Additional considerations
///
/// - The handle might have internal mutable state, and be passed
/// along several threads in both a `sync` and `async` context.
///
/// - The handle's state can be a global mutable static value behind a
/// wrapper.
///
/// - The handle is almost never read. All interactions with the
/// handle are writes.
///
/// - The handle can retain a reference to different types, depending
/// on the configuration options. The types might not all be known
/// ahead of time, or be impractically long (both true for
/// `tracting_subscriber::reload::Handle`).
///
/// # Usage
///
/// Embed a `SyncValue<T, H: super::Reload<T>>`, in your
/// configuration options.  When using the configuration to initialise
/// components, call [`handle::SyncValue::set_handle`], on a value that
/// implements [`ReloadMut`] (which you defined earlier). Call
/// [`handle::SyncValue::reload`] to change the configuration at run-time.
///
/// If the type stored in `H` is a single simple type, it is
/// recommended to use a custom tuple `struct`, and `impl`
/// [`Reload`] for it.
///
/// If the types are too varied, or generic in arguments that change
/// depending on run-time values, (as in
/// e.g. `tracing_subscriber::reload::Handle`), it is recommended to
/// instead use the provided opaque wrapper [`handle::Singleton`].
///
/// **NOTE** you shouldn't normally need to use either
/// [`handle::Singleton`] or [`handle::Value`] directly.
///
/// # Examples
/// ```rust,ignore
/// use iroha_config_derive::Configurable;
/// use serde::{Deserialize, Serialize};
/// use iroha_config::runtime_upgrades::{handle, Reload, ReloadMut, ReloadError};
/// use tracing::Level;
/// use tracing_subscriber::{reload::Handle, filter::LevelFilter};
/// use std::fmt::Debug;
///
/// struct Logger;
///
/// #[derive(Clone, Deserialize, Serialize, Debug, Configurable)]
/// struct Configuration {
///     pub max_log_level: handle::SyncValue<Level, handle::Singleton<Level>>,
///     pub log_file_path: Option<std::path::PathBuf>,
/// }
///
/// fn init(config: &Configuration) -> Logger {
///     let level = config.max_log_level.value();
///     let level_filter = tracing_subscriber::filter::LevelFilter::from_level(level);
///     let (filter, handle) = reload::Layer::new(level_filter);
///     config.max_log_level.set_handle(handle).unwrap();
/// }
///
/// impl<T: Subscriber + Debug> ReloadMut<Level> for Handle<LevelFilter, T> {
///    fn reload(&mut self, level: Level) -> Result<(), ReloadError> {
///         let level_filter = LevelFilter::from_level(level);
///         Handle::reload(self, level_filter).map_err(|_todo| ReloadError::Dropped)
///    }
/// }
/// ```

pub mod handle {
    use std::{
        fmt::{Debug, Formatter},
        sync::{Arc, Mutex},
    };

    use crossbeam::atomic::AtomicCell;
    use serde::{Deserialize, Serialize};

    use super::{Reload, ReloadError, ReloadMut, Result};
    // -----------------------------------------------------------------

    /// An opaque handle for arbitrary [`super::ReloadMut<T>`], useful
    /// when it is either impossible or impractical to specify a
    /// single `enum` or generic type.  You shouldn't embed this into
    /// your configuration, and instead use [`SyncValue`].
    #[derive(Clone, Serialize, Deserialize)]
    pub struct Singleton<T: Send + Sync> {
        #[serde(skip)]
        inner: Arc<Mutex<Option<Box<dyn ReloadMut<T> + Send + Sync>>>>,
    }

    impl<T: Send + Sync> Default for Singleton<T> {
        fn default() -> Self {
            Self {
                inner: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl<T: Send + Sync> Singleton<T> {
        /// Set and/or initialize the [`Self`] to a non-empty value.
        /// Reloading before calling this `fn` should cause
        /// [`ReloadError::NotInitialized`].
        ///
        /// # Errors
        /// [`ReloadError::Poisoned`] When the [`Mutex`] storing the reload handle is poisoned.
        pub fn set(&self, handle: impl ReloadMut<T> + Send + Sync + 'static) -> Result<()> {
            *self.inner.lock()? = Some(Box::new(handle));
            Ok(())
        }
    }

    impl<T: Debug + Send + Sync> Debug for Singleton<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Handle with side effect").finish()
        }
    }

    impl<T: Send + Sync + Debug> Reload<T> for Singleton<T> {
        fn reload(&self, item: T) -> Result<()> {
            match &mut *self.inner.lock()? {
                Some(handle) => {
                    handle.reload(item)?;
                    Ok(())
                }
                None => Err(ReloadError::NotInitialized),
            }
        }
    }

    // ---------------------------------------------------------------

    /// A run-time reloadable configuration option with
    /// value-semantics.  This means that reloading a [`Value`] only
    /// affects the [`Value`] itself. It's useful when you want to
    /// keep a configuration immutable, but retain thread-safe
    /// interior mutability, which is preferable to making the entire
    /// configuration `mut`.
    ///
    /// # Examples
    /// ```ignore
    /// use serde::{Serialize, Deserialize};
    /// use  iroha_config::runtime_upgrades::{handle::Value, Reload};
    ///
    /// #[derive(iroha_config::derive::Configurable, Serialize, Deserialize)]
    /// pub struct Config { option: Value<bool> }
    ///
    /// fn main() {
    ///    let c = Config { option: true.into() };
    ///
    ///    c.option.reload(false);
    /// }
    /// ```
    ///
    /// If you wish to perform validation on the value, consider using
    /// a thin wrapper `tuple` struct.
    ///
    #[derive(Debug)]
    pub struct Value<T: Clone + Copy>(pub AtomicCell<T>);

    impl<T: Clone + Copy> Clone for Value<T> {
        fn clone(&self) -> Self {
            Self(AtomicCell::new(self.0.load()))
        }
    }

    impl<T: Clone + Copy> From<T> for Value<T> {
        fn from(value: T) -> Self {
            Self(AtomicCell::new(value))
        }
    }

    impl<T: Default + Clone + Copy> Default for Value<T> {
        fn default() -> Self {
            Self(AtomicCell::default())
        }
    }

    impl<T: Clone + Copy> Reload<T> for Value<T> {
        fn reload(&self, item: T) -> Result<()> {
            self.0.swap(item);
            Ok(())
        }
    }

    impl<'de, T: Deserialize<'de> + Copy + Clone> Deserialize<'de> for Value<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(AtomicCell::new(T::deserialize(deserializer)?)))
        }
    }

    impl<T: Serialize + Clone + Copy> Serialize for Value<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            (self.0.load()).serialize(serializer)
        }
    }

    // -----------------------------------------------------------------------

    /// Structure that encapsulates a configuration value as well as a
    /// handle for reloading other parts of the program.  This is the
    /// `struct` that you want to use 99% of the time.
    ///
    /// It handles automatic synchronisation of the current value from
    /// the reload, as well as proper (de)serialization: namely the
    /// handle doesn't pollute your configuration options.
    pub struct SyncValue<T: Clone + Copy, H: Reload<T>>(Value<T>, H);

    impl<T: Clone + Copy, H: Reload<T>> SyncValue<T, H> {
        /// Getter for the wrapped [`Value`]
        pub fn value(&self) -> T {
            self.0 .0.load()
        }
    }

    impl<T: Clone + Copy + Send + Sync + Debug> SyncValue<T, Singleton<T>> {
        /// Set the handle
        ///
        /// # Errors
        /// If [`Singleton::set`] fails.
        pub fn set_handle(&self, other: impl ReloadMut<T> + Send + Sync + 'static) -> Result<()> {
            self.1.set(other)
        }
    }

    impl<T: Clone + Copy, H: Reload<T> + Clone> Clone for SyncValue<T, H> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }

    impl<T: Clone + Copy + Debug, H: Reload<T> + Debug> Debug for SyncValue<T, H> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("Reconfigure")
                .field(&self.0)
                .field(&self.1)
                .finish()
        }
    }

    impl<T> Default for SyncValue<T, Singleton<T>>
    where
        T: Default + Clone + Copy + Send + Sync + Debug,
    {
        fn default() -> Self {
            Self(Value::default(), Singleton::default())
        }
    }

    impl<T: Clone + Copy, H: Reload<T> + Default> From<T> for SyncValue<T, H> {
        fn from(value: T) -> Self {
            Self(Value(AtomicCell::new(value)), H::default())
        }
    }

    impl<T: Serialize + Clone + Copy, H: Reload<T>> Serialize for SyncValue<T, H> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            // We only want the actual (simple) value to be part of the serializing
            self.0.serialize(serializer)
        }
    }

    impl<'de, T: Deserialize<'de> + Copy + Clone, H: Reload<T> + Default> Deserialize<'de>
        for SyncValue<T, H>
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(Value::<T>::deserialize(deserializer)?, H::default()))
        }
    }

    impl<T: Clone + Copy, H: Reload<T>> Reload<T> for SyncValue<T, H> {
        fn reload(&self, item: T) -> Result<()> {
            self.1.reload(item)?;
            self.0.reload(item)
        }
    }
}
