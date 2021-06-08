use std::error::Error as StdError;
use std::fmt::{self, Debug, Display};

/// Error type used for simple messages
#[derive(Eq, PartialEq, Clone)]
pub struct MessageError<D> {
    /// message field
    pub msg: D,
}

impl<M: Debug> Debug for MessageError<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.msg, f)
    }
}

impl<M: Display> Display for MessageError<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.msg, f)
    }
}

impl<M: Display + Debug + 'static> StdError for MessageError<M> {}

impl<D> MessageError<D> {
    /// Constructor for [`MessageError`]
    pub const fn new(msg: D) -> Self {
        Self { msg }
    }
}
