//! Module containing operations and their priorities.

/// Type of expression operation.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Operation {
    MethodCall,
    RaiseTo,
    Multiply,
    Divide,
    Mod,
    Add,
    Subtract,
    Greater,
    Less,
    Equal,
    Not,
    And,
    Or,
    Other,
}

/// Priority of operation.
///
/// [`First`](Operation::First) is the highest priority
/// and [`Eight`](Operation::Eight) is the lowest.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Priority {
    First,
    Second,
    Third,
    Fourth,
    Fifth,
    Sixth,
    Seventh,
    Eighth,
    Ninth,
}

impl Operation {
    /// Get the priority of the operation.
    ///
    /// Ordering is the same as in Python code.
    /// See [`here`](https://docs.python.org/3/reference/expressions.html#operator-precedence)
    /// for more details.
    pub fn priority(self) -> Priority {
        use Operation::*;
        use Priority::*;

        match self {
            MethodCall => First,
            RaiseTo => Second,
            Multiply | Divide | Mod => Third,
            Add | Subtract => Fourth,
            Greater | Less | Equal => Fifth,
            Not => Sixth,
            And => Seventh,
            Or => Eighth,
            Other => Ninth,
        }
    }
}

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering::*;

        let lhs = *self as u8;
        let rhs = *other as u8;

        match lhs.cmp(&rhs) {
            Less => Greater,
            Equal => Equal,
            Greater => Less,
        }
    }
}
