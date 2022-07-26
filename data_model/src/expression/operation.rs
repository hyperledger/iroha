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
    First = 1,
    Second = 2,
    Third = 3,
    Fourth = 4,
    Fifth = 5,
    Sixth = 6,
    Seventh = 7,
    Eighth = 8,
    Ninth = 9,
}

impl Operation {
    /// Get the priority of the operation.
    ///
    /// Ordering is the same as in Python code.
    /// See [`here`](https://docs.python.org/3/reference/expressions.html#operator-precedence)
    /// for more details.
    pub fn priority(self) -> Priority {
        use Operation::*;

        match self {
            MethodCall => Priority::First,
            RaiseTo => Priority::Second,
            Multiply | Divide | Mod => Priority::Third,
            Add | Subtract => Priority::Fourth,
            Greater | Less | Equal => Priority::Fifth,
            Not => Priority::Sixth,
            And => Priority::Seventh,
            Or => Priority::Eighth,
            Other => Priority::Ninth,
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
