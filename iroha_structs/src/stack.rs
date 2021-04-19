//! Stack module

use std::ops::{Deref, DerefMut};

/// Stack
#[derive(Debug)]
pub struct Stack<T>(lockfree::stack::Stack<T>);

impl<T> Default for Stack<T> {
    fn default() -> Self {
        Self(lockfree::stack::Stack::new())
    }
}

impl<T> Deref for Stack<T> {
    type Target = lockfree::stack::Stack<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Stack<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
