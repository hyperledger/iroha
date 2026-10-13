//! Exact original-pool backing for the shared native source verifier kernels.

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use std::{
    cell::RefCell,
    fmt,
    ops::{Deref, DerefMut},
};

/// A resource refusal remains distinct from the verifier's protocol rejection.
#[derive(Debug)]
pub enum AttemptError<E> {
    Protocol(E),
    Allocation(ChargedBufferError),
}

/// One call's explicit allocation source and its first unformatted refusal.
pub struct Memory<'a> {
    budget: Option<&'a AllocationBudget>,
    refusal: RefCell<Option<ChargedBufferError>>,
}

impl<'a> Memory<'a> {
    pub fn detached() -> Self {
        Self {
            budget: None,
            refusal: RefCell::new(None),
        }
    }

    pub fn admitted(budget: &'a AllocationBudget) -> Self {
        Self {
            budget: Some(budget),
            refusal: RefCell::new(None),
        }
    }

    pub fn finish<T, E>(&self, result: Result<T, E>) -> Result<T, AttemptError<E>> {
        self.take_refusal().map_or_else(
            || result.map_err(AttemptError::Protocol),
            |error| Err(AttemptError::Allocation(error)),
        )
    }

    pub fn take_refusal(&self) -> Option<ChargedBufferError> {
        self.refusal.borrow_mut().take()
    }

    pub fn buffer<T>(&self, capacity: usize) -> Option<Buffer<T>> {
        let result = self.budget.map_or_else(
            || {
                let mut buffer = Vec::new();
                buffer
                    .try_reserve_exact(capacity)
                    .map(|()| Buffer::Detached(buffer))
                    .map_err(|_| ChargedBufferError::Allocator {
                        requested_bytes: capacity.saturating_mul(size_of::<T>()),
                    })
            },
            |budget| ChargedBuffer::new(capacity, budget).map(Buffer::Admitted),
        );
        match result {
            Ok(buffer) => Some(buffer),
            Err(error) => {
                let mut refusal = self.refusal.borrow_mut();
                if refusal.is_none() {
                    *refusal = Some(error);
                }
                None
            }
        }
    }

    pub fn copy<T: Copy>(&self, data: &[T]) -> Option<Buffer<T>> {
        let mut buffer = self.buffer(data.len())?;
        buffer.extend_from_slice(data)?;
        Some(buffer)
    }

    pub fn filled<T: Copy>(&self, count: usize, value: T) -> Option<Buffer<T>> {
        let mut buffer = self.buffer(count)?;
        for _ in 0..count {
            buffer.push(value)?;
        }
        Some(buffer)
    }
}

/// Move-only actual backing; the native variant releases its charge after deallocation.
pub enum Buffer<T> {
    Detached(Vec<T>),
    Admitted(ChargedBuffer<T>),
}

impl<T> Buffer<T> {
    pub fn push(&mut self, value: T) -> Option<()> {
        match self {
            Self::Detached(buffer) => {
                buffer.push(value);
                Some(())
            }
            Self::Admitted(buffer) => buffer.try_push(value).ok(),
        }
    }

    pub fn extend_from_slice(&mut self, values: &[T]) -> Option<()>
    where
        T: Copy,
    {
        for value in values {
            self.push(*value)?;
        }
        Some(())
    }

    pub fn pop(&mut self) -> Option<T> {
        match self {
            Self::Detached(v) => v.pop(),
            Self::Admitted(v) => v.pop(),
        }
    }

    pub fn truncate(&mut self, len: usize) {
        match self {
            Self::Detached(v) => v.truncate(len),
            Self::Admitted(v) => v.truncate(len),
        }
    }

    pub fn as_slice(&self) -> &[T] {
        self
    }

    pub fn into_detached(self) -> Option<Vec<T>> {
        match self {
            Self::Detached(buffer) => Some(buffer),
            Self::Admitted(_) => None,
        }
    }
}

impl<T> Deref for Buffer<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        match self {
            Self::Detached(buffer) => buffer,
            Self::Admitted(buffer) => buffer.as_slice(),
        }
    }
}
impl<T> DerefMut for Buffer<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        match self {
            Self::Detached(buffer) => buffer,
            Self::Admitted(buffer) => buffer.as_mut_slice(),
        }
    }
}
impl<T: fmt::Debug> fmt::Debug for Buffer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(formatter)
    }
}
impl<T: PartialEq> PartialEq for Buffer<T> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl<T: Eq> Eq for Buffer<T> {}
impl<'a, T> IntoIterator for &'a Buffer<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<T> From<Vec<T>> for Buffer<T> {
    fn from(value: Vec<T>) -> Self {
        Self::Detached(value)
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl<T: Clone> Clone for Buffer<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Detached(buffer) => Self::Detached(buffer.clone()),
            Self::Admitted(_) => panic!("native physical owners cannot be cloned"),
        }
    }
}

impl<'a, T> IntoIterator for &'a mut Buffer<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
#[cfg(any(test, feature = "test-fixtures"))]
impl<T> FromIterator<T> for Buffer<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::Detached(iter.into_iter().collect())
    }
}
impl<T: PartialEq> PartialEq<Vec<T>> for Buffer<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for Buffer<T> {
    fn eq(&self, other: &[T; N]) -> bool {
        self.as_slice() == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_backing_refuses_before_construction_and_refunds_only_after_drop() {
        let budget = AllocationBudget::new(16);
        let memory = Memory::admitted(&budget);
        let mut first = memory.buffer::<u64>(2).unwrap();
        first.push(7).unwrap();
        first.push(8).unwrap();
        assert!(first.push(9).is_none());
        assert_eq!(budget.reserved_bytes(), 16);
        assert!(memory.buffer::<u8>(1).is_none());
        assert!(matches!(
            memory.take_refusal(),
            Some(ChargedBufferError::Admission(_))
        ));
        let moved = first;
        assert_eq!(moved.as_slice(), &[7, 8]);
        assert_eq!(budget.reserved_bytes(), 16);
        drop(moved);
        assert_eq!(budget.reserved_bytes(), 0);
        let second = memory.copy(&[1_u8, 2, 3]).unwrap();
        assert_eq!(budget.reserved_bytes(), 3);
        drop(second);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
