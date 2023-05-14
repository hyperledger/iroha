//! Contains riffle iterator and related trait

/// Iterator which combine two iterators into the single one.
/// Name is inspired by riffle shuffle of cards deck.
///
/// TODO: Proper test with assertions and explanations.
/// ```
/// use iroha_primitives::riffle_iter::RiffleIter;
///
/// let a = vec![1, 2, 3, 4, 5];
/// let b = vec![10, 20, 30];
/// let mut r = a.into_iter().riffle(b);
/// assert_eq!(r.next(), Some(1));
/// assert_eq!(r.next(), Some(10));
/// assert_eq!(r.next(), Some(2));
/// assert_eq!(r.next(), Some(20));
/// assert_eq!(r.next(), Some(3));
/// assert_eq!(r.next(), Some(30));
/// assert_eq!(r.next(), Some(4));
/// assert_eq!(r.next(), Some(5));
/// ```
#[derive(Clone)]
pub struct RiffleIterator<A, B> {
    left_iter: A,
    right_iter: B,
    state: RiffleState,
}

#[derive(Clone, Copy)]
enum RiffleState {
    CurrentLeft,
    CurrentRight,
    LeftExhausted,
    RightExhausted,
    BothExhausted,
}

/// Trait to create [`RiffleIterator`] from two iterators.
pub trait RiffleIter: Iterator + Sized {
    /// Create `RoundRobinIterator` from two iterators.
    fn riffle<I: IntoIterator<Item = Self::Item>>(
        self,
        iter: I,
    ) -> RiffleIterator<Self, <I as IntoIterator>::IntoIter> {
        RiffleIterator {
            left_iter: self,
            right_iter: iter.into_iter(),
            state: RiffleState::CurrentLeft,
        }
    }
}

impl<T: Iterator> RiffleIter for T {}

impl<A, B, T> Iterator for RiffleIterator<A, B>
where
    A: Iterator<Item = T>,
    B: Iterator<Item = T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        use RiffleState::*;
        loop {
            match self.state {
                BothExhausted => break None,
                LeftExhausted => {
                    let item = self.right_iter.next();
                    if item.is_none() {
                        self.state = BothExhausted;
                    }
                    break item;
                }
                RightExhausted => {
                    let item = self.left_iter.next();
                    if item.is_none() {
                        self.state = BothExhausted;
                    }
                    break item;
                }
                CurrentLeft => {
                    let item = self.left_iter.next();
                    if item.is_none() {
                        self.state = LeftExhausted;
                        continue;
                    }
                    self.state = CurrentRight;
                    break item;
                }
                CurrentRight => {
                    let item = self.right_iter.next();
                    if item.is_none() {
                        self.state = RightExhausted;
                        continue;
                    }
                    self.state = CurrentLeft;
                    break item;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn riffle_iter_a_eq_b_size() {
        let a = vec![0, 2, 4, 6, 8];
        let b = vec![1, 3, 5, 7, 9];
        assert_eq!(
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            a.into_iter().riffle(b).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn riffle_iter_a_gt_b_size() {
        let a = vec![0, 2, 4, 6, 8];
        let b = vec![1, 3, 5];
        assert_eq!(
            vec![0, 1, 2, 3, 4, 5, 6, 8],
            a.into_iter().riffle(b).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn riffle_iter_a_lt_b_size() {
        let a = vec![0, 2, 4];
        let b = vec![1, 3, 5, 7, 9];
        assert_eq!(
            vec![0, 1, 2, 3, 4, 5, 7, 9],
            a.into_iter().riffle(b).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn riffle_iter_a_empty() {
        let a = vec![0, 2, 4, 6, 8];
        let b = Vec::new();
        assert_eq!(
            vec![0, 2, 4, 6, 8],
            a.into_iter().riffle(b).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn riffle_iter_b_empty() {
        let a = Vec::new();
        let b = vec![1, 3, 5, 7, 9];
        assert_eq!(
            vec![1, 3, 5, 7, 9],
            a.into_iter().riffle(b).collect::<Vec<u8>>()
        );
    }
}
