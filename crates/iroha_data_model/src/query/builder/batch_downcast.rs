#[cfg(not(feature = "std"))]
use alloc::vec::{self, Vec};
#[cfg(feature = "std")]
use std::vec;

use crate::query::{QueryOutputBatchBox, QueryOutputBatchBoxTuple};

#[derive(Debug)]
pub struct TypedBatchIterUntupled<T> {
    t: vec::IntoIter<T>,
}

impl<T> Iterator for TypedBatchIterUntupled<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.t.next()
    }
}

impl<T> ExactSizeIterator for TypedBatchIterUntupled<T> {
    fn len(&self) -> usize {
        self.t.len()
    }
}

#[derive(Debug, Copy, Clone, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum TypedBatchDowncastError {
    /// Not enough slices in the tuple
    NotEnoughSlices,
    /// Too many slices in the tuple
    TooManySlices,
    /// Wrong type at index {0}
    WrongType(usize),
}

pub trait HasTypedBatchIter {
    type TypedBatchIter: Iterator<Item = Self> + ExactSizeIterator;
    fn downcast(
        erased_batch: QueryOutputBatchBoxTuple,
    ) -> Result<Self::TypedBatchIter, TypedBatchDowncastError>;
}

impl<T> HasTypedBatchIter for T
where
    Vec<T>: TryFrom<QueryOutputBatchBox>,
{
    type TypedBatchIter = TypedBatchIterUntupled<T>;
    fn downcast(
        erased_batch_tuple: QueryOutputBatchBoxTuple,
    ) -> Result<Self::TypedBatchIter, TypedBatchDowncastError> {
        let mut iter = erased_batch_tuple.tuple.into_iter();
        let t1 = iter
            .next()
            .ok_or(TypedBatchDowncastError::NotEnoughSlices)?;
        if iter.next().is_some() {
            return Err(TypedBatchDowncastError::TooManySlices);
        }

        let t1 = <Vec<T> as TryFrom<QueryOutputBatchBox>>::try_from(t1)
            .ok()
            .ok_or(TypedBatchDowncastError::WrongType(0))?
            .into_iter();

        Ok(TypedBatchIterUntupled { t: t1 })
    }
}

macro_rules! typed_batch_tuple {
    // (@repeat_none @recur) => {};
    // (@repeat_none @recur $dummy1:ident $($rest:ident)*) => {
    //     None, typed_batch_tuple!(@repeat_none @recur $($rest)*)
    // };
    // (@repeat_none $($rest:ident)*) => {
    //     (typed_batch_tuple!(@repeat_none @recur $($rest)*))
    // };
    // (@first $first:tt $($rest:tt)*) => { $first };
    (
        $(
            $name:ident($($ty_name:ident: $ty:ident),+);
        )*
    ) => {
        $(
            #[derive(Debug)]
            pub struct $name<$($ty),+> {
                $($ty_name: vec::IntoIter<$ty>),+
            }

            impl<$($ty),+> Iterator for $name<$($ty),+> {
                type Item = ($($ty,)+);
                #[allow(unreachable_patterns)] // for batch size the panic will be unreachable. this is fine
                fn next(&mut self) -> Option<Self::Item> {
                    $(
                        let $ty_name = self.$ty_name.next();
                    )+

                    match ($($ty_name,)+) {
                        ( $(Some($ty_name),)+ ) => Some(($($ty_name,)+)),
                        ( $(None::<$ty>,)* ) => None,
                        _ => panic!("BUG: TypedBatch length mismatch"),
                    }
                }
            }

            impl<$($ty),+> ExactSizeIterator for $name<$($ty),+> {
                #[allow(unreachable_code)]
                fn len(&self) -> usize {
                    // the length of all the iterators in the batch tuple should be the same
                    // HACK: get the length of the first iterator, making the code for other branches unreachable
                    $(return self.$ty_name.len();)+
                }
            }

            impl<$($ty),+> HasTypedBatchIter for ($($ty,)+)
            where
                $(Vec<$ty>: TryFrom<QueryOutputBatchBox>),+
            {
                type TypedBatchIter = $name<$($ty),+>;
                #[expect(unused_assignments)] // the last increment of `index` will be unreachable. this is fine
                fn downcast(
                    erased_batch: QueryOutputBatchBoxTuple,
                ) -> Result<Self::TypedBatchIter, TypedBatchDowncastError> {
                    let mut iter = erased_batch.tuple.into_iter();
                    $(
                        let $ty_name = iter
                            .next()
                            .ok_or(TypedBatchDowncastError::NotEnoughSlices)?;
                    )+
                    if iter.next().is_some() {
                        return Err(TypedBatchDowncastError::TooManySlices);
                    }

                    let mut index = 0;
                    $(
                        let $ty_name = <Vec<$ty> as TryFrom<QueryOutputBatchBox>>::try_from($ty_name)
                            .ok()
                            .ok_or(TypedBatchDowncastError::WrongType(index))?
                            .into_iter();
                        index += 1;
                    )+

                    Ok($name {
                        $($ty_name),+
                    })
                }
            }
        )*
    };
}

typed_batch_tuple! {
    TypedBatch1(t1: T1);
    TypedBatch2(t1: T1, t2: T2);
    TypedBatch3(t1: T1, t2: T2, t3: T3);
    TypedBatch4(t1: T1, t2: T2, t3: T3, t4: T4);
    TypedBatch5(t1: T1, t2: T2, t3: T3, t4: T4, t5: T5);
    TypedBatch6(t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6);
    TypedBatch7(t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6, t7: T7);
    TypedBatch8(t1: T1, t2: T2, t3: T3, t4: T4, t5: T5, t6: T6, t7: T7, t8: T8);
    // who needs more than 8 values in their query, right?
}

// pub struct QueryIterator<T>
// where
//     T: HasTypedBatchIter,
// {
//     batch: T::TypedBatchIter,
//     // TODO: include the query executor in here
// }
//
// impl<T> QueryIterator<T>
// where
//     T: HasTypedBatchIter,
// {
//     pub fn new(first_batch: QueryOutputBatchBoxTuple) -> Result<Self, TypedBatchDowncastError> {
//         let batch = T::downcast(first_batch)?;
//
//         Ok(Self { batch })
//     }
// }
//
// impl<T> Iterator for QueryIterator<T>
// where
//     T: HasTypedBatchIter,
// {
//     type Item = Result<T, ()>;
//
//     fn next(&mut self) -> Option<Self::Item> {
//         if let Some(item) = self.batch.next() {
//             return Some(Ok(item));
//         }
//
//         // TODO: request next batch
//         None
//     }
// }
