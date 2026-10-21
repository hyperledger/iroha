use crate::{
    account::{Account, AccountId},
    asset::{AssetDefinitionId, AssetId, definition::AssetDefinition, value::Asset},
    block::{BlockHeader, SignedBlock},
    domain::Domain,
    escrow::AssetEscrowRecord,
    asset::uid::AssetUidPolicyViewV1,
    asset::uid_enrollment::AssetUidEnrollmentViewV1,
    asset::fi_link::AssetFiRelationshipViewV1,
    events::data::oracle::FeedEventRecord,
    nft::{Nft, NftId},
    oracle::{
        FeedConfig, OracleChangeProposal, OracleDispute, OracleProviderStatsRecord,
        TwitterBindingRecord,
    },
    parameter::Parameter,
    permission::Permission,
    proof::ProofRecord,
    query::{CommittedTransaction, QueryOutputBatchBox, QueryOutputBatchBoxTuple},
    repo::RepoAgreement,
    role::{Role, RoleId},
    rwa::{Rwa, RwaId},
    transaction::{TransactionEntrypoint, TransactionResult as TxResultType},
    trigger::{Trigger, TriggerId, action::Action},
};
use iroha_crypto::{HashOf, PublicKey};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_primitives::{json::Json, numeric::Numeric};
use std::vec::{self, Vec};
#[derive(Debug)]
/// Iterator over a single-column typed query batch.
pub struct TypedBatchIterUntupled<T> {
    t: vec::IntoIter<T>,
}
impl<T> Iterator for TypedBatchIterUntupled<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        self.t.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.t.size_hint()
    }
}
impl<T> ExactSizeIterator for TypedBatchIterUntupled<T> {
    fn len(&self) -> usize {
        self.t.len()
    }
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, displaydoc::Display, thiserror::Error)]
/// Error returned when an erased iterable-query batch cannot be downcast.
pub enum TypedBatchDowncastError {
    /// Expected {expected} batch columns, found {actual}
    ColumnCountMismatch {
        /// Number of columns required by the selected result type.
        expected: usize,
        /// Number of columns returned by the query response.
        actual: usize,
    },
    /// Wrong batch type at column {column}
    WrongType {
        /// Zero-based index of the column with an unexpected batch type.
        column: usize,
    },
}
impl From<TypedBatchDowncastError> for crate::executor::ValidationFail {
    fn from(error: TypedBatchDowncastError) -> Self {
        Self::InternalError(error.to_string())
    }
}
mod single_item {
    use super::*;
    /// Sealed marker for result items that can be read from a single batch column.
    pub trait Sealed {}
    macro_rules! impl_single_item {
        ($($ty:path),+ $(,)?) => {
            $(impl Sealed for $ty {})+
        };
    }
    impl_single_item!(
        PublicKey,
        String,
        Metadata,
        Json,
        Numeric,
        Name,
        DomainId,
        Domain,
        AccountId,
        Account,
        AssetId,
        Asset,
        AssetDefinitionId,
        AssetDefinition,
        RepoAgreement,
        NftId,
        Nft,
        RwaId,
        Rwa,
        Role,
        Parameter,
        Permission,
        CommittedTransaction,
        TxResultType,
        HashOf<TxResultType>,
        TransactionEntrypoint,
        HashOf<TransactionEntrypoint>,
        PeerId,
        RoleId,
        TriggerId,
        Trigger,
        Action,
        SignedBlock,
        BlockHeader,
        HashOf<BlockHeader>,
        ProofRecord,
        FeedConfig,
        FeedEventRecord,
        OracleProviderStatsRecord,
        OracleDispute,
        OracleChangeProposal,
        TwitterBindingRecord,
        AssetEscrowRecord,
        AssetUidPolicyViewV1,
        AssetUidEnrollmentViewV1,
        AssetFiRelationshipViewV1,
    );
}
/// Query result item represented by one typed batch column.
pub trait SingleBatchItem: single_item::Sealed {}
impl<T> SingleBatchItem for T where T: single_item::Sealed {}
/// Query result type that can downcast an erased batch into a typed iterator.
pub trait HasTypedBatchIter {
    /// Iterator returned after successful batch downcast.
    type TypedBatchIter: Iterator<Item = Self> + ExactSizeIterator;
    /// Downcast an erased column batch into the iterator for this result type.
    ///
    /// # Errors
    ///
    /// Returns [`TypedBatchDowncastError`] when the batch has the wrong number
    /// of columns or a column contains an unexpected erased type.
    fn downcast(
        erased_batch: QueryOutputBatchBoxTuple,
    ) -> Result<Self::TypedBatchIter, TypedBatchDowncastError>;
}
impl<T> HasTypedBatchIter for T
where
    T: SingleBatchItem,
    Vec<T>: TryFrom<QueryOutputBatchBox>,
{
    type TypedBatchIter = TypedBatchIterUntupled<T>;
    fn downcast(
        erased_batch_tuple: QueryOutputBatchBoxTuple,
    ) -> Result<Self::TypedBatchIter, TypedBatchDowncastError> {
        let actual = erased_batch_tuple.column_count();
        if actual != 1 {
            return Err(TypedBatchDowncastError::ColumnCountMismatch {
                expected: 1,
                actual,
            });
        }
        let mut iter = erased_batch_tuple.into_iter();
        let Some(t1) = iter.next() else {
            return Err(TypedBatchDowncastError::ColumnCountMismatch {
                expected: 1,
                actual: 0,
            });
        };
        let t1 = <Vec<T> as TryFrom<QueryOutputBatchBox>>::try_from(t1)
            .ok()
            .ok_or(TypedBatchDowncastError::WrongType { column: 0 })?
            .into_iter();
        Ok(TypedBatchIterUntupled { t: t1 })
    }
}
macro_rules! typed_batch_tuple {
    (
        $(
            $name:ident($($ty_name:ident: $ty:ident),+);
        )*
    ) => {
        $(
            #[derive(Debug)]
            /// Iterator over rows of a typed multi-column query batch.
            pub struct $name<$($ty),+> {
                $($ty_name: vec::IntoIter<$ty>,)+
                remaining: usize,
            }
            impl<$($ty),+> Iterator for $name<$($ty),+> {
                type Item = ($($ty,)+);
                fn next(&mut self) -> Option<Self::Item> {
                    if self.remaining == 0 {
                        return None;
                    }
                    let row = ($(self.$ty_name.next()?,)+);
                    self.remaining -= 1;
                    Some(row)
                }
                fn size_hint(&self) -> (usize, Option<usize>) {
                    (self.remaining, Some(self.remaining))
                }
            }
            impl<$($ty),+> ExactSizeIterator for $name<$($ty),+> {
                fn len(&self) -> usize {
                    self.remaining
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
                    let expected = 0usize $(+ { let _ = stringify!($ty_name); 1usize })+;
                    let actual = erased_batch.column_count();
                    if actual != expected {
                        return Err(TypedBatchDowncastError::ColumnCountMismatch {
                            expected,
                            actual,
                        });
                    }
                    let remaining = erased_batch.len();
                    let mut iter = erased_batch.into_iter();
                    $(
                        let Some($ty_name) = iter.next() else {
                            return Err(TypedBatchDowncastError::ColumnCountMismatch {
                                expected,
                                actual: 0,
                            });
                        };
                    )+
                    let mut index = 0;
                    $(
                        let $ty_name = <Vec<$ty> as TryFrom<QueryOutputBatchBox>>::try_from($ty_name)
                            .ok()
                            .ok_or(TypedBatchDowncastError::WrongType { column: index })?
                            .into_iter();
                        index += 1;
                    )+
                    Ok($name {
                        $($ty_name,)+
                        remaining,
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
#[cfg(test)]
mod tests {
    use super::*;
    fn numeric(values: &[u32]) -> QueryOutputBatchBox {
        QueryOutputBatchBox::Numeric(values.iter().copied().map(Numeric::from).collect())
    }
    #[test]
    fn downcast_reports_exact_column_count() {
        let one_column = QueryOutputBatchBoxTuple::from_batch(numeric(&[1]));
        let error = <(Numeric, Numeric)>::downcast(one_column)
            .expect_err("two selected values require two columns");
        assert_eq!(
            error,
            TypedBatchDowncastError::ColumnCountMismatch {
                expected: 2,
                actual: 1,
            }
        );
        let two_columns = QueryOutputBatchBoxTuple::new(vec![numeric(&[1]), numeric(&[2])])
            .expect("equal column lengths");
        let error =
            Numeric::downcast(two_columns).expect_err("one selected value requires one column");
        assert_eq!(
            error,
            TypedBatchDowncastError::ColumnCountMismatch {
                expected: 1,
                actual: 2,
            }
        );
    }
    #[test]
    fn downcast_reports_wrong_type_at_each_column() {
        let first_wrong = QueryOutputBatchBoxTuple::new(vec![
            QueryOutputBatchBox::String(vec!["one".to_owned()]),
            numeric(&[2]),
        ])
        .expect("equal column lengths");
        assert_eq!(
            <(Numeric, Numeric)>::downcast(first_wrong).expect_err("first type differs"),
            TypedBatchDowncastError::WrongType { column: 0 }
        );
        let second_wrong = QueryOutputBatchBoxTuple::new(vec![
            numeric(&[1]),
            QueryOutputBatchBox::String(vec!["two".to_owned()]),
        ])
        .expect("equal column lengths");
        assert_eq!(
            <(Numeric, Numeric)>::downcast(second_wrong).expect_err("second type differs"),
            TypedBatchDowncastError::WrongType { column: 1 }
        );
    }
    #[test]
    fn tuple_iterator_tracks_exact_remaining_rows_without_indexing() {
        let batch = QueryOutputBatchBoxTuple::new(vec![numeric(&[1, 2]), numeric(&[10, 20])])
            .expect("equal column lengths");
        let mut iter = <(Numeric, Numeric)>::downcast(batch).expect("matching types");
        assert_eq!(iter.len(), 2);
        assert_eq!(iter.size_hint(), (2, Some(2)));
        assert_eq!(
            iter.next(),
            Some((Numeric::from(1_u32), Numeric::from(10_u32)))
        );
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.size_hint(), (1, Some(1)));
        assert_eq!(
            iter.next(),
            Some((Numeric::from(2_u32), Numeric::from(20_u32)))
        );
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.size_hint(), (0, Some(0)));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }
    #[test]
    fn downcast_error_maps_to_internal_validation_failure() {
        let validation: crate::executor::ValidationFail =
            TypedBatchDowncastError::WrongType { column: 2 }.into();
        assert!(matches!(
            validation,
            crate::executor::ValidationFail::InternalError(message)
                if message.contains("column 2")
        ));
    }
}
