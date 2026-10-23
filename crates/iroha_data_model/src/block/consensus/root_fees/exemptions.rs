//! Canonically ordered fee-exempt identities with one explicit contiguous backing.

use std::alloc::Layout;

use iroha_schema::IntoSchema;
use norito::{
    core::{Archived, DecodeFromSlice, DeserializePayload, Encoder, SerializePayload},
    json::{JsonDeserialize, JsonSerialize},
};

use crate::account::AccountId;

/// Exact set of canonical accounts exempt from a successful public claim fee.
///
/// The sole representation is a sorted contiguous sequence. Decoders reject
/// duplicate or out-of-order entries rather than normalizing signed input.
/// Authoring may insert accounts in any order through the fallible API.
#[derive(Clone, Debug, Default, PartialEq, Eq, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::consensus::RootFeeExemptions")]
pub struct RootFeeExemptions(Vec<AccountId>);

impl RootFeeExemptions {
    /// Construct an empty authoring set without allocating.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Number of distinct canonical exempt identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no authority is exempt.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Test exact account identity without parsing or allocating.
    #[must_use]
    pub fn contains(&self, account: &AccountId) -> bool {
        self.0.binary_search(account).is_ok()
    }

    /// Borrow identities in their canonical strictly increasing order.
    pub fn iter(&self) -> std::slice::Iter<'_, AccountId> {
        self.0.iter()
    }

    /// Remove all exemptions from an explicitly owned authoring policy.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Insert an authored identity; return false for an existing exact identity.
    ///
    /// # Errors
    /// Preserves the original decoder-budget or allocator refusal before growing.
    pub fn try_insert(&mut self, account: AccountId) -> Result<bool, norito::Error> {
        let index = match self.0.binary_search(&account) {
            Ok(_) => return Ok(false),
            Err(index) => index,
        };
        if self.0.len() == self.0.capacity() {
            let next = self
                .0
                .len()
                .checked_add(1)
                .ok_or(norito::Error::LengthMismatch)?;
            let layout =
                Layout::array::<AccountId>(next).map_err(|_| norito::Error::LengthMismatch)?;
            // Reallocation can temporarily retain both original and destination arrays.
            norito::core::reserve_decode_allocation(layout.size())?;
            self.0
                .try_reserve_exact(1)
                .map_err(|_| norito::Error::AllocationFailed {
                    bytes: u64::try_from(layout.size()).unwrap_or(u64::MAX),
                })?;
            if self.0.capacity() != next {
                return Err(norito::Error::AllocationFailed {
                    bytes: u64::try_from(layout.size()).unwrap_or(u64::MAX),
                });
            }
        }
        self.0.insert(index, account);
        Ok(true)
    }

    /// Author a canonical set from a sequence, coalescing repeated exact identities.
    ///
    /// # Errors
    /// Returns the first original budget or allocator refusal.
    pub fn try_from_iter(
        accounts: impl IntoIterator<Item = AccountId>,
    ) -> Result<Self, norito::Error> {
        let mut set = Self::new();
        for account in accounts {
            set.try_insert(account)?;
        }
        Ok(set)
    }

    pub(in crate::block::consensus) fn validate_sorted(
        accounts: &[AccountId],
    ) -> Result<(), norito::Error> {
        if accounts.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(norito::Error::Message(
                "root fee exemptions must be strictly increasing unique account identities".into(),
            ));
        }
        Ok(())
    }

    pub(in crate::block::consensus) fn from_sorted(
        accounts: Vec<AccountId>,
    ) -> Result<Self, norito::Error> {
        Self::validate_sorted(&accounts)?;
        Ok(Self(accounts))
    }

    // The sole admitted caller validates the unchanged array before move-only
    // extraction. This constructor neither allocates nor clones account backing.
    pub(in crate::block::consensus) fn from_validated_sorted(accounts: Vec<AccountId>) -> Self {
        Self(accounts)
    }

    /// Visit the exact array and account allocations made by an admitted clone.
    /// This read-only plan allocates nothing and never estimates tree-node sizes.
    ///
    /// # Errors
    /// Rejects an unrepresentable array or malformed stored account.
    pub fn for_each_admission_clone_layout(
        &self,
        mut visit: impl FnMut(Layout),
    ) -> Result<(), norito::Error> {
        visit(Layout::array::<AccountId>(self.len()).map_err(|_| norito::Error::LengthMismatch)?);
        for account in &self.0 {
            account.for_each_admission_clone_layout(&mut visit)?;
        }
        Ok(())
    }

    /// Copy into exact fallible storage after the caller funds its complete layout plan.
    /// The caller must retain all planned charges until this independent clone is dropped.
    ///
    /// # Errors
    /// Preserves decoder-budget and allocator refusals without exposing a partial set.
    pub fn try_clone_for_admission(&self) -> Result<Self, norito::Error> {
        let layout =
            Layout::array::<AccountId>(self.len()).map_err(|_| norito::Error::LengthMismatch)?;
        norito::core::reserve_decode_allocation(layout.size())?;
        let mut accounts = Vec::new();
        accounts
            .try_reserve_exact(self.len())
            .map_err(|_| norito::Error::AllocationFailed {
                bytes: u64::try_from(layout.size()).unwrap_or(u64::MAX),
            })?;
        if accounts.capacity() != self.len() {
            return Err(norito::Error::AllocationFailed {
                bytes: u64::try_from(layout.size()).unwrap_or(u64::MAX),
            });
        }
        for account in &self.0 {
            accounts.push(account.try_clone_for_admission()?);
        }
        Ok(Self(accounts))
    }
}

impl<'a> IntoIterator for &'a RootFeeExemptions {
    type Item = &'a AccountId;
    type IntoIter = std::slice::Iter<'a, AccountId>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl SerializePayload for RootFeeExemptions {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.0.serialize(writer)
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

impl<'a> DeserializePayload<'a> for RootFeeExemptions {
    fn deserialize(archived: &'a Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("valid canonical root fee exemptions")
    }

    fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, norito::Error> {
        Self::from_sorted(Vec::<AccountId>::try_deserialize(
            archived.cast::<Vec<AccountId>>(),
        )?)
    }
}

impl<'a> DecodeFromSlice<'a> for RootFeeExemptions {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::Error> {
        let (accounts, used) = Vec::<AccountId>::decode_from_slice(bytes)?;
        Ok((Self::from_sorted(accounts)?, used))
    }
}

impl JsonSerialize for RootFeeExemptions {
    fn json_serialize(&self, output: &mut String) {
        self.0.json_serialize(output);
    }

    fn json_serialize_to(
        &self,
        output: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        self.0.json_serialize_to(output)
    }
}

impl JsonDeserialize for RootFeeExemptions {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        super::super::monetary_json::decode_exemptions_ordinary(parser)
    }

    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        Self::from_sorted(Vec::<AccountId>::json_from_value(value)?)
            .map_err(norito::json::Error::from_decode_resource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};

    fn accounts() -> [AccountId; 2] {
        let mut accounts = [1, 2].map(|seed| {
            AccountId::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
            )
        });
        accounts.sort();
        accounts
    }

    #[test]
    fn authoring_inserts_in_order_and_preserves_exact_identity() {
        let [first, second] = accounts();
        let mut exemptions = RootFeeExemptions::new();
        assert!(exemptions.is_empty());
        assert!(exemptions.try_insert(second.clone()).unwrap());
        assert!(exemptions.try_insert(first.clone()).unwrap());
        assert!(!exemptions.try_insert(first.clone()).unwrap());
        assert_eq!(exemptions.len(), 2);
        assert!(exemptions.contains(&first));
        assert_eq!(exemptions.iter().collect::<Vec<_>>(), [&first, &second]);
        assert_eq!(
            exemptions,
            RootFeeExemptions::try_from_iter([second, first.clone(), first]).unwrap()
        );
        exemptions.clear();
        assert!(exemptions.is_empty());
    }

    #[test]
    fn canonical_json_and_binary_reject_duplicate_and_reversed_entries() {
        let [first, second] = accounts();
        let valid = RootFeeExemptions::try_from_iter([second.clone(), first.clone()]).unwrap();
        let bytes = norito::encode_canonical(&valid).unwrap();
        assert_eq!(
            norito::decode_canonical::<RootFeeExemptions>(&bytes).unwrap(),
            valid
        );
        let json = norito::json::to_json(&valid).unwrap();
        assert_eq!(
            norito::json::from_str::<RootFeeExemptions>(&json).unwrap(),
            valid
        );
        for invalid in [
            vec![first.clone(), first],
            vec![second.clone(), accounts()[0].clone()],
        ] {
            let invalid = RootFeeExemptions(invalid);
            let json = norito::json::to_json(&invalid).unwrap();
            assert!(norito::json::from_str::<RootFeeExemptions>(&json).is_err());
            let bytes = norito::encode_canonical(&invalid).unwrap();
            assert!(matches!(
                norito::decode_canonical::<RootFeeExemptions>(&bytes),
                Err(norito::Error::Message(message)) if message.contains("strictly increasing unique")
            ));
        }
    }

    #[test]
    fn admitted_clone_refuses_before_array_then_retries_with_exact_layouts() {
        let source = RootFeeExemptions::try_from_iter(accounts()).unwrap();
        let mut layouts = Vec::new();
        source
            .for_each_admission_clone_layout(|layout| layouts.push(layout))
            .unwrap();
        assert_eq!(layouts[0], Layout::array::<AccountId>(2).unwrap());
        assert_eq!(
            layouts.len(),
            3,
            "array plus two independently owned public keys"
        );
        let demand = layouts.iter().map(Layout::size).sum::<usize>();
        let zero = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            usize::MAX,
        ));
        assert!(
            zero.with(|| source.try_clone_for_admission())
                .unwrap_err()
                .is_decode_resource_limit()
        );
        let exact = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            demand,
            usize::MAX,
        ));
        assert_eq!(
            exact.with(|| source.try_clone_for_admission()).unwrap(),
            source
        );
        assert_eq!(
            exact.consumed_allocated_bytes(),
            u64::try_from(demand).unwrap()
        );
    }
}
