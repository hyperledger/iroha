//! Types for custom instructions
use derive_more::{Constructor, From};
use iroha_data_model::{
    isi::{CustomInstruction, InstructionBox},
    prelude::{Json, *},
};
use iroha_schema::IntoSchema;
use std::{collections::BTreeMap, format, string::String, vec::Vec};
macro_rules! impl_custom_instruction {
    ($box:ty, $($instruction:ty)|+) => {
        impl From<$box> for CustomInstruction {
            fn from(value: $box) -> Self {
                let payload = norito::json::to_value(&value)
                    .expect(concat!("INTERNAL BUG: Couldn't serialize ", stringify!($box)));
                Self::new(payload)
            }
        }
        impl From<$box> for InstructionBox {
            fn from(value: $box) -> Self {
                InstructionBox::from(CustomInstruction::from(value))
            }
        }
        impl TryFrom<&Json> for $box {
            type Error = norito::Error;
            fn try_from(payload: &Json) -> Result<Self, norito::Error> {
                norito::json::from_str::<Self>(payload.as_ref())
                    .map_err(norito::json::Error::into_core_error)
            }
        }
        $(
            impl From<$instruction> for InstructionBox {
                fn from(value: $instruction) -> Self {
                    InstructionBox::from(<$box>::from(value))
                }
            }
        )+
    };
}
/// Types for multisig instructions
pub mod multisig {
    use super::*;
    use crate::json_macros::{
        JsonDeserialize as DeriveJsonDeserialize, JsonSerialize as DeriveJsonSerialize,
    };
    use core::num::{NonZeroU16, NonZeroU64};
    use iroha_crypto::{HashOf, KeyPair};
    use iroha_model_base::domain::DomainId;
    use norito::json::{self, JsonDeserialize, JsonSerialize};
    use std::{borrow::ToOwned, collections::BTreeSet};
    /// Multisig-related instructions
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        From,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigInstructionBox")]
    pub enum MultisigInstructionBox {
        /// Register a multisig account, which is a prerequisite of multisig transactions
        Register(MultisigRegister),
        /// Propose a multisig transaction and initialize approvals with the proposer's one
        Propose(MultisigPropose),
        /// Approve a certain multisig transaction
        Approve(MultisigApprove),
        /// Cancel a certain multisig transaction before it reaches quorum
        Cancel(MultisigCancel),
        /// Atomically invalidate every outstanding proposal owned by a multisig account
        InvalidateOutstanding(MultisigInvalidateOutstanding),
    }
    impl JsonSerialize for MultisigInstructionBox {
        fn json_serialize(&self, out: &mut String) {
            out.push('{');
            match self {
                Self::Register(value) => {
                    norito::json::write_json_string("Register", out);
                    out.push(':');
                    value.json_serialize(out);
                }
                Self::Propose(value) => {
                    norito::json::write_json_string("Propose", out);
                    out.push(':');
                    value.json_serialize(out);
                }
                Self::Approve(value) => {
                    norito::json::write_json_string("Approve", out);
                    out.push(':');
                    value.json_serialize(out);
                }
                Self::Cancel(value) => {
                    norito::json::write_json_string("Cancel", out);
                    out.push(':');
                    value.json_serialize(out);
                }
                Self::InvalidateOutstanding(value) => {
                    norito::json::write_json_string("InvalidateOutstanding", out);
                    out.push(':');
                    value.json_serialize(out);
                }
            }
            out.push('}');
        }

        fn json_serialize_to(
            &self,
            out: &mut dyn json::JsonWriteSink,
        ) -> Result<(), json::BoundedJsonError> {
            out.begin_container()?;
            let result = (|| -> Result<(), norito::json::BoundedJsonError> {
                out.push('{')?;
                match self {
                    Self::Register(value) => {
                        json::write_json_string_to("Register", out)?;
                        out.push(':')?;
                        value.json_serialize_to(out)?;
                    }
                    Self::Propose(value) => {
                        json::write_json_string_to("Propose", out)?;
                        out.push(':')?;
                        value.json_serialize_to(out)?;
                    }
                    Self::Approve(value) => {
                        json::write_json_string_to("Approve", out)?;
                        out.push(':')?;
                        value.json_serialize_to(out)?;
                    }
                    Self::Cancel(value) => {
                        json::write_json_string_to("Cancel", out)?;
                        out.push(':')?;
                        value.json_serialize_to(out)?;
                    }
                    Self::InvalidateOutstanding(value) => {
                        json::write_json_string_to("InvalidateOutstanding", out)?;
                        out.push(':')?;
                        value.json_serialize_to(out)?;
                    }
                }
                out.push('}')?;
                Ok(())
            })();
            out.end_container();
            result?;
            Ok(())
        }
    }
    impl JsonDeserialize for MultisigInstructionBox {
        fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
            let mut visitor = json::MapVisitor::new(parser)?;
            let mut variant: Option<Self> = None;
            while let Some(key) = visitor.next_key()? {
                let name = key.as_str().to_owned();
                match name.as_str() {
                    "Register" => {
                        if variant.is_some() {
                            visitor.skip_value()?;
                            return Err(json::Error::duplicate_field(name));
                        }
                        let value = visitor.parse_value::<MultisigRegister>()?;
                        variant = Some(Self::Register(value));
                    }
                    "Propose" => {
                        if variant.is_some() {
                            visitor.skip_value()?;
                            return Err(json::Error::duplicate_field(name));
                        }
                        let value = visitor.parse_value::<MultisigPropose>()?;
                        variant = Some(Self::Propose(value));
                    }
                    "Approve" => {
                        if variant.is_some() {
                            visitor.skip_value()?;
                            return Err(json::Error::duplicate_field(name));
                        }
                        let value = visitor.parse_value::<MultisigApprove>()?;
                        variant = Some(Self::Approve(value));
                    }
                    "Cancel" => {
                        if variant.is_some() {
                            visitor.skip_value()?;
                            return Err(json::Error::duplicate_field(name));
                        }
                        let value = visitor.parse_value::<MultisigCancel>()?;
                        variant = Some(Self::Cancel(value));
                    }
                    "InvalidateOutstanding" => {
                        if variant.is_some() {
                            visitor.skip_value()?;
                            return Err(json::Error::duplicate_field(name));
                        }
                        let value = visitor.parse_value::<MultisigInvalidateOutstanding>()?;
                        variant = Some(Self::InvalidateOutstanding(value));
                    }
                    other => {
                        visitor.skip_value()?;
                        return Err(json::Error::unknown_field(other));
                    }
                }
            }
            visitor.finish()?;
            variant.ok_or_else(|| json::Error::missing_field("variant"))
        }
    }
    /// Register a multisig account, which is a prerequisite of multisig transactions
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        DeriveJsonSerialize,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigRegister")]
    pub struct MultisigRegister {
        /// Account backing the multisig controller.
        ///
        /// The supplied id anchors the registration step, but the account is rekeyed to the
        /// canonical multisig controller derived from the spec after registration, so the key is
        /// never used for signing.
        pub account: AccountId,
        /// Optional home domain used for registration authorization, linking, and RBAC namespacing.
        pub home_domain: Option<DomainId>,
        /// Specification of the multisig account
        pub spec: MultisigSpec,
        /// Immutable universal identity established with the new account.
        /// Explicit `None` registers an account without a universal identity.
        pub uaid: Option<iroha_data_model::nexus::UniversalAccountId>,
    }
    impl MultisigRegister {
        /// Construct a multisig registration.
        pub fn new(
            account: AccountId,
            home_domain: impl Into<Option<DomainId>>,
            spec: MultisigSpec,
        ) -> Self {
            Self {
                account,
                home_domain: home_domain.into(),
                spec,
                uaid: None,
            }
        }
        /// Bind the immutable universal identity to fresh registration.
        /// Existing accounts must already have this exact value; this never
        /// assigns or changes an existing account's universal identity.
        #[must_use]
        pub fn with_uaid(
            mut self,
            uaid: Option<iroha_data_model::nexus::UniversalAccountId>,
        ) -> Self {
            self.uaid = uaid;
            self
        }
        /// Construct a multisig registration using an explicit account id.
        pub fn with_account(
            account: AccountId,
            home_domain: impl Into<Option<DomainId>>,
            spec: MultisigSpec,
        ) -> Self {
            Self::new(account, home_domain, spec)
        }
        /// Construct a multisig registration using a freshly generated domainless account id.
        /// The generated key is not meant for direct signing; it only anchors the registration
        /// step before the account is rekeyed to the canonical controller derived from the spec.
        ///
        /// # Errors
        ///
        /// Returns an error if fresh account key generation fails.
        pub fn from_spec(
            home_domain: impl Into<Option<DomainId>>,
            spec: MultisigSpec,
        ) -> Result<Self, iroha_crypto::Error> {
            let key_pair = KeyPair::try_random()?;
            let account = AccountId::new(key_pair.public_key().clone());
            Ok(Self::new(account, home_domain, spec))
        }
    }
    impl JsonDeserialize for MultisigRegister {
        fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
            let mut visitor = json::MapVisitor::new(parser)?;
            let mut account: Option<AccountId> = None;
            let mut home_domain: Option<Option<DomainId>> = None;
            let mut spec: Option<MultisigSpec> = None;
            let mut uaid: Option<Option<iroha_data_model::nexus::UniversalAccountId>> = None;
            while let Some(key) = visitor.next_key()? {
                match key.as_str() {
                    "account" => {
                        let value = visitor.parse_value::<AccountId>()?;
                        account = Some(value);
                    }
                    "home_domain" => {
                        let value = visitor.parse_value::<Option<DomainId>>()?;
                        home_domain = Some(value);
                    }
                    "uaid" => {
                        if uaid.is_some() {
                            return Err(json::Error::duplicate_field("uaid"));
                        }
                        uaid = Some(
                            visitor
                                .parse_value::<Option<iroha_data_model::nexus::UniversalAccountId>>(
                                )?,
                        );
                    }
                    "spec" => {
                        let value = visitor.parse_value::<MultisigSpec>()?;
                        spec = Some(value);
                    }
                    _ => {
                        visitor.skip_value()?;
                    }
                }
            }
            visitor.finish()?;
            let spec = spec.ok_or_else(|| json::Error::missing_field("spec"))?;
            let account = account.ok_or_else(|| json::Error::missing_field("account"))?;
            Ok(Self {
                account,
                home_domain: home_domain.unwrap_or(None),
                spec,
                uaid: uaid.ok_or_else(|| json::Error::missing_field("uaid"))?,
            })
        }
    }
    /// Relative weight of responsibility for the multisig account.
    /// 0 is allowed for observers who don't join governance
    type Weight = u8;
    /// Default multisig transaction time-to-live in milliseconds based on block timestamps
    pub const DEFAULT_MULTISIG_TTL_MS: u64 = 60 * 60 * 1_000; // 1 hour
    /// Propose a multisig transaction and initialize approvals with the proposer's one
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        DeriveJsonSerialize,
        DeriveJsonDeserialize,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigPropose")]
    pub struct MultisigPropose {
        /// Multisig account to propose
        pub account: AccountId,
        /// Proposal contents
        pub instructions: Vec<InstructionBox>,
        /// Optional TTL to override the account default. Cannot be longer than the account default
        pub transaction_ttl_ms: Option<NonZeroU64>,
    }
    /// Approve a certain multisig transaction
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        DeriveJsonSerialize,
        DeriveJsonDeserialize,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigApprove")]
    pub struct MultisigApprove {
        /// Multisig account to approve
        pub account: AccountId,
        /// Proposal to approve
        pub instructions_hash: HashOf<Vec<InstructionBox>>,
    }
    /// Cancel a certain multisig transaction before it reaches quorum
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        DeriveJsonSerialize,
        DeriveJsonDeserialize,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigCancel")]
    pub struct MultisigCancel {
        /// Multisig account that owns the target proposal
        pub account: AccountId,
        /// Proposal to cancel
        pub instructions_hash: HashOf<Vec<InstructionBox>>,
    }
    /// Atomically invalidate every outstanding proposal owned by a multisig account.
    ///
    /// This instruction must execute as `account` itself, normally as the first instruction in an
    /// approved multisig policy-change proposal. The proposal executing this instruction is already
    /// terminal before its payload runs, so only other outstanding proposals are invalidated.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        DeriveJsonSerialize,
        DeriveJsonDeserialize,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_executor_data_model::isi::multisig::MultisigInvalidateOutstanding"
    )]
    pub struct MultisigInvalidateOutstanding {
        /// Multisig account whose outstanding proposals must be invalidated.
        pub account: AccountId,
    }
    impl_custom_instruction!(
        MultisigInstructionBox,
        MultisigRegister
            | MultisigPropose
            | MultisigApprove
            | MultisigCancel
            | MultisigInvalidateOutstanding
    );
    impl TryFrom<&InstructionBox> for MultisigInstructionBox {
        type Error = norito::Error;
        fn try_from(instruction: &InstructionBox) -> Result<Self, norito::Error> {
            if let Some(multisig) = instruction
                .as_any()
                .downcast_ref::<MultisigInstructionBox>()
            {
                return Ok(multisig.clone());
            }
            let custom = instruction
                .as_any()
                .downcast_ref::<CustomInstruction>()
                .ok_or_else(|| {
                    norito::Error::Message("instruction is not CustomInstruction".into())
                })?;
            Self::try_from(custom.payload())
        }
    }
    /// Native ledger value for a multisig account state entry.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigAccountState")]
    pub struct MultisigAccountState {
        /// Canonical multisig account id for this state entry.
        pub account_id: AccountId,
        /// Optional home domain used to materialize missing signatory accounts and roles.
        pub home_domain: Option<DomainId>,
        /// Multisig policy specification.
        pub spec: MultisigSpec,
    }
    impl MultisigAccountState {
        /// Construct a multisig account state snapshot.
        pub fn new(
            account_id: AccountId,
            home_domain: impl Into<Option<DomainId>>,
            spec: MultisigSpec,
        ) -> Self {
            Self {
                account_id,
                home_domain: home_domain.into(),
                spec,
            }
        }
    }
    /// Native ledger value for a multisig proposal state entry.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigProposalState")]
    pub struct MultisigProposalState {
        /// Canonical multisig account id that owns this proposal.
        pub multisig_account_id: AccountId,
        /// Hash of the proposed instruction list.
        pub instructions_hash: HashOf<Vec<InstructionBox>>,
        /// Proposal contents.
        pub instructions: Vec<InstructionBox>,
        /// Time in milliseconds at which the proposal was made.
        pub proposed_at_ms: u64,
        /// Time in milliseconds at which the proposal will expire.
        pub expires_at_ms: u64,
        /// List of approvers of the proposal so far.
        pub approvals: BTreeSet<AccountId>,
        /// In case this proposal is some relaying approval, indicates if it has executed or not.
        pub is_relayed: Option<bool>,
    }
    /// Terminal lifecycle states persisted for top-level multisig proposals.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_executor_data_model::isi::multisig::MultisigProposalTerminalStatus"
    )]
    pub enum MultisigProposalTerminalStatus {
        /// Proposal executed after reaching quorum.
        Finalized,
        /// Proposal was canceled by a separate multisig action.
        Canceled,
        /// Proposal expired before reaching quorum.
        Expired,
    }
    /// Native ledger value for a persisted terminal multisig proposal entry.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_executor_data_model::isi::multisig::MultisigProposalTerminalState"
    )]
    pub struct MultisigProposalTerminalState {
        /// Canonical multisig account id that owns this proposal.
        pub multisig_account_id: AccountId,
        /// Hash of the proposed instruction list.
        pub instructions_hash: HashOf<Vec<InstructionBox>>,
        /// Proposal contents and collected approvals at the time it became terminal.
        pub proposal: MultisigProposalValue,
        /// Terminal lifecycle state.
        pub status: MultisigProposalTerminalStatus,
        /// Time in milliseconds at which the proposal became terminal.
        pub terminal_at_ms: u64,
    }
    /// Immutable transaction-bound evidence that a multisig proposal became terminal.
    ///
    /// This evidence binds the terminal proposal to the exact transaction entrypoint and
    /// finalized height, in addition to the proposal payload in [`MultisigProposalTerminalState`].
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_executor_data_model::isi::multisig::MultisigProposalTerminalExecutionStateV1"
    )]
    pub struct MultisigProposalTerminalExecutionStateV1 {
        /// Terminal proposal payload captured at execution time.
        pub terminal: MultisigProposalTerminalState,
        /// Exact multisig account identifier carried by the entrypoint instruction.
        ///
        /// Current native approval admission requires this to resolve to the existing canonical
        /// account in `terminal.multisig_account_id`; persisting both makes that signed-to-resolved
        /// binding independently verifiable.
        pub entrypoint_account_id: AccountId,
        /// Finalised block height at which the proposal became terminal.
        pub terminal_block_height: u64,
        /// Hash of the block entrypoint that made the proposal terminal.
        pub terminal_entrypoint_hash: [u8; 32],
    }
    /// Whether one successful multisig approval entrypoint executed its proposal.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        norito::NoritoSchema,
    )]
    #[norito_schema(
        name = "iroha_executor_data_model::isi::multisig::MultisigApprovalOutcomeStatusV1"
    )]
    pub enum MultisigApprovalOutcomeStatusV1 {
        /// The approval reached quorum and executed the concrete proposal instructions.
        Executed,
        /// The approval succeeded but did not execute proposal instructions.
        NotExecuted,
    }
    /// Immutable transaction-bound classification of one successful multisig approval.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigApprovalOutcomeV1")]
    pub struct MultisigApprovalOutcomeV1 {
        /// Exact account identifier carried by the signed approval instruction.
        pub entrypoint_account_id: AccountId,
        /// Canonical multisig account to which the entrypoint resolved during execution.
        pub resolved_multisig_account_id: AccountId,
        /// Hash carried by the signed approval instruction.
        pub instructions_hash: HashOf<Vec<InstructionBox>>,
        /// Whether this approval actually executed its concrete proposal instructions.
        pub status: MultisigApprovalOutcomeStatusV1,
        /// Finalised block height at which the approval entrypoint ran.
        pub block_height: u64,
        /// Hash of the block entrypoint containing the signed approval.
        pub entrypoint_hash: [u8; 32],
    }
    /// Metadata value for a multisig account specification
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        norito::JsonDeserialize,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigSpec")]
    pub struct MultisigSpec {
        /// List of signatories and their relative weights of responsibility for the multisig account
        pub signatories: BTreeMap<AccountId, Weight>,
        /// Threshold of total weight at which the multisig account is considered authenticated
        pub quorum: NonZeroU16,
        /// Multisig transaction time-to-live in milliseconds based on block timestamps. Defaults to [`DEFAULT_MULTISIG_TTL_MS`]
        pub transaction_ttl_ms: NonZeroU64,
    }
    /// Metadata value for a multisig transaction proposal
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        Constructor,
        norito::JsonDeserialize,
        norito::NoritoSchema,
    )]
    #[norito_schema(name = "iroha_executor_data_model::isi::multisig::MultisigProposalValue")]
    pub struct MultisigProposalValue {
        /// Proposal contents
        pub instructions: Vec<InstructionBox>,
        /// Time in milliseconds at which the proposal was made
        pub proposed_at_ms: u64,
        /// Time in milliseconds at which the proposal will expire
        pub expires_at_ms: u64,
        /// List of approvers of the proposal so far
        pub approvals: BTreeSet<AccountId>,
        /// In case this proposal is some relaying approval, indicates if it has executed or not
        pub is_relayed: Option<bool>,
    }
    impl JsonSerialize for MultisigSpec {
        fn json_serialize(&self, out: &mut String) {
            out.push('{');
            norito::json::write_json_string("signatories", out);
            out.push(':');
            self.signatories.json_serialize(out);
            out.push(',');
            norito::json::write_json_string("quorum", out);
            out.push(':');
            self.quorum.json_serialize(out);
            out.push(',');
            norito::json::write_json_string("transaction_ttl_ms", out);
            out.push(':');
            self.transaction_ttl_ms.json_serialize(out);
            out.push('}');
        }

        fn json_serialize_to(
            &self,
            out: &mut dyn json::JsonWriteSink,
        ) -> Result<(), json::BoundedJsonError> {
            out.begin_container()?;
            let result = (|| -> Result<(), norito::json::BoundedJsonError> {
                out.push('{')?;
                json::write_json_string_to("signatories", out)?;
                out.push(':')?;
                self.signatories.json_serialize_to(out)?;
                out.push(',')?;
                json::write_json_string_to("quorum", out)?;
                out.push(':')?;
                self.quorum.json_serialize_to(out)?;
                out.push(',')?;
                json::write_json_string_to("transaction_ttl_ms", out)?;
                out.push(':')?;
                self.transaction_ttl_ms.json_serialize_to(out)?;
                out.push('}')?;
                Ok(())
            })();
            out.end_container();
            result?;
            Ok(())
        }
    }
    impl JsonSerialize for MultisigProposalValue {
        fn json_serialize(&self, out: &mut String) {
            out.push('{');
            norito::json::write_json_string("instructions", out);
            out.push(':');
            self.instructions.json_serialize(out);
            out.push(',');
            norito::json::write_json_string("proposed_at_ms", out);
            out.push(':');
            self.proposed_at_ms.json_serialize(out);
            out.push(',');
            norito::json::write_json_string("expires_at_ms", out);
            out.push(':');
            self.expires_at_ms.json_serialize(out);
            out.push(',');
            norito::json::write_json_string("approvals", out);
            out.push(':');
            self.approvals.json_serialize(out);
            out.push(',');
            norito::json::write_json_string("is_relayed", out);
            out.push(':');
            self.is_relayed.json_serialize(out);
            out.push('}');
        }

        fn json_serialize_to(
            &self,
            out: &mut dyn json::JsonWriteSink,
        ) -> Result<(), json::BoundedJsonError> {
            out.begin_container()?;
            let result = (|| -> Result<(), norito::json::BoundedJsonError> {
                out.push('{')?;
                json::write_json_string_to("instructions", out)?;
                out.push(':')?;
                self.instructions.json_serialize_to(out)?;
                out.push(',')?;
                json::write_json_string_to("proposed_at_ms", out)?;
                out.push(':')?;
                self.proposed_at_ms.json_serialize_to(out)?;
                out.push(',')?;
                json::write_json_string_to("expires_at_ms", out)?;
                out.push(':')?;
                self.expires_at_ms.json_serialize_to(out)?;
                out.push(',')?;
                json::write_json_string_to("approvals", out)?;
                out.push(':')?;
                self.approvals.json_serialize_to(out)?;
                out.push(',')?;
                json::write_json_string_to("is_relayed", out)?;
                out.push(':')?;
                self.is_relayed.json_serialize_to(out)?;
                out.push('}')?;
                Ok(())
            })();
            out.end_container();
            result?;
            Ok(())
        }
    }
    impl From<MultisigSpec> for Json {
        fn from(details: MultisigSpec) -> Self {
            Json::new(details)
        }
    }
    impl TryFrom<&Json> for MultisigSpec {
        type Error = norito::Error;
        fn try_from(payload: &Json) -> Result<Self, norito::Error> {
            norito::json::from_str::<Self>(payload.as_ref())
                .map_err(norito::json::Error::into_core_error)
        }
    }
    impl From<MultisigProposalValue> for Json {
        fn from(details: MultisigProposalValue) -> Self {
            Json::new(details)
        }
    }
    impl TryFrom<&Json> for MultisigProposalValue {
        type Error = norito::Error;
        fn try_from(payload: &Json) -> Result<Self, norito::Error> {
            norito::json::from_str::<Self>(payload.as_ref())
                .map_err(norito::json::Error::into_core_error)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use iroha_crypto::{Algorithm, KeyPair};
        use std::{
            collections::BTreeMap,
            num::{NonZeroU16, NonZeroU64},
        };
        fn fixture_key_pair(seed: u8) -> KeyPair {
            assert_ne!(seed, 0, "multisig fixture seeds must be nonzero");
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("derive multisig fixture key")
        }
        fn fixture_account(seed: u8) -> AccountId {
            AccountId::of(fixture_key_pair(seed).public_key().clone())
        }
        fn sample_spec() -> MultisigSpec {
            let mut signatories = BTreeMap::new();
            signatories.insert(fixture_account(1), 1);
            signatories.insert(fixture_account(2), 1);
            MultisigSpec::new(
                signatories,
                NonZeroU16::new(2).expect("nonzero quorum"),
                NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).expect("nonzero ttl"),
            )
        }
        fn sample_instruction_box() -> InstructionBox {
            let domain: DomainId =
                DomainId::try_new("multisig", "universal").expect("valid domain");
            let multisig_account = fixture_account(3);
            let spec = sample_spec();
            let register = MultisigRegister::with_account(multisig_account, Some(domain), spec);
            InstructionBox::from(register)
        }
        #[test]
        fn multisig_instruction_batch_hash_matches_sdk_golden() {
            let fixture: norito::json::Value = norito::json::from_str(include_str!(
                "../../../fixtures/multisig/instruction_batch_hash_v1.json"
            ))
            .expect("shared Rust/Kotlin/Java instruction batch fixture");
            assert_eq!(
                fixture["schema"].as_str(),
                Some("iroha.multisig.instruction-batch-hash.v1")
            );
            assert_eq!(fixture["layout_flags"].as_u64(), Some(2));
            let fixture_bytes = |key: &str| {
                let value = fixture[key].as_str().expect("fixture hex string");
                assert_eq!(value.len() % 2, 0, "complete fixture hex bytes");
                value
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                            .expect("valid fixture hex byte")
                    })
                    .collect::<Vec<_>>()
            };
            let instructions = vec![InstructionBox::from(CustomInstruction::new(Json::new(())))];
            assert_eq!(
                norito::codec::Encode::encode(&instructions),
                fixture_bytes("instruction_batch_hex"),
                "the complete canonical vector must match the shared Rust-produced bytes",
            );
            assert_eq!(
                HashOf::new(&instructions).as_ref().as_slice(),
                fixture_bytes("instruction_batch_hash_hex"),
                "HashOf<Vec<InstructionBox>> must match the independently checked shared hash",
            );
        }
        #[test]
        fn fixture_account_uses_checked_seed_derivation() {
            let account = fixture_account(42);
            let expected = AccountId::of(fixture_key_pair(42).public_key().clone());
            assert_eq!(account, expected);
            assert!(KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err());
        }

        #[test]
        fn multisig_spec_rejects_every_duplicate_field_before_replacement() {
            let source = json::to_json(&sample_spec()).unwrap();
            for (name, value) in [
                ("signatories", "{}"),
                ("quorum", "1"),
                ("transaction_ttl_ms", "1"),
            ] {
                let duplicate = format!("{{\"{name}\":{value},{}", &source[1..]);
                let error = json::from_str::<MultisigSpec>(&duplicate)
                    .expect_err("duplicate multisig spec field must not replace authority");
                assert!(matches!(error, json::Error::DuplicateField { field } if field == name));
            }
            let escaped = format!("{{\"\\u0071uorum\":1,{}", &source[1..]);
            assert!(matches!(json::from_str::<MultisigSpec>(&escaped),
                Err(json::Error::DuplicateField { field }) if field == "quorum"));
        }

        #[test]
        fn multisig_proposal_rejects_every_duplicate_field_including_null() {
            let expected = MultisigProposalValue::new(
                vec![sample_instruction_box()],
                1,
                2,
                BTreeSet::from([fixture_account(4)]),
                Some(false),
            );
            let source = json::to_json(&expected).unwrap();
            for (name, value) in [
                ("instructions", "[]"),
                ("proposed_at_ms", "0"),
                ("expires_at_ms", "0"),
                ("approvals", "[]"),
                ("is_relayed", "null"),
            ] {
                let duplicate = format!("{{\"{name}\":{value},{}", &source[1..]);
                let error = json::from_str::<MultisigProposalValue>(&duplicate)
                    .expect_err("duplicate multisig proposal field must not replace authority");
                assert!(matches!(error, json::Error::DuplicateField { field } if field == name));
            }
        }

        #[test]
        fn canonical_multisig_readers_keep_wire_values_required_fields_and_optional_null() {
            let spec = sample_spec();
            let source = json::to_json(&spec).unwrap();
            let decoded = json::from_str::<MultisigSpec>(&source).unwrap();
            assert_eq!(decoded, spec);
            assert_eq!(json::to_json(&decoded).unwrap(), source);
            assert!(matches!(json::from_str::<MultisigSpec>("{}"),
                Err(json::Error::MissingField { field }) if field == "signatories"));
            let expected = MultisigProposalValue::new(
                vec![sample_instruction_box()],
                1,
                2,
                BTreeSet::from([fixture_account(4)]),
                None,
            );
            let source = json::to_json(&expected).unwrap();
            assert!(source.contains(",\"is_relayed\":null"));
            let omitted = source.replace(",\"is_relayed\":null", "");
            for input in [source.as_str(), omitted.as_str()] {
                let decoded = json::from_str::<MultisigProposalValue>(input).unwrap();
                assert_eq!(decoded, expected);
                assert_eq!(json::to_json(&decoded).unwrap(), source);
            }
            assert!(matches!(json::from_str::<MultisigProposalValue>("{}"),
                Err(json::Error::MissingField { field }) if field == "instructions"));
        }

        fn allocation_limits(bytes: usize) -> norito::DecodeLimits {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        }

        #[test]
        fn multisig_signatory_json_preserves_original_refusal_at_every_allocation_limit() {
            let expected = sample_spec();
            let source = json::to_json(&expected).unwrap();
            let (baseline, usage) =
                norito::core::with_decode_limits_measured(allocation_limits(usize::MAX), || {
                    json::from_str::<MultisigSpec>(&source)
                });
            assert_eq!(baseline.unwrap(), expected);
            let demand = usage.total_allocated_bytes();
            assert!(demand > 0);
            for limit in 0..demand {
                let error =
                    norito::core::with_decode_limits_measured(allocation_limits(limit), || {
                        json::from_str::<MultisigSpec>(&source)
                    })
                    .0
                    .expect_err("every smaller original allocation limit must refuse");
                let original = error.into_core_error();
                let Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted,
                    limit: actual_limit,
                }) = original.decode_resource_error()
                else {
                    panic!(
                        "signatory account decoding erased original refusal at {limit}: {original:?}"
                    );
                };
                assert_eq!(actual_limit, u64::try_from(limit).unwrap());
                assert!(attempted > actual_limit);
            }
            let (retry, usage) =
                norito::core::with_decode_limits_measured(allocation_limits(demand), || {
                    json::from_str::<MultisigSpec>(&source)
                });
            assert_eq!(retry.unwrap(), expected);
            assert_eq!(usage.total_allocated_bytes(), demand);
            let malformed = source.replacen(&fixture_account(1).to_string(), "invalid-account", 1);
            let error = json::from_str::<MultisigSpec>(&malformed).unwrap_err();
            assert!(!error.is_decode_resource_limit());
        }

        fn assert_metadata_refusal_and_retry<T: std::fmt::Debug + PartialEq>(
            payload: &Json,
            expected: &T,
            decode: impl Fn(&Json) -> Result<T, norito::Error>,
        ) {
            let source_pointer = payload.as_ref().as_ptr();
            let (baseline, usage) =
                norito::core::with_decode_limits_measured(allocation_limits(usize::MAX), || {
                    decode(payload)
                });
            assert_eq!(&baseline.unwrap(), expected);
            let demand = usage.total_allocated_bytes();
            assert!(demand > 0);
            for limit in [0, 1, demand - 1] {
                let context = norito::core::DecodeBudgetContext::new(allocation_limits(
                    demand.checked_mul(4).unwrap(),
                ));
                let error = context
                    .with(|| {
                        norito::core::with_decode_limits_measured(allocation_limits(limit), || {
                            decode(payload)
                        })
                    })
                    .0
                    .expect_err("actual metadata reader must refuse its original inner limit");
                let Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted,
                    limit: actual_limit,
                }) = error.decode_resource_error()
                else {
                    panic!("metadata conversion erased original resource fields: {error:?}");
                };
                assert_eq!(actual_limit, u64::try_from(limit).unwrap());
                assert!(attempted > actual_limit);
                let before_retry = context.consumed_allocated_bytes();
                assert_eq!(&context.with(|| decode(payload)).unwrap(), expected);
                assert_eq!(
                    context.consumed_allocated_bytes() - before_retry,
                    u64::try_from(demand).unwrap()
                );
                assert_eq!(payload.as_ref().as_ptr(), source_pointer);
            }
        }

        #[test]
        fn multisig_spec_metadata_keeps_original_resource_fields_and_same_context_retry() {
            let expected = sample_spec();
            let payload = Json::try_new(expected.clone()).unwrap();
            assert_metadata_refusal_and_retry(&payload, &expected, |value| {
                MultisigSpec::try_from(value)
            });
        }

        #[test]
        fn multisig_proposal_metadata_keeps_original_resource_fields_and_same_context_retry() {
            let expected = MultisigProposalValue::new(
                vec![sample_instruction_box()],
                1,
                2,
                BTreeSet::from([fixture_account(4)]),
                Some(false),
            );
            let payload = Json::try_new(expected.clone()).unwrap();
            assert_metadata_refusal_and_retry(&payload, &expected, |value| {
                MultisigProposalValue::try_from(value)
            });
        }

        #[test]
        fn multisig_metadata_values_support_bounded_json() {
            let spec = sample_spec();
            let encoded_spec = Json::try_new(spec.clone()).expect("bounded multisig spec JSON");
            assert_eq!(
                MultisigSpec::try_from(&encoded_spec).expect("decode bounded multisig spec JSON"),
                spec
            );

            let proposal = MultisigProposalValue::new(
                vec![sample_instruction_box()],
                1,
                2,
                BTreeSet::from([fixture_account(4)]),
                Some(false),
            );
            let encoded_proposal =
                Json::try_new(proposal.clone()).expect("bounded multisig proposal JSON");
            assert_eq!(
                MultisigProposalValue::try_from(&encoded_proposal)
                    .expect("decode bounded multisig proposal JSON"),
                proposal
            );
        }

        #[test]
        fn try_from_instruction_box_roundtrip() {
            let instruction_box = sample_instruction_box();
            let decoded = MultisigInstructionBox::try_from(&instruction_box)
                .expect("decode multisig instruction");
            match decoded {
                MultisigInstructionBox::Register(register) => {
                    assert_eq!(register.spec.signatories.len(), 2);
                }
                _ => panic!("expected register variant"),
            }
        }
        #[test]
        fn custom_multisig_conversion_preserves_decode_resource_identity() {
            let instruction = sample_instruction_box();
            let expected = MultisigInstructionBox::try_from(&instruction).unwrap();
            norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || {
                    let error = MultisigInstructionBox::try_from(&instruction)
                        .expect_err("the actual JSON decoder must honor its zero-allocation scope");
                    assert!(
                        matches!(
                            error.decode_resource_error(),
                            Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
                                limit: 0,
                                ..
                            })
                        ),
                        "original JSON refusal was erased: {error:?}",
                    );
                },
            );
            assert_eq!(
                MultisigInstructionBox::try_from(&instruction).unwrap(),
                expected
            );
            let malformed = Json::new(norito::json!({"UnknownMultisigVariant": {}}));
            let error = MultisigInstructionBox::try_from(&malformed)
                .expect_err("unknown variants remain deterministic errors");
            assert!(error.decode_resource_error().is_none());
            assert!(!norito::core::decode_error_matches_active_limits(&error));
        }
        #[test]
        fn multisig_register_json_includes_account_field() {
            let domain: DomainId =
                DomainId::try_new("multisig", "universal").expect("valid domain");
            let multisig_account = fixture_account(42);
            let spec = sample_spec();
            let register = MultisigRegister::with_account(multisig_account, Some(domain), spec);
            let rendered =
                norito::json::to_json(&register).expect("multisig register should serialize");
            assert!(
                rendered.contains("\"account\""),
                "account field missing from serialized json: {rendered}"
            );
            assert!(
                rendered.contains("\"home_domain\""),
                "home_domain field missing from serialized json: {rendered}"
            );
        }
        #[test]
        fn multisig_register_uaid_is_explicit_and_roundtrips_exact_native_frames() {
            use iroha_data_model::nexus::UniversalAccountId;
            let uaid =
                UniversalAccountId::from_hash(iroha_crypto::Hash::new(b"multisig-register-uaid"));
            for uaid in [None, Some(uaid)] {
                let register =
                    MultisigRegister::with_account(fixture_account(47), None, sample_spec())
                        .with_uaid(uaid);
                let encoded = norito::to_bytes(&register).expect("typed wire");
                let decoded: MultisigRegister = norito::decode_from_bytes(&encoded).unwrap();
                assert_eq!(decoded, register);
                let json = norito::json::to_json(&register).unwrap();
                assert!(json.contains("\"uaid\":"));
                assert_eq!(
                    norito::json::from_str::<MultisigRegister>(&json).unwrap(),
                    register
                );
                let outer = InstructionBox::from(register.clone());
                assert_eq!(
                    MultisigInstructionBox::try_from(&outer).unwrap(),
                    MultisigInstructionBox::Register(register.clone())
                );
                let duplicate = format!("{{\"uaid\":null,{}", &json[1..]);
                assert!(norito::json::from_str::<MultisigRegister>(&duplicate).is_err());
                let missing = norito::json!({
                    "account": (register.account.clone()),
                    "home_domain": null,
                    "spec": (register.spec.clone())
                });
                assert!(norito::json::from_value::<MultisigRegister>(missing).is_err());
            }
        }
        #[test]
        fn multisig_register_json_requires_account_field() {
            let spec = sample_spec();
            let spec_json = norito::json::to_json(&spec).expect("spec should serialize");
            let payload = format!(r#"{{"spec": {spec_json}}}"#);
            let err = norito::json::from_str::<MultisigRegister>(&payload)
                .expect_err("missing account should be rejected");
            let rendered = err.to_string();
            assert!(
                rendered.contains("account"),
                "missing account error should mention account field: {rendered}"
            );
        }
        #[test]
        fn multisig_register_from_spec_randomizes_controller() {
            let domain: DomainId =
                DomainId::try_new("non-derived", "universal").expect("valid domain");
            let spec = sample_spec();
            let first = MultisigRegister::from_spec(Some(domain.clone()), spec.clone())
                .expect("checked multisig controller account generation");
            let second = MultisigRegister::from_spec(Some(domain.clone()), spec.clone())
                .expect("checked multisig controller account generation");
            assert_eq!(
                first.home_domain.as_ref(),
                Some(&domain),
                "generated controller must carry the explicit home domain"
            );
            assert_ne!(
                first.account, second.account,
                "from_spec should randomize the controller id for each call"
            );
        }
        #[test]
        fn multisig_register_json_defaults_home_domain_to_none() {
            let account = fixture_account(7);
            let account_json = norito::json::to_json(&account).expect("account json");
            let spec = sample_spec();
            let spec_json = norito::json::to_json(&spec).expect("spec json");
            let payload =
                format!(r#"{{"account": {account_json}, "spec": {spec_json}, "uaid": null}}"#);
            let register = norito::json::from_str::<MultisigRegister>(&payload)
                .expect("missing home_domain should default to none");
            assert_eq!(register.home_domain, None);
        }
        #[test]
        fn multisig_cancel_instruction_roundtrip_preserves_target_hash() {
            let multisig_account = fixture_account(11);
            let instructions_hash = HashOf::new(&vec![sample_instruction_box()]);
            let cancel = MultisigCancel::new(multisig_account.clone(), instructions_hash);
            let instruction_box = InstructionBox::from(cancel.clone());
            let decoded = MultisigInstructionBox::try_from(&instruction_box)
                .expect("decode multisig cancel instruction");
            match decoded {
                MultisigInstructionBox::Cancel(decoded_cancel) => {
                    assert_eq!(decoded_cancel.account, multisig_account);
                    assert_eq!(decoded_cancel.instructions_hash, cancel.instructions_hash);
                }
                _ => panic!("expected cancel variant"),
            }
        }
        #[test]
        fn multisig_invalidate_outstanding_instruction_roundtrips_exact_account() {
            let multisig_account = fixture_account(13);
            let invalidate = MultisigInvalidateOutstanding::new(multisig_account.clone());
            let instruction_box = InstructionBox::from(invalidate);
            let decoded = MultisigInstructionBox::try_from(&instruction_box)
                .expect("decode multisig invalidation instruction");
            match &decoded {
                MultisigInstructionBox::InvalidateOutstanding(decoded) => {
                    assert_eq!(decoded.account, multisig_account);
                }
                _ => panic!("expected invalidate-outstanding variant"),
            }
            let json = norito::json::to_json(&decoded)
                .expect("encode multisig invalidation instruction JSON");
            assert_eq!(
                norito::json::to_json_bounded(&decoded, json.len())
                    .expect("encode bounded multisig invalidation instruction JSON"),
                json
            );
            assert!(json.contains("\"InvalidateOutstanding\""));
            let decoded_json = norito::json::from_str::<MultisigInstructionBox>(&json)
                .expect("decode multisig invalidation instruction JSON");
            assert_eq!(decoded_json, decoded);
        }
        #[test]
        fn multisig_terminal_state_roundtrip_preserves_status() {
            let multisig_account = fixture_account(12);
            let instructions = vec![sample_instruction_box()];
            let instructions_hash = HashOf::new(&instructions);
            let proposal = MultisigProposalValue::new(
                instructions,
                1_700_000_000_000,
                1_700_000_060_000,
                BTreeSet::from([multisig_account.clone()]),
                None,
            );
            let terminal = MultisigProposalTerminalState::new(
                multisig_account.clone(),
                instructions_hash,
                proposal.clone(),
                MultisigProposalTerminalStatus::Canceled,
                1_700_000_010_000,
            );
            let bytes = norito::to_bytes(&terminal).expect("encode terminal state");
            let decoded = norito::decode_from_bytes::<MultisigProposalTerminalState>(&bytes)
                .expect("decode terminal state");
            assert_eq!(decoded.multisig_account_id, multisig_account);
            assert_eq!(decoded.instructions_hash, instructions_hash);
            assert_eq!(decoded.proposal, proposal);
            assert_eq!(decoded.status, MultisigProposalTerminalStatus::Canceled);
            assert_eq!(decoded.terminal_at_ms, 1_700_000_010_000);
        }
        #[test]
        fn multisig_terminal_execution_state_roundtrip_preserves_binding() {
            let multisig_account = fixture_account(13);
            let instructions = vec![sample_instruction_box()];
            let instructions_hash = HashOf::new(&instructions);
            let terminal = MultisigProposalTerminalState::new(
                multisig_account.clone(),
                instructions_hash,
                MultisigProposalValue::new(
                    instructions,
                    1_700_000_000_000,
                    1_700_000_060_000,
                    BTreeSet::new(),
                    None,
                ),
                MultisigProposalTerminalStatus::Finalized,
                1_700_000_010_000,
            );
            let execution = MultisigProposalTerminalExecutionStateV1::new(
                terminal.clone(),
                multisig_account.clone(),
                42,
                [0xabu8; 32],
            );
            let bytes = norito::to_bytes(&execution).expect("encode terminal execution state");
            let decoded =
                norito::decode_from_bytes::<MultisigProposalTerminalExecutionStateV1>(&bytes)
                    .expect("decode terminal execution state");
            assert_eq!(decoded.terminal, terminal);
            assert_eq!(decoded.entrypoint_account_id, multisig_account);
            assert_eq!(decoded.terminal_block_height, 42);
            assert_eq!(decoded.terminal_entrypoint_hash, [0xabu8; 32]);
        }
        #[test]
        fn multisig_approval_outcome_roundtrip_preserves_resolution_and_binding() {
            let entrypoint_account = fixture_account(14);
            let resolved_account = fixture_account(15);
            let instructions_hash = HashOf::new(&vec![sample_instruction_box()]);
            let outcome = MultisigApprovalOutcomeV1::new(
                entrypoint_account.clone(),
                resolved_account.clone(),
                instructions_hash,
                MultisigApprovalOutcomeStatusV1::Executed,
                43,
                [0xcdu8; 32],
            );
            let bytes = norito::to_bytes(&outcome).expect("encode approval outcome");
            let decoded = norito::decode_from_bytes::<MultisigApprovalOutcomeV1>(&bytes)
                .expect("decode approval outcome");
            assert_eq!(decoded.entrypoint_account_id, entrypoint_account);
            assert_eq!(decoded.resolved_multisig_account_id, resolved_account);
            assert_eq!(decoded.instructions_hash, instructions_hash);
            assert_eq!(decoded.status, MultisigApprovalOutcomeStatusV1::Executed);
            assert_eq!(decoded.block_height, 43);
            assert_eq!(decoded.entrypoint_hash, [0xcdu8; 32]);
        }

        mod checked_refusal_oracle {
            // Test-only refusal oracle over the sole ordinary writer and original borrowed graph.

            use norito::json::{BoundedJsonError, JsonSerialize, JsonWriteSink};

            pub const ORIGINAL_DEPTH: usize = 7;
            pub struct OriginalSink {
                pub(crate) text: String,
                pub(crate) depth: usize,
                cap: usize,
                deny_entry: Option<usize>,
                entries: usize,
            }
            impl OriginalSink {
                pub(crate) fn new(cap: usize) -> Self {
                    Self {
                        text: String::new(),
                        depth: ORIGINAL_DEPTH,
                        cap,
                        deny_entry: None,
                        entries: 0,
                    }
                }
            }
            impl JsonWriteSink for OriginalSink {
                fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
                    self.push_str(value.encode_utf8(&mut [0; 4]))
                }
                fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
                    if self
                        .text
                        .len()
                        .checked_add(value.len())
                        .is_none_or(|len| len > self.cap)
                    {
                        return Err(BoundedJsonError::BodyTooLarge);
                    }
                    self.text.push_str(value);
                    Ok(())
                }
                fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
                    self.entries += 1;
                    if self.deny_entry == Some(self.entries) {
                        return Err(BoundedJsonError::Unsupported);
                    }
                    self.depth += 1;
                    Ok(())
                }
                fn end_container(&mut self) {
                    assert!(
                        self.depth > ORIGINAL_DEPTH,
                        "writer cannot release inherited caller depth"
                    );
                    self.depth -= 1;
                }
            }
            /// Retain exact bytes/errors/depth on every byte cap and every actual entry refusal.
            pub fn audit_write(
                ordinary: &str,
                write: impl Fn(&mut dyn JsonWriteSink) -> Result<(), BoundedJsonError>,
            ) {
                for cap in 0..ordinary.len() {
                    let mut sink = OriginalSink::new(cap);
                    assert_eq!(
                        write(&mut sink),
                        Err(BoundedJsonError::BodyTooLarge),
                        "exact byte refusal at {cap}"
                    );
                    assert_eq!(
                        sink.depth, ORIGINAL_DEPTH,
                        "original inherited depth at byte cap {cap}"
                    );
                    assert!(
                        ordinary.starts_with(&sink.text),
                        "unchanged canonical prefix at {cap}"
                    );
                }
                let mut sink = OriginalSink::new(ordinary.len());
                assert_eq!(write(&mut sink), Ok(()));
                assert_eq!(sink.text, ordinary);
                assert_eq!(sink.depth, ORIGINAL_DEPTH);
                for denied in 1..=sink.entries {
                    let mut refused = OriginalSink::new(usize::MAX);
                    refused.deny_entry = Some(denied);
                    assert_eq!(
                        write(&mut refused),
                        Err(BoundedJsonError::Unsupported),
                        "actual entry {denied}"
                    );
                    assert_eq!(
                        refused.depth, ORIGINAL_DEPTH,
                        "every entered level must release on child admission refusal {denied}"
                    );
                    assert!(ordinary.starts_with(&refused.text));
                }
                // Retry the same borrowed graph with a fresh test sink; no decode or copied source.
                let mut retry = OriginalSink::new(ordinary.len());
                assert_eq!(write(&mut retry), Ok(()));
                assert_eq!(retry.text, ordinary);
                assert_eq!(retry.depth, ORIGINAL_DEPTH);
            }
            /// Observe the same owning object via ordinary and checked canonical writers.
            pub fn audit<T: JsonSerialize + ?Sized>(value: &T) {
                let original = std::ptr::from_ref(value);
                let mut ordinary = String::new();
                value.json_serialize(&mut ordinary);
                audit_write(&ordinary, |out| value.json_serialize_to(out));
                assert!(std::ptr::eq(std::ptr::from_ref(value), original));
            }
        }
        use checked_refusal_oracle::audit;

        #[test]
        fn original_multisig_spec_checked_container_retains_original_signers_and_depth() {
            let value = sample_spec();
            audit(&value);
        }
        #[test]
        fn original_multisig_proposal_checked_container_retains_original_instructions_and_depth() {
            let value = MultisigProposalValue {
                instructions: vec![
                    iroha_data_model::isi::Log::new(
                        iroha_data_model::Level::INFO,
                        "original".into(),
                    )
                    .into(),
                ],
                proposed_at_ms: 17,
                expires_at_ms: 23,
                approvals: [fixture_account(1), fixture_account(2)].into(),
                is_relayed: Some(false),
            };
            let pointer = value.instructions.as_ptr();
            audit(&value);
            assert_eq!(value.instructions.as_ptr(), pointer);
        }
        #[test]
        fn original_multisig_instruction_checked_container_retains_every_variant_and_depth() {
            let account = fixture_account(3);
            let instructions: Vec<InstructionBox> = vec![
                iroha_data_model::isi::Log::new(iroha_data_model::Level::INFO, "original".into())
                    .into(),
            ];
            let hash = HashOf::new(&instructions);
            audit(&MultisigInstructionBox::Register(MultisigRegister::new(
                account.clone(),
                None::<DomainId>,
                sample_spec(),
            )));
            audit(&MultisigInstructionBox::Propose(MultisigPropose {
                account: account.clone(),
                instructions,
                transaction_ttl_ms: NonZeroU64::new(17),
            }));
            audit(&MultisigInstructionBox::Approve(MultisigApprove {
                account: account.clone(),
                instructions_hash: hash,
            }));
            audit(&MultisigInstructionBox::Cancel(MultisigCancel {
                account: account.clone(),
                instructions_hash: hash,
            }));
            audit(&MultisigInstructionBox::InvalidateOutstanding(
                MultisigInvalidateOutstanding { account },
            ));
        }
    }
}
