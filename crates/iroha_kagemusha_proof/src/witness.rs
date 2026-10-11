//! Native witnesses of the step relations `sigma_send` and `sigma_recv` and
//! their reference evaluation, in the G1 wallet layout
//! (`specs/kagemusha_single_design_proposal.md` sections 3, 3.2, 5.1 and 7;
//! the wire record `specs/kagemusha_wallet_wire_v1.md` section 3.2).
//!
//! # Hashes
//!
//! Every value a step relation computes is `P(d, items)`, the RP57 Poseidon
//! [`hash_with_domain`] over the Pasta `Fp` σ field, under the G1 domains:
//! the state commitment `kgwcore1`, the rest digest `kgwrest1`, `credit_id`
//! `kgwcrdt1`, the chain appends `kgwschn1` / `kgwrchn1` and the statement
//! `kgwstmt1`. Element lists follow the G1 rule: an integer, tag or mask is
//! one element, a 32-byte SHA-256 digest or identifier two `u128` limbs (low
//! half first), a `P` value one element.
//!
//! # State
//!
//! A wallet state is a 32-element core ([`CoreState`], in the G1
//! `KagemushaWalletStateV1::core_field_items` order: lifecycle; scheme id,
//! asset digest, `wallet_id` and credential digest (two limbs each);
//! balance, `burned_total`, sequence, `next_send`, `next_load`,
//! `next_redeem`; both chains; the consumed-credit, pending-outgoing,
//! load/redeem-recovery, fee-claim and quota-usage roots; the
//! enabled-controls mask; the quota-windows root; the blacklist version,
//! root, issue time and maximum age; the lease expiry; the policy epoch; the
//! accepted-time floor; the state nonce) and a 13-element rest
//! ([`StateRest`]) that no step relation opens. The commitment is one `Fp`
//! value `P(kgwcore1, core || P(kgwrest1, rest))` (owner answer Q10).
//!
//! # Relations
//!
//! A [`SigmaRelation`] is a step and the enabled-controls mask its
//! verifying key is selected by (the G1 selector `(operation tag, mask)`,
//! owner answer Q11). Both steps open the predecessor commitment, require the
//! lifecycle to be Active or Retiring (carried unchanged: a Retiring wallet
//! keeps sending and receiving, spec section 6.3), a nonzero `u128` amount
//! and `sequence + 1 < 2^128`, hash the 24-element Request body into
//! `credit_id = P(kgwcrdt1, body)` (one element, owner answer Q1), require
//! distinct payer and receiver wallets, append one chain and commit the
//! successor with a fresh state nonce. The Request's scheme, asset and own
//! wallet are the opened core cells.
//!
//! - `sigma_send` takes `burned_total` and the pending-outgoing root of the
//!   predecessor's lineage proof as public inputs ([`LineageInputs`]). It
//!   requires the core's enabled-controls mask to be the relation's, checks
//!   `amount + fee < 2^128` and `amount + fee <= balance - burned_total`,
//!   advances the send ordinal without overflow and requires
//!   `request_policy_epoch <= policy_epoch` and
//!   `max(accepted_time_floor, request_time) <= lower <= upper` (all
//!   `u64`). The successor balance is `balance - amount - fee`, its
//!   `burned_total` the lineage input, its accepted-time floor `lower`, and
//!   its pending-outgoing and fee-claim roots are carried witnesses.
//!   `send_chain' = P(kgwschn1, [send_chain, credit_id, receiver (2),
//!   ordinal, amount, fee, request digest (2)])`.
//!   With the blacklist control in its mask it also enforces the maximum
//!   list age (owner answer Q5): while a list is held (`blacklist_version !=
//!   0`) under an age rule (`blacklist_max_age_ms != 0`),
//!   `blacklist_issued_at_ms <= upper <= blacklist_issued_at_ms +
//!   blacklist_max_age_ms` (the native G1 `check_blacklist` rule).
//! - `sigma_recv` credits the amount (`balance + amount < 2^128`). The
//!   Request's receiver is the core `wallet_id` (owner answer Q8: matched by
//!   `wallet_id`, never by credential digest; the Request's receiver
//!   credential digest is a Request term, so a Request quoted before a
//!   renewal stays receivable after it; the `payment_key` match is the
//!   native Payment check and `Λ_recv`'s). `recv_chain' = P(kgwrchn1,
//!   [recv_chain, credit_id, payer (2), amount])`, and the successor's
//!   consumed-credit root is a carried witness.
//!
//! Map roots that a step does not touch are copied; the roots it updates are
//! carried witnesses (spec section 3.2 assigns their transitions to the
//! native Advance check and to the lineage relation).
//!
//! The public input is the statement digest `P(kgwstmt1, 28 elements)`
//! ([`iroha_plonk_gadgets::statement`]): the G1
//! `KagemushaWalletStatementV1::field_items` with the scheme-level relation
//! identity carried by the witness ([`StepWitness::relation_id`]).
// TODO(G3, spec section 7): sigma_send with the blacklist control enforces
// only the maximum list age; the recipient non-membership opening against
// `blacklist_root`, the quota windows and usage update and the lease expiry
// check are not implemented, so `CONTROLS_SUPPORTED` admits the blacklist
// bit alone and no relation with an enabled control may be frozen into a
// verifying-key allowlist yet.
//!
//! # Native reference
//!
//! [`StepWitness::evaluate`] computes every digest and the successor core
//! with field arithmetic, exactly as the circuit does, and lists the
//! relation [`Violation`]s. An honest witness has none; the circuit has no
//! satisfying assignment for a witness with any.

use iroha_pasta::poseidon::{PoseidonField, hash_with_domain};
use iroha_plonk_gadgets::statement::{
    EFFECT_UNION_FIELDS, STATEMENT_DOMAIN, STATEMENT_FIELDS, STATEMENT_HEADER_FIELDS,
    STATEMENT_VERSION, StatementV1, StepRelation, digest_fields,
};

/// Core elements: every field a step relation reads, changes or carries.
pub const CORE_FIELDS: usize = 32;
/// Rest elements: the fields only the lineage relation opens.
pub const REST_FIELDS: usize = 13;
/// Inputs of the state commitment: the core and the rest digest.
pub const COMMITMENT_ARITY: usize = CORE_FIELDS + 1;
/// Elements of the Request body (the `credit_id` preimage).
pub const REQUEST_FIELDS: usize = 24;
/// Inputs of a `send_chain` append: the chain and the 8 descriptor elements.
pub const SEND_CHAIN_FIELDS: usize = 9;
/// Inputs of a `recv_chain` append: the chain and 4 descriptor elements.
pub const RECEIVE_CHAIN_FIELDS: usize = 5;
/// Effect elements of `sigma_send`: `credit_id`, receiver (2), send
/// ordinal, amount, fee, Request digest (2), accepted lower and upper time.
pub const SEND_EFFECT_FIELDS: usize = 10;
/// Effect elements of `sigma_recv`: `credit_id`, payer (2), amount.
pub const RECEIVE_EFFECT_FIELDS: usize = 4;
/// The Request body version (G1 `KAGEMUSHA_WALLET_VERSION_V1`).
pub const REQUEST_VERSION: u64 = 1;
/// The Active lifecycle tag.
pub const LIFECYCLE_ACTIVE: u8 = 1;
/// The Retiring lifecycle tag.
pub const LIFECYCLE_RETIRING: u8 = 2;

/// State commitment domain `kgwcore1` (G1 `KAGEMUSHA_WALLET_CORE_DOMAIN_V1`).
pub const CORE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwcore1");
/// Rest digest domain `kgwrest1` (G1 `KAGEMUSHA_WALLET_REST_DOMAIN_V1`).
pub const REST_DOMAIN: u64 = u64::from_le_bytes(*b"kgwrest1");
/// `credit_id` domain `kgwcrdt1` (G1 `KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1`).
pub const CREDIT_DOMAIN: u64 = u64::from_le_bytes(*b"kgwcrdt1");
/// `send_chain` append domain `kgwschn1` (G1
/// `KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1`).
pub const SEND_CHAIN_DOMAIN: u64 = u64::from_le_bytes(*b"kgwschn1");
/// `recv_chain` append domain `kgwrchn1` (G1
/// `KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1`).
pub const RECEIVE_CHAIN_DOMAIN: u64 = u64::from_le_bytes(*b"kgwrchn1");

/// Recipient blacklist control bit (G1 `KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1`).
pub const CONTROL_BLACKLIST: u32 = 1 << 0;
/// Sending quota control bit (G1 `KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1`).
pub const CONTROL_QUOTAS: u32 = 1 << 1;
/// Attestation lease control bit (G1
/// `KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1`).
pub const CONTROL_ATTESTATION_LEASE: u32 = 1 << 2;
/// Every defined control bit.
pub const CONTROLS_DEFINED: u32 = CONTROL_BLACKLIST | CONTROL_QUOTAS | CONTROL_ATTESTATION_LEASE;
/// The control bits a `sigma_send` of this crate may enable: the blacklist
/// control, whose maximum-age rule it enforces (see the module TODO).
pub const CONTROLS_SUPPORTED: u32 = CONTROL_BLACKLIST;

const _: () = assert!(SEND_EFFECT_FIELDS <= EFFECT_UNION_FIELDS);
const _: () = assert!(RECEIVE_EFFECT_FIELDS <= EFFECT_UNION_FIELDS);
const _: () = assert!(STATEMENT_HEADER_FIELDS + EFFECT_UNION_FIELDS == STATEMENT_FIELDS);

/// Core element positions (G1 core element order).
pub mod core_index {
    /// The lifecycle tag.
    pub const LIFECYCLE: usize = 0;
    /// The scheme identifier limbs.
    pub const SCHEME: usize = 1;
    /// The asset digest limbs.
    pub const ASSET: usize = 3;
    /// The `wallet_id` limbs.
    pub const WALLET: usize = 5;
    /// The credential digest limbs.
    pub const CREDENTIAL: usize = 7;
    /// The `u128` balance.
    pub const BALANCE: usize = 9;
    /// The `u128` `burned_total`.
    pub const BURNED_TOTAL: usize = 10;
    /// The `u128` sequence number.
    pub const SEQUENCE: usize = 11;
    /// The next send ordinal.
    pub const NEXT_SEND: usize = 12;
    /// The next load ordinal.
    pub const NEXT_LOAD: usize = 13;
    /// The next redeem ordinal.
    pub const NEXT_REDEEM: usize = 14;
    /// The send chain.
    pub const SEND_CHAIN: usize = 15;
    /// The receive chain.
    pub const RECEIVE_CHAIN: usize = 16;
    /// The consumed-credit root.
    pub const CONSUMED_CREDIT_ROOT: usize = 17;
    /// The pending-outgoing root.
    pub const PENDING_OUTGOING_ROOT: usize = 18;
    /// The load/redeem recovery root (one map keyed by `(kind, ordinal)`).
    pub const LOAD_REDEEM_ROOT: usize = 19;
    /// The fee-claim recovery root.
    pub const FEE_CLAIM_ROOT: usize = 20;
    /// The quota-usage root.
    pub const QUOTA_USAGE_ROOT: usize = 21;
    /// The enabled-controls mask.
    pub const ENABLED_CONTROLS: usize = 22;
    /// The quota-windows root.
    pub const QUOTA_WINDOWS_ROOT: usize = 23;
    /// The blacklist version.
    pub const BLACKLIST_VERSION: usize = 24;
    /// The blacklist root.
    pub const BLACKLIST_ROOT: usize = 25;
    /// The blacklist issue time.
    pub const BLACKLIST_ISSUED_AT: usize = 26;
    /// The regulatory policy's maximum blacklist age.
    pub const BLACKLIST_MAX_AGE: usize = 27;
    /// The lease expiry.
    pub const LEASE_EXPIRY: usize = 28;
    /// The `u64` policy epoch.
    pub const POLICY_EPOCH: usize = 29;
    /// The `u64` accepted-time floor.
    pub const TIME_FLOOR: usize = 30;
    /// The state nonce.
    pub const STATE_NONCE: usize = 31;
}

/// A step relation and the enabled-controls mask it enforces: the G1
/// verifying-key selector `(operation tag, mask)` (owner answer Q11).
///
/// `sigma_recv` has the empty mask (G1 selects every operation other than
/// Send with mask 0); `sigma_send` has one relation per mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigmaRelation {
    step: StepRelation,
    enabled_controls: u32,
}

impl SigmaRelation {
    /// `sigma_send` with every control off.
    pub const SEND: Self = Self::send(0);
    /// `sigma_recv`.
    pub const RECEIVE: Self = Self {
        step: StepRelation::Receive,
        enabled_controls: 0,
    };

    /// `sigma_send` enforcing `enabled_controls`.
    #[must_use]
    pub const fn send(enabled_controls: u32) -> Self {
        Self {
            step: StepRelation::Send,
            enabled_controls,
        }
    }

    /// The relation of `step` with every control off.
    #[must_use]
    pub const fn of(step: StepRelation) -> Self {
        match step {
            StepRelation::Send => Self::SEND,
            StepRelation::Receive => Self::RECEIVE,
        }
    }

    /// The step.
    #[must_use]
    pub const fn step(self) -> StepRelation {
        self.step
    }

    /// The enabled-controls mask the relation enforces (zero for Receive).
    #[must_use]
    pub const fn enabled_controls(self) -> u32 {
        self.enabled_controls
    }

    /// The G1 verifying-key selector `(operation tag, mask)`.
    #[must_use]
    pub const fn selector(self) -> (u8, u32) {
        (self.step.effect_tag(), self.enabled_controls)
    }

    /// Whether the relation enforces every bit of `control`.
    #[must_use]
    pub const fn enforces(self, control: u32) -> bool {
        control != 0 && self.enabled_controls & control == control
    }

    /// Whether this crate implements the relation: `sigma_recv`, or
    /// `sigma_send` with a mask of [`CONTROLS_SUPPORTED`] bits.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.enabled_controls & !CONTROLS_SUPPORTED == 0
    }

    /// A short label: `send_m<mask>` or `recv`.
    #[must_use]
    pub fn label(self) -> String {
        match self.step {
            StepRelation::Send => format!("send_m{}", self.enabled_controls),
            StepRelation::Receive => "recv".to_owned(),
        }
    }
}

/// The identity of a wallet incarnation (spec section 2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// The scheme identifier.
    pub scheme_id: [u8; 32],
    /// The asset scope digest.
    pub asset_digest: [u8; 32],
    /// The `wallet_id`.
    pub wallet_id: [u8; 32],
    /// The digest of the current credential.
    pub credential_digest: [u8; 32],
}

/// The five map roots of the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapRoots<F> {
    /// The consumed-credit root.
    pub consumed_credit: F,
    /// The pending-outgoing root.
    pub pending_outgoing: F,
    /// The load/redeem recovery root.
    pub load_redeem_recovery: F,
    /// The fee-claim recovery root.
    pub fee_claim_recovery: F,
    /// The quota-usage root.
    pub quota_usage: F,
}

/// The regulatory-control fields of the core (spec section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Controls<F> {
    /// The enabled-controls mask.
    pub enabled: u32,
    /// The windows root of the held quota share.
    pub quota_windows_root: F,
    /// The held blacklist version (zero: none held).
    pub blacklist_version: u64,
    /// The held blacklist gap-tree root.
    pub blacklist_root: F,
    /// The held blacklist issue time in Unix milliseconds.
    pub blacklist_issued_at_ms: u64,
    /// The regulatory policy's maximum blacklist age (zero: no age rule).
    pub blacklist_max_age_ms: u64,
    /// The attestation lease expiry.
    pub lease_expires_at_ms: u64,
}

/// The 32 core elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreState<F> {
    /// The lifecycle tag ([`LIFECYCLE_ACTIVE`] or [`LIFECYCLE_RETIRING`]).
    pub lifecycle: u8,
    /// The incarnation identity.
    pub identity: Identity,
    /// The balance.
    pub balance: u128,
    /// The burned total.
    pub burned_total: u128,
    /// The sequence number.
    pub sequence: u128,
    /// The next send ordinal.
    pub next_send: u128,
    /// The next load ordinal.
    pub next_load: u128,
    /// The next redeem ordinal.
    pub next_redeem: u128,
    /// The send chain.
    pub send_chain: F,
    /// The receive chain.
    pub recv_chain: F,
    /// The map roots.
    pub roots: MapRoots<F>,
    /// The regulatory controls.
    pub controls: Controls<F>,
    /// The policy epoch.
    pub policy_epoch: u64,
    /// The accepted-time floor in Unix milliseconds.
    pub accepted_time_floor_ms: u64,
    /// The state nonce.
    pub state_nonce: F,
}

impl<F: PoseidonField> CoreState<F> {
    /// The element encoding, in [`core_index`] order.
    #[must_use]
    pub fn fields(&self) -> [F; CORE_FIELDS] {
        let [scheme_lo, scheme_hi] = digest_fields::<F>(&self.identity.scheme_id);
        let [asset_lo, asset_hi] = digest_fields::<F>(&self.identity.asset_digest);
        let [wallet_lo, wallet_hi] = digest_fields::<F>(&self.identity.wallet_id);
        let [credential_lo, credential_hi] = digest_fields::<F>(&self.identity.credential_digest);
        let controls = &self.controls;
        [
            F::from(u64::from(self.lifecycle)),
            scheme_lo,
            scheme_hi,
            asset_lo,
            asset_hi,
            wallet_lo,
            wallet_hi,
            credential_lo,
            credential_hi,
            F::from_u128(self.balance),
            F::from_u128(self.burned_total),
            F::from_u128(self.sequence),
            F::from_u128(self.next_send),
            F::from_u128(self.next_load),
            F::from_u128(self.next_redeem),
            self.send_chain,
            self.recv_chain,
            self.roots.consumed_credit,
            self.roots.pending_outgoing,
            self.roots.load_redeem_recovery,
            self.roots.fee_claim_recovery,
            self.roots.quota_usage,
            F::from(u64::from(controls.enabled)),
            controls.quota_windows_root,
            F::from(controls.blacklist_version),
            controls.blacklist_root,
            F::from(controls.blacklist_issued_at_ms),
            F::from(controls.blacklist_max_age_ms),
            F::from(controls.lease_expires_at_ms),
            F::from(self.policy_epoch),
            F::from(self.accepted_time_floor_ms),
            self.state_nonce,
        ]
    }
}

/// The 13 rest elements (opaque to the step relations; the lineage relation
/// opens them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateRest {
    /// Controls the credential's regulatory policy permits.
    pub permitted_controls: u32,
    /// The regulatory policy's time-anchor response-age bound.
    pub time_anchor_max_response_ms: u64,
    /// Digest of the held scheme policy.
    pub scheme_policy: [u8; 32],
    /// The fee schedule the held scheme policy names.
    pub fee_schedule: [u8; 32],
    /// Digest of the held blacklist.
    pub blacklist: [u8; 32],
    /// Digest of the held quota share.
    pub quota_share: [u8; 32],
    /// Identity of the held quota share.
    pub quota_share_id: u64,
    /// Digest of the committed time anchor.
    pub time_anchor: [u8; 32],
}

impl StateRest {
    /// The element encoding (G1 rest element order).
    #[must_use]
    pub fn fields<F: PoseidonField>(&self) -> [F; REST_FIELDS] {
        let [policy_lo, policy_hi] = digest_fields::<F>(&self.scheme_policy);
        let [schedule_lo, schedule_hi] = digest_fields::<F>(&self.fee_schedule);
        let [blacklist_lo, blacklist_hi] = digest_fields::<F>(&self.blacklist);
        let [share_lo, share_hi] = digest_fields::<F>(&self.quota_share);
        let [anchor_lo, anchor_hi] = digest_fields::<F>(&self.time_anchor);
        [
            F::from(u64::from(self.permitted_controls)),
            F::from(self.time_anchor_max_response_ms),
            policy_lo,
            policy_hi,
            schedule_lo,
            schedule_hi,
            blacklist_lo,
            blacklist_hi,
            share_lo,
            share_hi,
            F::from(self.quota_share_id),
            anchor_lo,
            anchor_hi,
        ]
    }

    /// The rest digest `P(kgwrest1, rest elements)`.
    #[must_use]
    pub fn digest<F: PoseidonField>(&self) -> F {
        hash_with_domain(REST_DOMAIN, &self.fields::<F>())
    }
}

/// A wallet state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateV1<F> {
    /// The core.
    pub core: CoreState<F>,
    /// The rest.
    pub rest: StateRest,
}

/// The state commitment `P(kgwcore1, core || rest digest)`.
fn commit<F: PoseidonField>(core: &[F; CORE_FIELDS], rest_digest: F) -> F {
    let mut inputs = core.to_vec();
    inputs.push(rest_digest);
    hash_with_domain(CORE_DOMAIN, &inputs)
}

impl<F: PoseidonField> StateV1<F> {
    /// The state commitment `P(kgwcore1, core || P(kgwrest1, rest))`.
    #[must_use]
    pub fn commitment(&self) -> F {
        commit(&self.core.fields(), self.rest.digest())
    }
}

/// The Request terms neither wallet state holds (spec section 5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTerms {
    /// The amount.
    pub amount: u128,
    /// The exact fee.
    pub fee: u128,
    /// The fee schedule digest.
    pub fee_schedule: [u8; 32],
    /// The receiver's scheme policy epoch.
    pub policy_epoch: u64,
    /// The receiver's scheme policy digest.
    pub scheme_policy: [u8; 32],
    /// The receiver's authenticated accepted time (G1
    /// `receiver_accepted_time_ms`).
    pub request_time: u64,
    /// The certificate-set digest.
    pub certificates: [u8; 32],
    /// The fresh Request nonce.
    pub nonce: [u8; 32],
}

/// The canonical 24-element Request body (spec section 5.1; G1
/// `KagemushaWalletRequestBodyV1::field_items`): the `credit_id` preimage,
/// as both wallets and every consumer hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestBody {
    /// The scheme identifier.
    pub scheme_id: [u8; 32],
    /// The asset scope digest.
    pub asset_digest: [u8; 32],
    /// The payer wallet.
    pub payer_wallet: [u8; 32],
    /// The receiver wallet.
    pub receiver_wallet: [u8; 32],
    /// The payer send ordinal `s`.
    pub send_ordinal: u128,
    /// The digest of the receiver credential carried beside the body.
    pub receiver_credential_digest: [u8; 32],
    /// The remaining terms.
    pub terms: RequestTerms,
}

impl RequestBody {
    /// The element encoding in request-body order.
    #[must_use]
    pub fn fields<F: PoseidonField>(&self) -> [F; REQUEST_FIELDS] {
        let pair = digest_fields::<F>;
        let [scheme_lo, scheme_hi] = pair(&self.scheme_id);
        let [asset_lo, asset_hi] = pair(&self.asset_digest);
        let [payer_lo, payer_hi] = pair(&self.payer_wallet);
        let [receiver_lo, receiver_hi] = pair(&self.receiver_wallet);
        let [credential_lo, credential_hi] = pair(&self.receiver_credential_digest);
        let terms = &self.terms;
        let [schedule_lo, schedule_hi] = pair(&terms.fee_schedule);
        let [policy_lo, policy_hi] = pair(&terms.scheme_policy);
        let [certificates_lo, certificates_hi] = pair(&terms.certificates);
        let [nonce_lo, nonce_hi] = pair(&terms.nonce);
        [
            F::from(REQUEST_VERSION),
            scheme_lo,
            scheme_hi,
            asset_lo,
            asset_hi,
            payer_lo,
            payer_hi,
            receiver_lo,
            receiver_hi,
            F::from_u128(self.send_ordinal),
            credential_lo,
            credential_hi,
            F::from_u128(terms.amount),
            schedule_lo,
            schedule_hi,
            F::from_u128(terms.fee),
            F::from(terms.policy_epoch),
            policy_lo,
            policy_hi,
            F::from(terms.request_time),
            certificates_lo,
            certificates_hi,
            nonce_lo,
            nonce_hi,
        ]
    }

    /// `credit_id = P(kgwcrdt1, Request body)`: one σ-field element.
    #[must_use]
    pub fn credit_id<F: PoseidonField>(&self) -> F {
        hash_with_domain(CREDIT_DOMAIN, &self.fields::<F>())
    }
}

/// The values a `sigma_send` takes from the predecessor's lineage proof
/// Ω(pred) (spec section 3.2): public inputs a consumer compares with Ω's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineageInputs<F> {
    /// The lineage-adjusted `burned_total`.
    pub burned_total: u128,
    /// The lineage-adjusted pending-outgoing root.
    pub pending_outgoing_root: F,
}

/// The `sigma_send` inputs beyond the predecessor state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendInputs<F> {
    /// The receiver wallet.
    pub receiver_wallet: [u8; 32],
    /// The receiver credential digest of the Request.
    pub receiver_credential_digest: [u8; 32],
    /// The other Request terms.
    pub request: RequestTerms,
    /// The digest of the signed Request (G1 `H("request", e || signature)`),
    /// bound by the Send effect and the chain append; `sigma_send` does not
    /// recompute it (SHA-256).
    pub request_digest: [u8; 32],
    /// The accepted lower time.
    pub accepted_lower: u64,
    /// The accepted upper time.
    pub accepted_upper: u64,
    /// The inputs taken from the predecessor's lineage proof.
    pub lineage: LineageInputs<F>,
    /// The successor's pending-outgoing root (the lineage input root with
    /// this credit's descriptor inserted; checked natively at Advance and by
    /// the lineage relation).
    pub successor_pending_outgoing: F,
    /// The successor's fee-claim recovery root (checked natively at Advance
    /// and by the lineage relation).
    pub successor_fee_claim: F,
}

/// The `sigma_recv` inputs beyond the predecessor state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveInputs<F> {
    /// The payer wallet.
    pub payer_wallet: [u8; 32],
    /// The payer send ordinal `s`.
    pub send_ordinal: u128,
    /// The receiver credential digest the Request was quoted under (equal
    /// to the core's unless the credential was renewed since).
    pub receiver_credential_digest: [u8; 32],
    /// The other Request terms.
    pub request: RequestTerms,
    /// The successor's consumed-credit root (the predecessor's with
    /// `credit_id` inserted; checked natively at Advance and by the lineage
    /// relation).
    pub successor_consumed_credit: F,
}

/// The step-specific inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepInputs<F> {
    /// `sigma_send`.
    Send(Box<SendInputs<F>>),
    /// `sigma_recv`.
    Receive(Box<ReceiveInputs<F>>),
}

impl<F> StepInputs<F> {
    /// The step these inputs belong to.
    #[must_use]
    pub const fn relation(&self) -> StepRelation {
        match self {
            Self::Send(_) => StepRelation::Send,
            Self::Receive(_) => StepRelation::Receive,
        }
    }

    /// The Request terms.
    #[must_use]
    pub fn terms(&self) -> &RequestTerms {
        match self {
            Self::Send(send) => &send.request,
            Self::Receive(receive) => &receive.request,
        }
    }

    /// The amount.
    #[must_use]
    pub fn amount(&self) -> u128 {
        self.terms().amount
    }
}

/// A full step witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepWitness<F> {
    /// The scheme-level relation identity the statement carries (G1
    /// `KagemushaWalletSchemeV1::relation_id`).
    pub relation_id: [u8; 32],
    /// The predecessor state.
    pub predecessor: StateV1<F>,
    /// The successor's fresh state nonce.
    pub successor_nonce: F,
    /// The step inputs.
    pub inputs: StepInputs<F>,
}

/// A relation rule the witness breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Violation {
    /// The witness belongs to another step than the relation.
    WrongStep,
    /// The relation enables a control this crate does not implement.
    UnsupportedRelation,
    /// The predecessor lifecycle is neither Active nor Retiring.
    Lifecycle,
    /// The amount is zero.
    ZeroAmount,
    /// `sequence + 1` reaches `2^128`.
    SequenceOverflow,
    /// The payer and receiver wallets are equal.
    SelfPayment,
    /// `sigma_send`: the core's enabled-controls mask is not the relation's.
    ControlsMismatch,
    /// `sigma_send`: `amount + fee` reaches `2^128`.
    DebitOverflow,
    /// `sigma_send`: `amount + fee` exceeds `balance - burned_total` (with
    /// the lineage input `burned_total`), or `burned_total` exceeds the
    /// balance.
    Overdraft,
    /// `sigma_send`: `next_send + 1` reaches `2^128`.
    SendOrdinalOverflow,
    /// `sigma_send`: the Request policy epoch is newer than the payer's.
    PolicyEpochNewer,
    /// `sigma_send`: the accepted lower time is below the accepted-time
    /// floor.
    AcceptedTimeBelowFloor,
    /// `sigma_send`: the accepted lower time is below the Request time.
    AcceptedTimeBelowRequest,
    /// `sigma_send`: the accepted upper time is below the lower time.
    AcceptedWindowInverted,
    /// `sigma_send` with the blacklist control: the held list is older than
    /// the maximum age at the accepted upper time, or issued after it.
    BlacklistTooOld,
    /// `sigma_recv`: `balance + amount` reaches `2^128`.
    BalanceOverflow,
}

/// The public input of a step proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepPublic<F> {
    /// The statement digest `P(kgwstmt1, statement elements)`.
    pub statement: F,
}

impl<F: Copy> StepPublic<F> {
    /// The instance column: the statement digest.
    #[must_use]
    pub fn instance(&self) -> Vec<F> {
        vec![self.statement]
    }
}

/// Every digest a step computes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepDigests<F> {
    /// The predecessor commitment.
    pub predecessor: F,
    /// The successor commitment.
    pub successor: F,
    /// The credit identifier `P(kgwcrdt1, Request body)`.
    pub credit: F,
    /// The appended chain (`send_chain'` or `recv_chain'`).
    pub chain: F,
    /// The statement digest.
    pub statement: F,
}

/// The reference evaluation of a step (field arithmetic, as in circuit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeStep<F> {
    /// The relation evaluated.
    pub relation: SigmaRelation,
    /// The successor core elements.
    pub successor_core: [F; CORE_FIELDS],
    /// The successor state, for a witness without violations.
    pub successor_state: Option<StateV1<F>>,
    /// The Request body.
    pub request: RequestBody,
    /// The chain append inputs that were hashed.
    pub chain_entry: Vec<F>,
    /// The statement encoding.
    pub statement: [F; STATEMENT_FIELDS],
    /// The digests.
    pub digests: StepDigests<F>,
    /// The rules the witness breaks (empty for an honest witness).
    pub violations: Vec<Violation>,
}

impl<F: Copy> NativeStep<F> {
    /// The public input the circuit computes from the witness.
    #[must_use]
    pub const fn public(&self) -> StepPublic<F> {
        StepPublic {
            statement: self.digests.statement,
        }
    }

    /// Whether the witness satisfies the relation.
    #[must_use]
    pub fn is_honest(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Whether the maximum-age rule rejects a held blacklist at `upper` (the
/// native G1 `check_blacklist` age check: underflow or an age above the
/// maximum).
fn blacklist_too_old(controls: &Controls<impl Sized>, upper: u64) -> bool {
    controls.blacklist_version != 0
        && controls.blacklist_max_age_ms != 0
        && upper
            .checked_sub(controls.blacklist_issued_at_ms)
            .is_none_or(|age| age > controls.blacklist_max_age_ms)
}

/// The relation rules `witness` breaks under `relation`.
fn violations<F>(witness: &StepWitness<F>, relation: SigmaRelation) -> Vec<Violation> {
    let core = &witness.predecessor.core;
    let mut found = Vec::new();
    if witness.inputs.relation() != relation.step() {
        found.push(Violation::WrongStep);
    }
    if !relation.is_supported() {
        found.push(Violation::UnsupportedRelation);
    }
    if core.lifecycle != LIFECYCLE_ACTIVE && core.lifecycle != LIFECYCLE_RETIRING {
        found.push(Violation::Lifecycle);
    }
    if witness.inputs.amount() == 0 {
        found.push(Violation::ZeroAmount);
    }
    if core.sequence == u128::MAX {
        found.push(Violation::SequenceOverflow);
    }
    let counterparty = match &witness.inputs {
        StepInputs::Send(send) => &send.receiver_wallet,
        StepInputs::Receive(receive) => &receive.payer_wallet,
    };
    if *counterparty == core.identity.wallet_id {
        found.push(Violation::SelfPayment);
    }
    match &witness.inputs {
        StepInputs::Send(send) => {
            if core.controls.enabled != relation.enabled_controls() {
                found.push(Violation::ControlsMismatch);
            }
            let debit = send.request.amount.checked_add(send.request.fee);
            if debit.is_none() {
                found.push(Violation::DebitOverflow);
            }
            let affordable = core
                .balance
                .checked_sub(send.lineage.burned_total)
                .zip(debit)
                .is_some_and(|(spendable, debit)| debit <= spendable);
            if !affordable {
                found.push(Violation::Overdraft);
            }
            if core.next_send == u128::MAX {
                found.push(Violation::SendOrdinalOverflow);
            }
            if send.request.policy_epoch > core.policy_epoch {
                found.push(Violation::PolicyEpochNewer);
            }
            if send.accepted_lower < core.accepted_time_floor_ms {
                found.push(Violation::AcceptedTimeBelowFloor);
            }
            if send.accepted_lower < send.request.request_time {
                found.push(Violation::AcceptedTimeBelowRequest);
            }
            if send.accepted_upper < send.accepted_lower {
                found.push(Violation::AcceptedWindowInverted);
            }
            if relation.enforces(CONTROL_BLACKLIST)
                && blacklist_too_old(&core.controls, send.accepted_upper)
            {
                found.push(Violation::BlacklistTooOld);
            }
        }
        StepInputs::Receive(receive) => {
            if core.balance.checked_add(receive.request.amount).is_none() {
                found.push(Violation::BalanceOverflow);
            }
        }
    }
    found
}

impl<F: PoseidonField> StepWitness<F> {
    /// The step of this witness.
    #[must_use]
    pub const fn relation(&self) -> StepRelation {
        self.inputs.relation()
    }

    /// The Request body: the scheme, asset and own wallet come from the
    /// predecessor core (the payer's for `sigma_send`, the receiver's for
    /// `sigma_recv`), the rest from the inputs.
    #[must_use]
    pub fn request_body(&self) -> RequestBody {
        let core = &self.predecessor.core;
        let identity = &core.identity;
        match &self.inputs {
            StepInputs::Send(send) => RequestBody {
                scheme_id: identity.scheme_id,
                asset_digest: identity.asset_digest,
                payer_wallet: identity.wallet_id,
                receiver_wallet: send.receiver_wallet,
                send_ordinal: core.next_send,
                receiver_credential_digest: send.receiver_credential_digest,
                terms: send.request,
            },
            StepInputs::Receive(receive) => RequestBody {
                scheme_id: identity.scheme_id,
                asset_digest: identity.asset_digest,
                payer_wallet: receive.payer_wallet,
                receiver_wallet: identity.wallet_id,
                send_ordinal: receive.send_ordinal,
                receiver_credential_digest: receive.receiver_credential_digest,
                terms: receive.request,
            },
        }
    }

    /// The typed successor state of an honest witness, given its appended
    /// chain value (`None` when the integer arithmetic fails).
    fn successor_state(&self, chain: F) -> Option<StateV1<F>> {
        let mut core = self.predecessor.core;
        core.sequence = core.sequence.checked_add(1)?;
        core.state_nonce = self.successor_nonce;
        match &self.inputs {
            StepInputs::Send(send) => {
                let debit = send.request.amount.checked_add(send.request.fee)?;
                core.balance = core.balance.checked_sub(debit)?;
                core.burned_total = send.lineage.burned_total;
                core.next_send = core.next_send.checked_add(1)?;
                core.send_chain = chain;
                core.roots.pending_outgoing = send.successor_pending_outgoing;
                core.roots.fee_claim_recovery = send.successor_fee_claim;
                core.accepted_time_floor_ms = send.accepted_lower;
            }
            StepInputs::Receive(receive) => {
                core.balance = core.balance.checked_add(receive.request.amount)?;
                core.recv_chain = chain;
                core.roots.consumed_credit = receive.successor_consumed_credit;
            }
        }
        Some(StateV1 {
            core,
            rest: self.predecessor.rest,
        })
    }

    /// The public statement of an honest witness under `relation` (`None`
    /// when the witness breaks the relation).
    #[must_use]
    pub fn statement(&self, relation: SigmaRelation) -> Option<StatementV1<F>> {
        let native = self.evaluate(relation);
        let successor = native.successor_state?;
        if !native.violations.is_empty() {
            return None;
        }
        let core = &self.predecessor.core;
        let (lineage_burned_total, lineage_pending_outgoing_root) = match &self.inputs {
            StepInputs::Send(send) => (
                send.lineage.burned_total,
                send.lineage.pending_outgoing_root,
            ),
            StepInputs::Receive(_) => (0, F::ZERO),
        };
        let effect_len = match self.relation() {
            StepRelation::Send => SEND_EFFECT_FIELDS,
            StepRelation::Receive => RECEIVE_EFFECT_FIELDS,
        };
        Some(StatementV1 {
            relation_id: self.relation_id,
            step: self.relation(),
            scheme_id: core.identity.scheme_id,
            asset_digest: core.identity.asset_digest,
            credential_digest: core.identity.credential_digest,
            lifecycle: successor.core.lifecycle,
            sequence: successor.core.sequence,
            next_load: successor.core.next_load,
            enabled_controls: core.controls.enabled,
            lineage_burned_total,
            lineage_pending_outgoing_root,
            predecessor: native.digests.predecessor,
            successor: native.digests.successor,
            effect: native.statement[STATEMENT_HEADER_FIELDS..][..effect_len].to_vec(),
        })
    }

    /// The reference evaluation under `relation`.
    #[must_use]
    pub fn evaluate(&self, relation: SigmaRelation) -> NativeStep<F> {
        let state = &self.predecessor;
        let core = state.core.fields();
        let rest_digest = state.rest.digest::<F>();
        let predecessor = commit(&core, rest_digest);
        let request = self.request_body();
        let credit = request.credit_id::<F>();
        let mut successor_core = core;
        successor_core[core_index::SEQUENCE] += F::ONE;
        successor_core[core_index::STATE_NONCE] = self.successor_nonce;
        let amount = F::from_u128(request.terms.amount);
        let (chain_entry, chain_domain, effect, lineage) = match &self.inputs {
            StepInputs::Send(send) => {
                let [receiver_lo, receiver_hi] = digest_fields::<F>(&send.receiver_wallet);
                let [request_lo, request_hi] = digest_fields::<F>(&send.request_digest);
                let ordinal = core[core_index::NEXT_SEND];
                let fee = F::from_u128(send.request.fee);
                let entry = vec![
                    core[core_index::SEND_CHAIN],
                    credit,
                    receiver_lo,
                    receiver_hi,
                    ordinal,
                    amount,
                    fee,
                    request_lo,
                    request_hi,
                ];
                let effect = vec![
                    credit,
                    receiver_lo,
                    receiver_hi,
                    ordinal,
                    amount,
                    fee,
                    request_lo,
                    request_hi,
                    F::from(send.accepted_lower),
                    F::from(send.accepted_upper),
                ];
                successor_core[core_index::BALANCE] -= amount + fee;
                successor_core[core_index::BURNED_TOTAL] = F::from_u128(send.lineage.burned_total);
                successor_core[core_index::NEXT_SEND] += F::ONE;
                successor_core[core_index::PENDING_OUTGOING_ROOT] = send.successor_pending_outgoing;
                successor_core[core_index::FEE_CLAIM_ROOT] = send.successor_fee_claim;
                successor_core[core_index::TIME_FLOOR] = F::from(send.accepted_lower);
                let lineage = [
                    F::from_u128(send.lineage.burned_total),
                    send.lineage.pending_outgoing_root,
                ];
                (entry, SEND_CHAIN_DOMAIN, effect, lineage)
            }
            StepInputs::Receive(receive) => {
                let [payer_lo, payer_hi] = digest_fields::<F>(&receive.payer_wallet);
                let entry = vec![
                    core[core_index::RECEIVE_CHAIN],
                    credit,
                    payer_lo,
                    payer_hi,
                    amount,
                ];
                let effect = vec![credit, payer_lo, payer_hi, amount];
                successor_core[core_index::BALANCE] += amount;
                successor_core[core_index::CONSUMED_CREDIT_ROOT] =
                    receive.successor_consumed_credit;
                (entry, RECEIVE_CHAIN_DOMAIN, effect, [F::ZERO; 2])
            }
        };
        let chain = hash_with_domain(chain_domain, &chain_entry);
        let step = self.relation();
        match step {
            StepRelation::Send => successor_core[core_index::SEND_CHAIN] = chain,
            StepRelation::Receive => successor_core[core_index::RECEIVE_CHAIN] = chain,
        }
        let successor = commit(&successor_core, rest_digest);
        let mut statement = [F::ZERO; STATEMENT_FIELDS];
        let [relation_lo, relation_hi] = digest_fields::<F>(&self.relation_id);
        let header = [
            F::from(STATEMENT_VERSION),
            relation_lo,
            relation_hi,
            core[core_index::SCHEME],
            core[core_index::SCHEME + 1],
            core[core_index::ASSET],
            core[core_index::ASSET + 1],
            core[core_index::CREDENTIAL],
            core[core_index::CREDENTIAL + 1],
            successor_core[core_index::LIFECYCLE],
            successor_core[core_index::SEQUENCE],
            successor_core[core_index::NEXT_LOAD],
            core[core_index::ENABLED_CONTROLS],
            lineage[0],
            lineage[1],
            predecessor,
            successor,
            F::from(u64::from(step.effect_tag())),
        ];
        statement[..STATEMENT_HEADER_FIELDS].copy_from_slice(&header);
        statement[STATEMENT_HEADER_FIELDS..STATEMENT_HEADER_FIELDS + effect.len()]
            .copy_from_slice(&effect);
        let statement_digest = hash_with_domain(STATEMENT_DOMAIN, &statement);
        let violations = violations(self, relation);
        let successor_state = if violations.is_empty() {
            self.successor_state(chain)
        } else {
            None
        };
        NativeStep {
            relation,
            successor_core,
            successor_state,
            request,
            chain_entry,
            statement,
            digests: StepDigests {
                predecessor,
                successor,
                credit,
                chain,
                statement: statement_digest,
            },
            violations,
        }
    }
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use iroha_pasta::{Fp, Fq};

    use super::*;
    use crate::vectors::{Mutation, sample_witness};

    #[test]
    fn domains_and_selectors_are_the_g1_ones() {
        assert_eq!(CORE_DOMAIN.to_le_bytes(), *b"kgwcore1");
        assert_eq!(REST_DOMAIN.to_le_bytes(), *b"kgwrest1");
        assert_eq!(CREDIT_DOMAIN.to_le_bytes(), *b"kgwcrdt1");
        assert_eq!(SEND_CHAIN_DOMAIN.to_le_bytes(), *b"kgwschn1");
        assert_eq!(RECEIVE_CHAIN_DOMAIN.to_le_bytes(), *b"kgwrchn1");
        assert_eq!(COMMITMENT_ARITY, 33);
        assert_eq!(SigmaRelation::SEND.selector(), (3, 0));
        assert_eq!(SigmaRelation::send(CONTROL_BLACKLIST).selector(), (3, 1));
        assert_eq!(SigmaRelation::RECEIVE.selector(), (4, 0));
        assert_eq!(
            SigmaRelation::of(StepRelation::Receive),
            SigmaRelation::RECEIVE
        );
        assert!(SigmaRelation::send(CONTROL_BLACKLIST).enforces(CONTROL_BLACKLIST));
        assert!(!SigmaRelation::SEND.enforces(CONTROL_BLACKLIST));
        assert!(!SigmaRelation::SEND.enforces(0));
        assert!(SigmaRelation::send(CONTROL_BLACKLIST).is_supported());
        for unsupported in [
            CONTROL_QUOTAS,
            CONTROL_ATTESTATION_LEASE,
            CONTROLS_DEFINED,
            8,
        ] {
            assert!(!SigmaRelation::send(unsupported).is_supported());
        }
        assert_eq!(SigmaRelation::send(1).label(), "send_m1");
        assert_eq!(SigmaRelation::RECEIVE.label(), "recv");
    }

    #[test]
    fn field_encodings_follow_the_core_layout() {
        let witness = sample_witness::<Fp>(3, SigmaRelation::SEND, Mutation::None);
        let state = witness.predecessor;
        let core = state.core.fields();
        assert_eq!(core[core_index::BALANCE], Fp::from_u128(state.core.balance));
        assert_eq!(core[core_index::LIFECYCLE], Fp::ONE);
        assert_eq!(
            [core[core_index::WALLET], core[core_index::WALLET + 1]],
            digest_fields::<Fp>(&state.core.identity.wallet_id)
        );
        assert_eq!(
            [core[core_index::ASSET], core[core_index::ASSET + 1]],
            digest_fields::<Fp>(&state.core.identity.asset_digest)
        );
        assert_eq!(
            core[core_index::BLACKLIST_ISSUED_AT],
            Fp::from(state.core.controls.blacklist_issued_at_ms)
        );
        assert_eq!(
            core[core_index::BLACKLIST_MAX_AGE],
            Fp::from(state.core.controls.blacklist_max_age_ms)
        );
        assert_eq!(
            core[core_index::LOAD_REDEEM_ROOT],
            state.core.roots.load_redeem_recovery
        );
        assert_eq!(
            core[core_index::TIME_FLOOR],
            Fp::from(state.core.accepted_time_floor_ms)
        );
        assert_eq!(core[core_index::STATE_NONCE], state.core.state_nonce);
        let rest = state.rest.fields::<Fp>();
        assert_eq!(rest[0], Fp::from(u64::from(state.rest.permitted_controls)));
        assert_eq!(rest[10], Fp::from(state.rest.quota_share_id));
        assert_eq!(
            state.commitment(),
            hash_with_domain(
                CORE_DOMAIN,
                &[core.as_slice(), &[hash_with_domain(REST_DOMAIN, &rest)]].concat()
            )
        );
    }

    #[test]
    fn request_bodies_take_identity_from_the_state() {
        let send = sample_witness::<Fp>(4, SigmaRelation::SEND, Mutation::None);
        let body = send.request_body();
        let core = &send.predecessor.core;
        assert_eq!(body.payer_wallet, core.identity.wallet_id);
        assert_eq!(body.scheme_id, core.identity.scheme_id);
        assert_eq!(body.asset_digest, core.identity.asset_digest);
        assert_eq!(body.send_ordinal, core.next_send);
        let fields = body.fields::<Fp>();
        assert_eq!(fields[0], Fp::from(REQUEST_VERSION));
        assert_eq!(fields[9], Fp::from_u128(core.next_send));
        assert_eq!(fields[12], Fp::from_u128(body.terms.amount));
        assert_eq!(
            body.credit_id::<Fp>(),
            hash_with_domain(CREDIT_DOMAIN, &fields)
        );
        let receive = sample_witness::<Fq>(4, SigmaRelation::RECEIVE, Mutation::None);
        let body = receive.request_body();
        let core = &receive.predecessor.core;
        assert_eq!(body.receiver_wallet, core.identity.wallet_id);
        let StepInputs::Receive(inputs) = &receive.inputs else {
            panic!("receive witness");
        };
        // The receiver credential digest is the Request's, not the core's.
        assert_eq!(
            body.receiver_credential_digest,
            inputs.receiver_credential_digest
        );
        assert_eq!(receive.inputs.terms(), &body.terms);
    }

    /// The statement encoding equals the gadgets' `StatementV1` for honest
    /// witnesses.
    fn statement_matches_gadgets<F: PoseidonField>(relation: SigmaRelation) {
        let witness = sample_witness::<F>(11, relation, Mutation::None);
        let native = witness.evaluate(relation);
        assert!(native.is_honest(), "{:?}", native.violations);
        let statement = witness.statement(relation).expect("honest statement");
        assert_eq!(statement.encode(), Some(native.statement));
        assert_eq!(statement.digest(), Some(native.digests.statement));
        assert_eq!(statement.relation_id, witness.relation_id);
        assert_eq!(statement.enabled_controls, relation.enabled_controls());
        assert_eq!(native.public().statement, native.digests.statement);
        assert_eq!(native.public().instance(), vec![native.digests.statement]);
    }

    #[test]
    fn statements_match_the_gadget_encoding_on_both_fields() {
        for relation in [
            SigmaRelation::SEND,
            SigmaRelation::send(CONTROL_BLACKLIST),
            SigmaRelation::RECEIVE,
        ] {
            statement_matches_gadgets::<Fp>(relation);
            statement_matches_gadgets::<Fq>(relation);
        }
    }

    #[test]
    fn send_reference_debits_and_appends() {
        let witness = sample_witness::<Fp>(5, SigmaRelation::SEND, Mutation::None);
        let StepInputs::Send(send) = &witness.inputs else {
            panic!("send witness");
        };
        let native = witness.evaluate(SigmaRelation::SEND);
        let core = witness.predecessor.core;
        let successor = native.successor_state.expect("honest successor");
        assert_eq!(successor.core.fields(), native.successor_core);
        assert_eq!(
            successor.core.balance,
            core.balance - send.request.amount - send.request.fee
        );
        assert_eq!(successor.core.burned_total, send.lineage.burned_total);
        assert_eq!(successor.core.next_send, core.next_send + 1);
        assert_eq!(successor.core.accepted_time_floor_ms, send.accepted_lower);
        assert_eq!(successor.core.lifecycle, core.lifecycle);
        assert_eq!(
            successor.core.roots.pending_outgoing,
            send.successor_pending_outgoing
        );
        assert_eq!(
            successor.core.roots.consumed_credit,
            core.roots.consumed_credit
        );
        assert_eq!(
            successor.core.send_chain,
            hash_with_domain(SEND_CHAIN_DOMAIN, &native.chain_entry)
        );
        assert_eq!(native.chain_entry.len(), SEND_CHAIN_FIELDS);
        // The chain entry and the effect carry the one-element credit_id.
        assert_eq!(native.chain_entry[1], native.digests.credit);
        assert_eq!(
            native.statement[STATEMENT_HEADER_FIELDS],
            native.digests.credit
        );
        // The Send effect and chain bind the Request digest limbs after the
        // fee.
        let request = digest_fields::<Fp>(&send.request_digest);
        assert_eq!(native.statement[24..26], request);
        assert_eq!(native.chain_entry[7..9], request);
        assert_eq!(
            native.digests.credit,
            hash_with_domain(CREDIT_DOMAIN, &native.request.fields::<Fp>())
        );
        assert_eq!(successor.commitment(), native.digests.successor);
    }

    #[test]
    fn receive_reference_credits_and_appends() {
        let witness = sample_witness::<Fq>(6, SigmaRelation::RECEIVE, Mutation::None);
        let StepInputs::Receive(receive) = &witness.inputs else {
            panic!("receive witness");
        };
        let native = witness.evaluate(SigmaRelation::RECEIVE);
        let core = witness.predecessor.core;
        let successor = native.successor_state.expect("honest successor");
        assert_eq!(successor.core.fields(), native.successor_core);
        assert_eq!(
            successor.core.balance,
            core.balance + receive.request.amount
        );
        assert_eq!(
            successor.core.roots.consumed_credit,
            receive.successor_consumed_credit
        );
        assert_eq!(successor.core.burned_total, core.burned_total);
        assert_eq!(
            successor.core.accepted_time_floor_ms,
            core.accepted_time_floor_ms
        );
        assert_eq!(native.chain_entry.len(), RECEIVE_CHAIN_FIELDS);
        assert_eq!(native.public().instance(), vec![native.digests.statement]);
        // The lineage inputs of a Receive statement are zero.
        assert_eq!(native.statement[13], Fq::ZERO);
        assert_eq!(native.statement[14], Fq::ZERO);
        assert_eq!(witness.relation(), StepRelation::Receive);
        assert_eq!(successor.commitment(), native.digests.successor);
    }

    #[test]
    fn mutations_are_reported_as_violations() {
        let blacklist = SigmaRelation::send(CONTROL_BLACKLIST);
        let cases = [
            (
                SigmaRelation::SEND,
                Mutation::Overdraft,
                Violation::Overdraft,
            ),
            (SigmaRelation::SEND, Mutation::Burned, Violation::Overdraft),
            (
                SigmaRelation::SEND,
                Mutation::StaleEpoch,
                Violation::PolicyEpochNewer,
            ),
            (
                SigmaRelation::SEND,
                Mutation::EarlyTime,
                Violation::AcceptedTimeBelowFloor,
            ),
            (
                SigmaRelation::SEND,
                Mutation::SelfPayment,
                Violation::SelfPayment,
            ),
            (
                SigmaRelation::SEND,
                Mutation::ControlsMismatch,
                Violation::ControlsMismatch,
            ),
            (
                blacklist,
                Mutation::StaleBlacklist,
                Violation::BlacklistTooOld,
            ),
            (
                blacklist,
                Mutation::FutureBlacklist,
                Violation::BlacklistTooOld,
            ),
            (
                SigmaRelation::RECEIVE,
                Mutation::Overflow,
                Violation::BalanceOverflow,
            ),
            (
                SigmaRelation::RECEIVE,
                Mutation::SelfPayment,
                Violation::SelfPayment,
            ),
        ];
        for (relation, mutation, violation) in cases {
            let native = sample_witness::<Fp>(9, relation, mutation).evaluate(relation);
            assert_eq!(native.violations, vec![violation], "{mutation:?}");
            assert!(native.successor_state.is_none());
        }
        // Without the blacklist control the age rule is not enforced.
        for mutation in [Mutation::StaleBlacklist, Mutation::FutureBlacklist] {
            assert!(
                sample_witness::<Fp>(9, SigmaRelation::SEND, mutation)
                    .evaluate(SigmaRelation::SEND)
                    .is_honest()
            );
        }
        let mut witness = sample_witness::<Fp>(9, SigmaRelation::SEND, Mutation::None);
        witness.predecessor.core.lifecycle = 3;
        witness.predecessor.core.sequence = u128::MAX;
        witness.predecessor.core.next_send = u128::MAX;
        if let StepInputs::Send(send) = &mut witness.inputs {
            send.request.amount = 0;
            send.accepted_upper = 0;
        }
        let found = witness.evaluate(SigmaRelation::SEND).violations;
        for violation in [
            Violation::Lifecycle,
            Violation::ZeroAmount,
            Violation::SequenceOverflow,
            Violation::SendOrdinalOverflow,
            Violation::AcceptedWindowInverted,
        ] {
            assert!(found.contains(&violation), "{violation:?}");
        }
        assert_eq!(witness.statement(SigmaRelation::SEND), None);
        // The overflowing successor sequence is the field value 2^128.
        let native = witness.evaluate(SigmaRelation::SEND);
        assert_eq!(
            native.successor_core[core_index::SEQUENCE],
            Fp::from_u128(u128::MAX) + Fp::ONE
        );
        // A debit of 2^128 overflows and overdraws.
        let mut witness = sample_witness::<Fp>(9, SigmaRelation::SEND, Mutation::None);
        if let StepInputs::Send(send) = &mut witness.inputs {
            send.request.amount = u128::MAX;
            send.request.fee = 1;
        }
        assert_eq!(
            witness.evaluate(SigmaRelation::SEND).violations,
            vec![Violation::DebitOverflow, Violation::Overdraft]
        );
        // A witness of the other step, and a relation this crate does not
        // implement.
        let send = sample_witness::<Fp>(9, SigmaRelation::SEND, Mutation::None);
        assert_eq!(
            send.evaluate(SigmaRelation::RECEIVE).violations,
            vec![Violation::WrongStep]
        );
        let mut quota = send;
        quota.predecessor.core.controls.enabled = CONTROL_QUOTAS;
        assert_eq!(
            quota
                .evaluate(SigmaRelation::send(CONTROL_QUOTAS))
                .violations,
            vec![Violation::UnsupportedRelation]
        );
    }

    #[test]
    fn retiring_wallets_keep_sending_and_receiving() {
        for relation in [SigmaRelation::SEND, SigmaRelation::RECEIVE] {
            let mut witness = sample_witness::<Fp>(12, relation, Mutation::None);
            witness.predecessor.core.lifecycle = LIFECYCLE_RETIRING;
            let native = witness.evaluate(relation);
            assert!(native.is_honest(), "{relation:?}");
            assert_eq!(
                native.successor_state.map(|state| state.core.lifecycle),
                Some(LIFECYCLE_RETIRING)
            );
            assert_eq!(
                witness
                    .statement(relation)
                    .map(|statement| statement.lifecycle),
                Some(LIFECYCLE_RETIRING)
            );
        }
    }

    #[test]
    fn the_blacklist_age_rule_is_the_native_g1_rule() {
        let controls = |version, issued, max_age| Controls {
            enabled: CONTROL_BLACKLIST,
            quota_windows_root: Fp::ZERO,
            blacklist_version: version,
            blacklist_root: Fp::ONE,
            blacklist_issued_at_ms: issued,
            blacklist_max_age_ms: max_age,
            lease_expires_at_ms: 0,
        };
        // Age exactly the maximum, issued at the upper time: accepted.
        assert!(!blacklist_too_old(&controls(1, 100, 50), 150));
        assert!(!blacklist_too_old(&controls(1, 150, 50), 150));
        // One millisecond older, or issued after the upper time: rejected.
        assert!(blacklist_too_old(&controls(1, 100, 50), 151));
        assert!(blacklist_too_old(&controls(1, 151, 50), 150));
        // No list held, or no age rule: not enforced.
        assert!(!blacklist_too_old(&controls(0, 0, 50), u64::MAX));
        assert!(!blacklist_too_old(&controls(1, u64::MAX, 0), 0));
        // The extremes of u64.
        assert!(!blacklist_too_old(&controls(1, 0, u64::MAX), u64::MAX));
        assert!(blacklist_too_old(&controls(1, 0, u64::MAX - 1), u64::MAX));
    }
}
