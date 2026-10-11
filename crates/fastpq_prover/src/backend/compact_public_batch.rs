//! Bounded whole-batch context and ordered one-delta segment relations.
//!
//! Every segment binds the complete original public claims and execution rows,
//! caller-expected seven-field `PublicIO`, exact ordered intermediate roots, count
//! and ordinal before the compact engine's first challenge. Its SMT ports come
//! only from the original immutable preparation, preserving whole-batch scales,
//! allocation and chronological occurrences. Intermediate roots remain public
//! claims: acceptance requires every ordered segment proof and authenticated
//! overall endpoints. This module performs no proof verification or authority
//! grant, and constructing a batch never reconstructs a private witness or LDE.
//!
//! TODO: Integrate and qualify the complete canonical outer bundle, cumulative
//! proof/decoder budgets, authenticated caller and aggregate soundness argument.
//! The offline engine fixes375 queries; production replay and default limits
//! remain unmodified pending a complete qualified artifact cutover.

#[cfg(test)]
use norito::{NoritoSerialize, codec::Encode};

#[cfg(test)]
use super::compact_protocol::PreparedAir;
use super::compact_value_domain::CompactTransferValue;
#[cfg(test)]
use super::{
    compact_protocol::{FixedAir, FixedAirSchema},
    compact_public_transfer::encode_context,
    compact_transfer_air::CompactTransferAir,
};
use crate::{
    Error, Result, VerifyLimits,
    gadgets::{
        compact_smt_air::PublicStatement,
        public_transfer_statement::{PreparedPublicTransfers, PublicTransferLimits},
    },
};
#[cfg(test)]
use crate::{ProofSemantics, proof::PublicIO};

#[cfg(test)]
const IDENTITY: &str = <u64 as CompactTransferValue>::BATCH_IDENTITY;

/// Explicit context-only ceilings, independent of proof and decoder budgets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BatchContextLimits {
    /// Maximum nonempty chronological segments, also capped by fixed defaults.
    pub(super) max_segments: usize,
    /// Sum of complete canonical segment statement lengths bound into transcripts.
    pub(super) max_total_statement_bytes: usize,
}

impl Default for BatchContextLimits {
    fn default() -> Self {
        let limits = VerifyLimits::default();
        Self {
            max_segments: limits.max_transitions / 2,
            max_total_statement_bytes: limits.max_batch_bytes,
        }
    }
}

#[cfg(test)]
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_public_batch::BoundBatchContext",
    frame = "fastpq_prover::compact_v1::OrdinaryTransferBatchContextV1"
)]
struct BoundBatchContext {
    version: u16,
    segment_count: u32,
    public_transfer_context: Vec<u8>,
    intermediate_roots: Vec<[u8; 32]>,
}

#[cfg(test)]
#[derive(NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_public_batch::BoundSegmentContext",
    frame = "fastpq_prover::compact_v1::OrdinaryTransferSegmentContextV1"
)]
struct BoundSegmentContext {
    version: u16,
    segment_count: u32,
    ordinal: u32,
    batch_context: Vec<u8>,
}

/// Test-only transfer diagnostic context with checked chronological segments.
/// The ordinary artifact facade uses the complete execution-effect batch.
///
/// This object is a statement, not a successful proof. It owns no private path,
/// witness, FFT/LDE or prepared fixed AIR cache. A verifier can use the exact
/// aggregate statement length before decoding or hashing any child proof.
#[cfg(test)]
pub(super) struct PublicTransferBatch {
    identity: &'static str,
    #[cfg(test)]
    public_io: PublicIO,
    context: Vec<u8>,
    statements: Vec<PublicStatement>,
    total_statement_bytes: usize,
    max_statement_bytes: usize,
}

#[cfg(test)]
impl PublicTransferBatch {
    /// Derive a nonempty ordinary bundle from the complete immutable preparation.
    ///
    /// Fixed public limits cannot be raised with this diagnostic policy. The
    /// intermediate list contains exactly m-1 claimed roots in chronological
    /// order; endpoints always come from the independently expected `PublicIO`.
    /// All counts/known bytes are bounded before cloning, serialization or AIR
    /// construction. Exact canonical payload counts precede encoded allocation.
    pub(super) fn new<V: CompactTransferValue>(
        prepared: &PreparedPublicTransfers<'_, V>,
        expected: &PublicIO,
        intermediate_roots: &[[u8; 32]],
        limits: BatchContextLimits,
    ) -> Result<Self> {
        let count = prepared.pairs().len();
        let root_bytes = preflight_prepared(prepared, intermediate_roots.len(), limits)?;
        if prepared.semantics() != ProofSemantics::StateTransition {
            return Err(Error::InvalidProofSemantics {
                profile: prepared.semantics().name(),
                details: "ordinary compact bundle requires transfer-state-transition semantics"
                    .to_owned(),
            });
        }
        // compact_statements validates every marker and links exact endpoints;
        // it takes ports from prepared.pairs(), never a re-prepared delta slice.
        let statements = prepared.compact_statements(intermediate_roots)?;
        let context = encode_context(prepared, expected)?;
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        check_statement_bytes(checked_sum(context.len(), root_bytes)?)?;
        let bound = BoundBatchContext {
            version: 1,
            segment_count: checked_u32(count)?,
            public_transfer_context: context,
            intermediate_roots: intermediate_roots.to_vec(),
        };
        let bytes = norito::core::encoded_payload_len(&bound)?;
        check_statement_bytes(bytes)?;
        check_total(checked_product(count, bytes)?, limits)?;
        let context = bound.encode();
        let mut batch = Self {
            identity: V::BATCH_IDENTITY,
            #[cfg(test)]
            public_io: *expected,
            context,
            statements,
            total_statement_bytes: 0,
            max_statement_bytes: 0,
        };
        // Count each actual full statement, including both canonical envelopes
        // and derived public ports. No assumption about codec scalar lengths or
        // segment uniformity is needed; no CompactTransferAir is built here.
        for ordinal in 0..count {
            let context = batch.segment_context(ordinal)?;
            let bytes = CompactTransferAir::encoded_statement_len(
                &batch.statements[ordinal],
                Some(&context),
            )?;
            batch.total_statement_bytes = checked_sum(batch.total_statement_bytes, bytes)?;
            batch.max_statement_bytes = batch.max_statement_bytes.max(bytes);
            check_total(batch.total_statement_bytes, limits)?;
        }
        Ok(batch)
    }

    /// Exact positive number of chronological segment statements.
    #[cfg(test)]
    pub(super) fn segment_count(&self) -> usize {
        self.statements.len()
    }

    /// Exact caller inputs checked before the context was constructed.
    #[cfg(test)]
    pub(super) const fn public_io(&self) -> PublicIO {
        self.public_io
    }

    /// Complete canonical common context, including all roots and public facts.
    #[cfg(test)]
    pub(super) fn context_bytes(&self) -> &[u8] {
        &self.context
    }

    /// Exact ports derived from the complete preparation in chronological order.
    pub(super) fn statements(&self) -> &[PublicStatement] {
        &self.statements
    }

    /// Exact sum of canonical full statements processed by all segment transcripts.
    pub(super) const fn total_statement_bytes(&self) -> usize {
        self.total_statement_bytes
    }

    /// Largest exact canonical segment statement, for a stricter child byte ceiling.
    pub(super) const fn max_statement_bytes(&self) -> usize {
        self.max_statement_bytes
    }

    /// Construct only the requested segment's fixed bounded-opening relation.
    ///
    /// The ordinal cannot be selected from a child proof. The outer verifier
    /// must call every ordinal once in order and reject any incomplete bundle.
    pub(super) fn segment(&self, ordinal: usize) -> Result<PublicTransferSegmentAir> {
        let statement = self.statement(ordinal)?;
        let context = self.segment_context(ordinal)?;
        Ok(PublicTransferSegmentAir {
            identity: self.identity,
            inner: CompactTransferAir::new(statement, Some(&context))?,
        })
    }

    fn statement(&self, ordinal: usize) -> Result<&PublicStatement> {
        self.statements
            .get(ordinal)
            .ok_or(Error::QueryIndexOutOfRange {
                index: ordinal,
                len: self.statements.len(),
            })
    }

    fn segment_context(&self, ordinal: usize) -> Result<Vec<u8>> {
        self.statement(ordinal)?;
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let bound = BoundSegmentContext {
            version: 1,
            segment_count: checked_u32(self.statements.len())?,
            ordinal: checked_u32(ordinal)?,
            batch_context: self.context.clone(),
        };
        check_statement_bytes(norito::core::encoded_payload_len(&bound)?)?;
        Ok(bound.encode())
    }
}

/// Fixed ordinary bundle relation; callers cannot replace its semantic profile.
#[cfg(test)]
pub(super) struct PublicTransferSegmentAir {
    identity: &'static str,
    inner: CompactTransferAir,
}

#[cfg(test)]
impl super::deep_relation::sealed::Sealed for PublicTransferSegmentAir {}

#[cfg(test)]
impl super::deep_relation::DeepRelation for PublicTransferSegmentAir {
    // Borrow the already constructed AIR without replacing the outer identity
    // or any byte of its complete prepared batch/ordinal/public context.
    fn deep_relation(&self) -> &CompactTransferAir {
        &self.inner
    }
}

#[cfg(test)]
impl FixedAir for PublicTransferSegmentAir {
    fn schema(&self) -> FixedAirSchema {
        FixedAirSchema {
            identity: self.identity,
            ..self.inner.schema()
        }
    }
    fn statement_bytes(&self) -> &[u8] {
        self.inner.statement_bytes()
    }
    #[cfg(test)]
    fn evaluate(&self, point: u64, current: &[u64], next: &[u64]) -> Result<Vec<u64>> {
        self.inner.evaluate(point, current, next)
    }
    #[cfg(test)]
    fn prepare_prover(&self) -> Result<Box<dyn PreparedAir + '_>> {
        self.inner.prepare_prover()
    }
}

/// Apply fixed public/count ceilings before either typed batch constructor clones.
///
/// This helper performs only resource checks; it selects no semantic profile and
/// cannot construct an AIR, trusted context or successful verification result.
pub(super) fn preflight_prepared<V: CompactTransferValue>(
    prepared: &PreparedPublicTransfers<'_, V>,
    root_count: usize,
    limits: BatchContextLimits,
) -> Result<usize> {
    let root_bytes = preflight_counts(
        prepared.pairs().len(),
        prepared.transitions().len(),
        root_count,
        limits,
    )?;
    let fixed = PublicTransferLimits::default();
    for (name, actual, maximum) in [
        (
            "max_public_transfer_transcripts",
            prepared.claims().len(),
            fixed.max_transcripts,
        ),
        (
            "max_public_transfer_bytes",
            prepared.work().public_bytes,
            fixed.max_public_bytes,
        ),
        (
            "max_public_transfer_keys",
            prepared.keys().len(),
            fixed.max_unique_keys,
        ),
        (
            "max_public_transfer_allocation_steps",
            prepared.work().allocation_steps,
            fixed.max_allocation_steps,
        ),
    ] {
        check_limit(name, actual, maximum)?;
    }
    Ok(root_bytes)
}

fn preflight_counts(
    segments: usize,
    rows: usize,
    roots: usize,
    limits: BatchContextLimits,
) -> Result<usize> {
    if segments == 0 {
        return Err(invariant(
            "compact public bundle requires at least one complete delta",
        ));
    }
    let fixed = PublicTransferLimits::default();
    check_limit(
        "max_compact_bundle_segments",
        segments,
        limits.max_segments.min(fixed.max_deltas),
    )?;
    check_limit("max_public_transfer_rows", rows, fixed.max_rows)?;
    if checked_product(segments, 2)? != rows {
        return Err(invariant("compact public bundle pair/row count mismatch"));
    }
    if roots != segments - 1 {
        return Err(invariant(
            "compact public bundle intermediate-root count mismatch",
        ));
    }
    let bytes = checked_product(roots, core::mem::size_of::<[u8; 32]>())?;
    check_statement_bytes(bytes)?;
    check_statement_bytes(checked_product(
        segments,
        core::mem::size_of::<PublicStatement>(),
    )?)?;
    Ok(bytes)
}

#[cfg(test)]
fn checked_u32(value: usize) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| invariant("compact public bundle count is not representable as u32"))
}

#[cfg(test)]
fn checked_sum(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| invariant("compact public bundle byte count overflows"))
}

fn checked_product(left: usize, right: usize) -> Result<usize> {
    left.checked_mul(right)
        .ok_or_else(|| invariant("compact public bundle byte count overflows"))
}

#[cfg(test)]
fn check_total(actual: usize, limits: BatchContextLimits) -> Result<()> {
    check_limit(
        "max_compact_bundle_statement_bytes",
        actual,
        limits.max_total_statement_bytes,
    )
}

fn check_statement_bytes(actual: usize) -> Result<()> {
    check_limit(
        "max_compact_statement_bytes",
        actual,
        VerifyLimits::default().max_batch_bytes,
    )
}

fn check_limit(limit: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        Err(Error::VerifierLimitExceeded { limit, actual, max })
    } else {
        Ok(())
    }
}

fn invariant(details: &str) -> Error {
    Error::TransferInvariant {
        details: details.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OperationKind, PublicInputs, StateTransition,
        backend::compact_public_transfer::PublicTransferAir,
        gadgets::{
            compact_smt_air::COLUMN_COUNT,
            public_transfer_statement::{
                PublicTransferDelta, PublicTransferTranscript, prepare_public_transfers,
            },
        },
    };
    use iroha_crypto::Hash;
    use iroha_data_model::asset::id::AssetDefinitionId;
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::{Numeric, Quantity};
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use iroha_zkp_halo2::poseidon::PoseidonByteHasher;

    struct PublicFixture {
        rows: Vec<StateTransition>,
        claims: Vec<PublicTransferTranscript>,
        inputs: PublicInputs,
    }

    impl PublicFixture {
        fn new(deltas: usize, self_transfer: bool) -> Self {
            Self::with_amount(deltas, self_transfer, 5)
        }

        fn with_amount(deltas: usize, self_transfer: bool, amount: u64) -> Self {
            // These are public statement facts only. No private path or full
            // trace is generated, and placeholder roots are never called proven.
            let _flags =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let asset = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
            let mut rows = Vec::new();
            let mut public_deltas = Vec::new();
            for index in 0..deltas {
                let from_before = if self_transfer {
                    100
                } else {
                    100 - amount * index as u64
                };
                let from_after = from_before - amount;
                let to_before = if self_transfer {
                    from_after
                } else {
                    200 + amount * index as u64
                };
                let to_after = to_before + amount;
                let delta = PublicTransferDelta {
                    from_account: (*ALICE_ID).clone(),
                    to_account: if self_transfer {
                        (*ALICE_ID).clone()
                    } else {
                        (*BOB_ID).clone()
                    },
                    asset_definition: asset.clone(),
                    amount: Quantity::from(amount),
                    from_balance_before: Quantity::from(from_before),
                    from_balance_after: Quantity::from(from_after),
                    to_balance_before: Quantity::from(to_before),
                    to_balance_after: Quantity::from(to_after),
                };
                for (account, before, after) in [
                    (&delta.from_account, from_before, from_after),
                    (&delta.to_account, to_before, to_after),
                ] {
                    rows.push(StateTransition::new(
                        iroha_data_model::fastpq::transfer_balance_key(&asset, account).unwrap(),
                        before.to_le_bytes().to_vec(),
                        after.to_le_bytes().to_vec(),
                        OperationKind::Transfer,
                    ));
                }
                public_deltas.push(delta);
            }
            rows.sort_by(|left, right| left.key.cmp(&right.key));
            let batch_hash = Hash::new(b"compact public batch context fixture");
            let poseidon_preimage_digest = if let [delta] = public_deltas.as_slice() {
                Some(single_delta_digest(delta, &batch_hash))
            } else {
                None
            };
            let claims = if public_deltas.is_empty() {
                Vec::new()
            } else {
                vec![PublicTransferTranscript {
                    batch_hash,
                    authority_digest: Hash::new(b"public claimed authority only"),
                    deltas: public_deltas,
                    poseidon_preimage_digest,
                }]
            };
            let old_root = Hash::new(b"public claimed old touched root").into();
            Self {
                rows,
                claims,
                inputs: PublicInputs {
                    dsid: [9; 16],
                    slot: 17,
                    old_root,
                    new_root: if deltas == 0 || amount == 0 || self_transfer {
                        old_root
                    } else {
                        Hash::new(b"public claimed new touched root").into()
                    },
                    perm_root: Hash::new(b"public permission context").into(),
                    tx_set_hash: Hash::new(b"public transaction context").into(),
                },
            }
        }

        fn prepare(&self) -> PreparedPublicTransfers<'_> {
            prepare_public_transfers(
                &self.rows,
                &self.claims,
                self.inputs,
                ProofSemantics::StateTransition,
                PublicTransferLimits::default(),
            )
            .unwrap()
        }
    }

    fn single_delta_digest(delta: &PublicTransferDelta, batch_hash: &Hash) -> Hash {
        let mut hasher = PoseidonByteHasher::new();
        delta.from_account.encode_to(&mut hasher);
        delta.to_account.encode_to(&mut hasher);
        delta.asset_definition.encode_to(&mut hasher);
        delta.amount.encode_to(&mut hasher);
        hasher.update(batch_hash.as_ref());
        Hash::prehashed(hasher.finalize())
    }

    fn expected(prepared: &PreparedPublicTransfers<'_>) -> PublicIO {
        let inputs = prepared.public_inputs();
        PublicIO {
            dsid: inputs.dsid,
            slot: inputs.slot,
            old_root: inputs.old_root,
            new_root: inputs.new_root,
            perm_root: inputs.perm_root,
            tx_set_hash: inputs.tx_set_hash,
            ordering_hash: prepared.ordering_hash().into(),
        }
    }

    fn roots(count: usize) -> Vec<[u8; 32]> {
        (0..count.saturating_sub(1))
            .map(|index| Hash::new(index.to_le_bytes()).into())
            .collect()
    }

    fn batch(prepared: &PreparedPublicTransfers<'_>) -> PublicTransferBatch {
        PublicTransferBatch::new(
            prepared,
            &expected(prepared),
            &roots(prepared.pairs().len()),
            BatchContextLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn complete_public_table_derives_ordered_ports_and_exact_segment_work() {
        for count in [1, 2, 3] {
            for (self_transfer, amount) in [(false, 5), (false, 0), (true, 5), (true, 0)] {
                let fixture = PublicFixture::with_amount(count, self_transfer, amount);
                let prepared = fixture.prepare();
                let batch = batch(&prepared);
                assert_eq!(batch.segment_count(), count);
                assert_eq!(batch.public_io(), expected(&prepared));
                assert_eq!(
                    batch.statements(),
                    prepared.compact_statements(&roots(count)).unwrap()
                );
                assert!(!batch.context_bytes().is_empty());
                let mut total = 0;
                let mut maximum = 0;
                for ordinal in 0..count {
                    assert_eq!(
                        batch.statements()[ordinal].updates,
                        prepared.pairs()[ordinal].updates
                    );
                    let air = batch.segment(ordinal).unwrap();
                    assert_eq!(air.schema().identity, IDENTITY);
                    assert_eq!(air.schema().trace_rows, 65_536);
                    assert_eq!(air.schema().width, 342);
                    assert_eq!(air.schema().constraints, 923);
                    total += air.statement_bytes().len();
                    maximum = maximum.max(air.statement_bytes().len());
                    if ordinal > 0 {
                        assert_eq!(
                            batch.statements()[ordinal - 1].new_root,
                            batch.statements()[ordinal].old_root
                        );
                    }
                }
                assert_eq!(total, batch.total_statement_bytes());
                assert_eq!(maximum, batch.max_statement_bytes());
                for ordinal in [count, usize::MAX] {
                    assert!(
                        matches!(batch.segment(ordinal), Err(Error::QueryIndexOutOfRange { index, len }) if index == ordinal && len == count)
                    );
                }
            }
        }
    }

    #[test]
    fn segment_wrapper_preserves_equations_and_has_a_distinct_one_delta_identity() {
        let fixture = PublicFixture::new(1, false);
        let prepared = fixture.prepare();
        let batch = batch(&prepared);
        let segment = batch.segment(0).unwrap();
        let existing = PublicTransferAir::new(&prepared, &expected(&prepared)).unwrap();
        let raw = CompactTransferAir::new(&batch.statements()[0], None).unwrap();
        assert_ne!(segment.schema().identity, existing.schema().identity);
        assert_ne!(segment.schema().identity, raw.schema().identity);
        assert_ne!(segment.statement_bytes(), existing.statement_bytes());
        let current = core::array::from_fn::<_, COLUMN_COUNT, _>(|index| index as u64 + 9);
        let next = core::array::from_fn::<_, COLUMN_COUNT, _>(|index| index as u64 + 77);
        assert_eq!(
            segment.evaluate(7, &current, &next).unwrap(),
            raw.evaluate(7, &current, &next).unwrap()
        );
        // A wrapper cannot hide malformed row geometry from the inner AIR.
        assert!(
            segment
                .evaluate(7, &current[..COLUMN_COUNT - 1], &next)
                .is_err()
        );
    }

    #[test]
    fn count_ordinal_roots_and_full_claims_change_every_segment_statement() {
        // Zero updates make adjacent public ports and roots identical. Thus
        // ordinal binding is observable independently of different SMT ports.
        let fixture = PublicFixture::with_amount(3, false, 0);
        let prepared = fixture.prepare();
        let root_chain = vec![fixture.inputs.old_root; 2];
        let original = PublicTransferBatch::new(
            &prepared,
            &expected(&prepared),
            &root_chain,
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_eq!(original.statements()[0], original.statements()[1]);
        assert_ne!(
            original.segment(0).unwrap().statement_bytes(),
            original.segment(1).unwrap().statement_bytes()
        );
        for byte in 0..32 {
            let mut changed_roots = root_chain.clone();
            changed_roots[1][byte] ^= if byte == 31 { 0x80 } else { 1 };
            let changed = PublicTransferBatch::new(
                &prepared,
                &expected(&prepared),
                &changed_roots,
                BatchContextLimits::default(),
            )
            .unwrap();
            // Segment zero's ports are unchanged, but all intermediate roots
            // belong to its common statement before the first challenge.
            assert_eq!(changed.statements()[0], original.statements()[0]);
            assert_ne!(
                changed.segment_context(0).unwrap(),
                original.segment_context(0).unwrap()
            );
        }
        let mut changed_fixture = PublicFixture::with_amount(3, false, 0);
        changed_fixture.claims[0].authority_digest = Hash::new(b"different authority claim");
        let changed_prepared = changed_fixture.prepare();
        let changed = PublicTransferBatch::new(
            &changed_prepared,
            &expected(&changed_prepared),
            &root_chain,
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_eq!(changed.statements(), original.statements());
        for ordinal in 0..3 {
            assert_ne!(
                changed.segment_context(ordinal).unwrap(),
                original.segment_context(ordinal).unwrap()
            );
        }
        let smaller_fixture = PublicFixture::with_amount(2, false, 0);
        let smaller_prepared = smaller_fixture.prepare();
        let smaller = PublicTransferBatch::new(
            &smaller_prepared,
            &expected(&smaller_prepared),
            &root_chain[..1],
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_eq!(smaller.statements()[0], original.statements()[0]);
        assert_ne!(
            smaller.segment_context(0).unwrap(),
            original.segment_context(0).unwrap()
        );
        // A permutation of valid root claims remains syntactically constructible
        // but produces a different statement. Only proofs can establish it.
        let ordered = roots(3);
        let reversed = [ordered[1], ordered[0]];
        let ordered = PublicTransferBatch::new(
            &prepared,
            &expected(&prepared),
            &ordered,
            BatchContextLimits::default(),
        )
        .unwrap();
        let reversed = PublicTransferBatch::new(
            &prepared,
            &expected(&prepared),
            &reversed,
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_ne!(ordered.context_bytes(), reversed.context_bytes());
    }

    #[test]
    fn exact_expected_inputs_root_markers_and_ordinary_route_are_required() {
        let fixture = PublicFixture::new(2, false);
        let prepared = fixture.prepare();
        let original = expected(&prepared);
        for field in 0..7 {
            let mut changed = original;
            match field {
                0 => changed.dsid[15] ^= 1,
                1 => changed.slot ^= 1,
                2 => changed.old_root[0] ^= 1,
                3 => changed.new_root[0] ^= 1,
                4 => changed.perm_root[31] ^= 0x80,
                5 => changed.tx_set_hash[31] ^= 0x80,
                6 => changed.ordering_hash[31] ^= 0x80,
                _ => unreachable!(),
            }
            assert!(matches!(
                PublicTransferBatch::new(
                    &prepared,
                    &changed,
                    &roots(2),
                    BatchContextLimits::default()
                ),
                Err(Error::PublicIoMismatch {
                    field: "compact_public_io"
                })
            ));
        }
        for roots in [&[][..], &[[0; 32]][..], &[[0; 32]; 2][..]] {
            assert!(
                PublicTransferBatch::new(
                    &prepared,
                    &original,
                    roots,
                    BatchContextLimits::default()
                )
                .is_err()
            );
        }
        let axt = prepare_public_transfers(
            &fixture.rows,
            &fixture.claims,
            fixture.inputs,
            ProofSemantics::AxtTransferClaim,
            PublicTransferLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            PublicTransferBatch::new(
                &axt,
                &expected(&axt),
                &roots(2),
                BatchContextLimits::default()
            ),
            Err(Error::InvalidProofSemantics { .. })
        ));
    }

    #[test]
    fn exact_cumulative_and_default_limits_apply_before_air_construction() {
        let fixture = PublicFixture::new(3, false);
        let prepared = fixture.prepare();
        let original = batch(&prepared);
        let exact = BatchContextLimits {
            max_segments: 3,
            max_total_statement_bytes: original.total_statement_bytes(),
        };
        assert_eq!(
            PublicTransferBatch::new(&prepared, &expected(&prepared), &roots(3), exact)
                .unwrap()
                .total_statement_bytes(),
            exact.max_total_statement_bytes
        );
        assert!(matches!(
            PublicTransferBatch::new(
                &prepared,
                &expected(&prepared),
                &roots(3),
                BatchContextLimits {
                    max_total_statement_bytes: exact.max_total_statement_bytes - 1,
                    ..exact
                }
            ),
            Err(Error::VerifierLimitExceeded {
                limit: "max_compact_bundle_statement_bytes",
                ..
            })
        ));
        assert!(matches!(
            PublicTransferBatch::new(
                &prepared,
                &expected(&prepared),
                &roots(3),
                BatchContextLimits {
                    max_segments: 2,
                    ..exact
                }
            ),
            Err(Error::VerifierLimitExceeded {
                limit: "max_compact_bundle_segments",
                ..
            })
        ));
        let empty = PublicFixture::new(0, false);
        let empty = empty.prepare();
        assert!(
            PublicTransferBatch::new(
                &empty,
                &expected(&empty),
                &[],
                BatchContextLimits::default()
            )
            .is_err()
        );
        assert!(preflight_counts(1, 1, 0, exact).is_err());
        assert!(preflight_counts(1, 2, 1, exact).is_err());
        assert!(
            preflight_counts(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                BatchContextLimits {
                    max_segments: usize::MAX,
                    max_total_statement_bytes: usize::MAX
                }
            )
            .is_err()
        );
        assert!(checked_sum(usize::MAX, 1).is_err());
        assert!(checked_product(usize::MAX, 2).is_err());
        assert_eq!(checked_sum(0, 7).unwrap(), 7);
        assert_eq!(checked_product(7, 0).unwrap(), 0);
        assert_eq!(checked_u32(u32::MAX as usize).unwrap(), u32::MAX);
        if usize::BITS > 32 {
            assert!(checked_u32((u32::MAX as usize) + 1).is_err());
        }
        assert!(check_statement_bytes(VerifyLimits::default().max_batch_bytes).is_ok());
        assert!(check_statement_bytes(VerifyLimits::default().max_batch_bytes + 1).is_err());
        assert!(check_limit("test", 1, 1).is_ok());
        assert!(check_limit("test", 2, 1).is_err());
    }

    #[test]
    fn larger_preparation_policies_cannot_raise_fixed_batch_or_legacy_limits() {
        let fixed = PublicTransferLimits::default();
        let count = fixed.max_deltas + 1;
        let mut fixture = PublicFixture::with_amount(count, false, 0);
        let claim = fixture.claims.pop().unwrap();
        fixture.claims = claim
            .deltas
            .into_iter()
            .map(|delta| PublicTransferTranscript {
                batch_hash: claim.batch_hash,
                authority_digest: claim.authority_digest,
                poseidon_preimage_digest: Some(single_delta_digest(&delta, &claim.batch_hash)),
                deltas: vec![delta],
            })
            .collect();
        let prepared = prepare_public_transfers(
            &fixture.rows,
            &fixture.claims,
            fixture.inputs,
            ProofSemantics::StateTransition,
            PublicTransferLimits {
                max_transcripts: count,
                max_deltas: count,
                max_rows: count * 2,
                ..fixed
            },
        )
        .unwrap();
        assert!(matches!(
            PublicTransferBatch::new(
                &prepared,
                &expected(&prepared),
                &roots(count),
                BatchContextLimits {
                    max_segments: usize::MAX,
                    max_total_statement_bytes: usize::MAX
                }
            ),
            Err(Error::VerifierLimitExceeded {
                limit: "max_compact_bundle_segments",
                ..
            })
        ));
        assert!(matches!(
            encode_context(&prepared, &expected(&prepared)),
            Err(Error::VerifierLimitExceeded {
                limit: "max_public_transfer_transcripts",
                ..
            })
        ));
        assert!(
            matches!(PublicTransferAir::new(&prepared, &expected(&prepared)), Err(Error::TransferInvariant { details }) if details == "compact public transfer requires exactly one complete delta")
        );

        // One multi-delta claim reaches the independent recorded-byte guard
        // without first exceeding the transcript count. No private work occurs.
        let fixture = PublicFixture::with_amount(3000, false, 0);
        let prepared = prepare_public_transfers(
            &fixture.rows,
            &fixture.claims,
            fixture.inputs,
            ProofSemantics::StateTransition,
            PublicTransferLimits {
                max_deltas: 3000,
                max_rows: 6000,
                max_public_bytes: 8 * 1024 * 1024,
                ..fixed
            },
        )
        .unwrap();
        assert!(prepared.work().public_bytes > fixed.max_public_bytes);
        assert!(matches!(
            encode_context(&prepared, &expected(&prepared)),
            Err(Error::VerifierLimitExceeded {
                limit: "max_public_transfer_bytes",
                ..
            })
        ));
    }

    #[test]
    fn context_and_segment_encoding_ignore_and_restore_ambient_flags() {
        let fixture = PublicFixture::new(2, false);
        let prepared = fixture.prepare();
        let original = batch(&prepared);
        let original_segment = original.segment(1).unwrap();
        for flags in
            (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            let actual = batch(&prepared);
            assert_eq!(actual.context_bytes(), original.context_bytes());
            assert_eq!(
                actual.total_statement_bytes(),
                original.total_statement_bytes()
            );
            assert_eq!(
                actual.segment(1).unwrap().statement_bytes(),
                original_segment.statement_bytes()
            );
            assert_eq!(norito::core::get_decode_flags(), flags);
        }
    }
    #[test]
    fn whole_batch_scale_and_order_are_preserved_across_transcript_boundaries() {
        let mut fixture = PublicFixture::new(2, false);
        let deltas = &mut fixture.claims[0].deltas;
        deltas[0].amount = Quantity::from(1_u64);
        deltas[0].from_balance_after = Quantity::from(99_u64);
        deltas[0].to_balance_after = Quantity::from(201_u64);
        deltas[1].amount = Quantity::try_from_numeric(Numeric::new(25, 2)).unwrap();
        deltas[1].from_balance_before = Quantity::from(99_u64);
        deltas[1].from_balance_after = Quantity::try_from_numeric(Numeric::new(9875, 2)).unwrap();
        deltas[1].to_balance_before = Quantity::from(201_u64);
        deltas[1].to_balance_after = Quantity::try_from_numeric(Numeric::new(20125, 2)).unwrap();
        let deltas = fixture.claims.pop().unwrap().deltas;
        fixture.rows.clear();
        for (ordinal, (delta, values)) in deltas
            .into_iter()
            .zip([
                [10_000_u64, 9_900, 20_000, 20_100],
                [9_900, 9_875, 20_100, 20_125],
            ])
            .enumerate()
        {
            for (account, before, after) in [
                (&delta.from_account, values[0], values[1]),
                (&delta.to_account, values[2], values[3]),
            ] {
                fixture.rows.push(StateTransition::new(
                    iroha_data_model::fastpq::transfer_balance_key(
                        &delta.asset_definition,
                        account,
                    )
                    .unwrap(),
                    before.to_le_bytes().to_vec(),
                    after.to_le_bytes().to_vec(),
                    OperationKind::Transfer,
                ));
            }
            let batch_hash = Hash::new([u8::try_from(ordinal).expect("fixture ordinal fits u8")]);
            let poseidon_preimage_digest = Some(single_delta_digest(&delta, &batch_hash));
            fixture.claims.push(PublicTransferTranscript {
                batch_hash,
                authority_digest: Hash::new(b"public claimed authority only"),
                deltas: vec![delta],
                poseidon_preimage_digest,
            });
        }
        fixture.rows.sort_by(|left, right| left.key.cmp(&right.key));
        let prepared = fixture.prepare();
        let batch = batch(&prepared);
        assert_eq!(prepared.claims().len(), 2);
        assert!(prepared.rows().iter().all(|row| row.asset_scale == 2));
        for (ordinal, pair) in prepared.pairs().iter().enumerate() {
            assert_eq!(pair.occurrence.transcript_ordinal as usize, ordinal);
            assert_eq!(pair.occurrence.delta_ordinal, 0);
            assert_eq!(pair.occurrence.pair_ordinal as usize, ordinal);
            assert_eq!(batch.statements()[ordinal].updates, pair.updates);
        }
        let first_pair = &prepared.pairs()[0];
        // The same first public claim prepared alone would use scale zero.
        // This control makes independently re-preparing each delta observable.
        let mut first_rows: Vec<_> = first_pair
            .row_indices
            .iter()
            .map(|index| {
                let mut row = fixture.rows[*index].clone();
                for bytes in [&mut row.pre_value, &mut row.post_value] {
                    let value = u64::from_le_bytes(bytes.as_slice().try_into().unwrap()) / 100;
                    *bytes = value.to_le_bytes().to_vec();
                }
                row
            })
            .collect();
        first_rows.sort_by(|left, right| left.key.cmp(&right.key));
        let isolated = prepare_public_transfers(
            &first_rows,
            &fixture.claims[..1],
            fixture.inputs,
            ProofSemantics::StateTransition,
            PublicTransferLimits::default(),
        )
        .unwrap();
        assert!(isolated.rows().iter().all(|row| row.asset_scale == 0));
        assert_ne!(batch.statements()[0].updates, isolated.pairs()[0].updates);
        assert_eq!(batch.statements().len(), 2);
    }

    /// A changed claim authority keeps every statement but rebinds every segment root.
    fn assert_quantity_claim_change_rebinds(
        rows: &[StateTransition],
        claims: &[PublicTransferTranscript],
        inputs: PublicInputs,
        root_chain: &[[u8; 32]],
        original: &PublicTransferBatch,
        roots: &[fastpq_isi::keccak256::Sha3Digest256V1],
    ) {
        use crate::backend::deep_relation::tests as deep;
        use crate::gadgets::public_transfer_statement::prepare_quantity_public_transfers;

        let mut changed_claims = claims.to_vec();
        changed_claims[0].authority_digest = Hash::new(b"other complete quantity authority claim");
        let changed_prepared = prepare_quantity_public_transfers(
            rows,
            &changed_claims,
            inputs,
            ProofSemantics::StateTransition,
            PublicTransferLimits::default(),
        )
        .unwrap();
        let changed = PublicTransferBatch::new(
            &changed_prepared,
            &deep::expected(&changed_prepared),
            root_chain,
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_eq!(original.statements(), changed.statements());
        for (ordinal, root) in roots.iter().enumerate() {
            assert_ne!(*root, deep::bound_root(&changed.segment(ordinal).unwrap()));
        }
    }

    /// A shorter bundle shares the first statement but binds its own count.
    fn assert_shorter_quantity_bundle_rebinds(
        root_chain: &[[u8; 32]],
        original: &PublicTransferBatch,
        roots: &[fastpq_isi::keccak256::Sha3Digest256V1],
    ) {
        use crate::backend::deep_relation::tests as deep;
        use crate::gadgets::public_transfer_statement::prepare_quantity_public_transfers;

        let smaller = PublicFixture::with_amount(2, false, 0);
        let (small_rows, small_claims, small_inputs) = deep::quantity_copy(&smaller.prepare());
        let small = prepare_quantity_public_transfers(
            &small_rows,
            &small_claims,
            small_inputs,
            ProofSemantics::StateTransition,
            PublicTransferLimits::default(),
        )
        .unwrap();
        let small = PublicTransferBatch::new(
            &small,
            &deep::expected(&small),
            &root_chain[..1],
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_eq!(original.statements()[0], small.statements()[0]);
        assert_ne!(roots[0], deep::bound_root(&small.segment(0).unwrap()));
    }

    #[test]
    fn deep_quantity_bridge_keeps_complete_count_ordinal_roots_claims_and_expected_inputs() {
        use crate::backend::deep_relation::{DeepRelation, tests as deep};
        use crate::gadgets::public_transfer_statement::prepare_quantity_public_transfers;
        use iroha_data_model::fastpq::FastpqQuantityUnits;

        // Zero updates isolate count and ordinal binding from the SMT ports.
        let fixture = PublicFixture::with_amount(3, false, 0);
        let narrow = fixture.prepare();
        let (rows, claims, inputs) = deep::quantity_copy(&narrow);
        let prepared = prepare_quantity_public_transfers(
            &rows,
            &claims,
            inputs,
            ProofSemantics::StateTransition,
            PublicTransferLimits::default(),
        )
        .unwrap();
        let expected = deep::expected(&prepared);
        let root_chain = [inputs.old_root; 2];
        let original = PublicTransferBatch::new(
            &prepared,
            &expected,
            &root_chain,
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_eq!(original.statements()[0], original.statements()[1]);
        let roots = (0..3)
            .map(|ordinal| {
                let segment = original.segment(ordinal).unwrap();
                assert_eq!(
                    segment.schema().identity,
                    FastpqQuantityUnits::BATCH_IDENTITY
                );
                assert_eq!(
                    segment.statement_bytes(),
                    segment.deep_relation().statement_bytes()
                );
                deep::bound_root(&segment)
            })
            .collect::<Vec<_>>();
        assert_ne!(roots[0], roots[1]);
        assert_ne!(roots[1], roots[2]);
        for field in 0..7 {
            assert!(matches!(
                PublicTransferBatch::new(
                    &prepared,
                    &deep::changed_input(expected, field),
                    &root_chain,
                    BatchContextLimits::default()
                ),
                Err(Error::PublicIoMismatch { .. })
            ));
        }
        let mut changed_roots = root_chain;
        changed_roots[1][0] ^= 1;
        let changed = PublicTransferBatch::new(
            &prepared,
            &expected,
            &changed_roots,
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_eq!(original.statements()[0], changed.statements()[0]);
        assert_ne!(roots[0], deep::bound_root(&changed.segment(0).unwrap()));
        assert_quantity_claim_change_rebinds(
            &rows,
            &claims,
            inputs,
            &root_chain,
            &original,
            &roots,
        );
        assert_shorter_quantity_bundle_rebinds(&root_chain, &original, &roots);
        let narrow = PublicTransferBatch::new(
            &narrow,
            &deep::expected(&narrow),
            &root_chain,
            BatchContextLimits::default(),
        )
        .unwrap();
        assert_ne!(
            narrow.segment(0).unwrap().schema().identity,
            FastpqQuantityUnits::BATCH_IDENTITY
        );
        assert_ne!(roots[0], deep::bound_root(&narrow.segment(0).unwrap()));
    }

    #[test]
    fn deep_wrapper_identity_changes_binding_without_changing_any_statement_byte() {
        use crate::backend::{
            deep_binding::Context,
            deep_relation::{DeepRelation, tests as deep},
        };
        let fixture = PublicFixture::new(2, false);
        let prepared = fixture.prepare();
        let original = batch(&prepared);
        let mut segment = original.segment(0).unwrap();
        let statement = segment.statement_bytes().to_vec();
        let root = deep::bound_root(&segment);
        assert_ne!(
            segment.schema().identity,
            segment.deep_relation().schema().identity
        );
        assert_ne!(root, deep::bound_root(segment.deep_relation()));
        segment.identity = "fastpq:deep:test-only-distinct-ordinary-segment";
        assert_eq!(statement, segment.statement_bytes());
        assert_ne!(root, deep::bound_root(&segment));
        segment.identity = "";
        assert!(Context::for_relation(&segment).is_err());
    }
}
