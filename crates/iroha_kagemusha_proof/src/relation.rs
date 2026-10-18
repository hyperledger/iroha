//! The in-circuit step relations (G1 core and rest layout) on the
//! `iroha_plonk_gadgets` chips.
//!
//! Every value is either range-checked where it is assigned (`u128` and
//! `u64` fields, via [`UintChip`]), a constant pinned through the constants
//! column, a hash output, or a free glue witness. Every free witness is one
//! of:
//!
//! - an opened core field or the rest digest (bound by the predecessor
//!   commitment, which a consumer compares with the lineage proof's head);
//! - a carried successor field (a state nonce or an updated map root, bound
//!   by the successor commitment; spec section 3.2 assigns root transitions
//!   to the native Advance check and to the lineage relation);
//! - a Request term (bound by `credit_id`, which the statement effect
//!   carries and both wallets recompute from the Request body they hold),
//!   both account digests included;
//! - the Request digest of a Send (bound by the statement effect);
//! - the lineage inputs of `sigma_send` and the scheme-level relation
//!   identity (bound by the statement, which a consumer compares with the
//!   lineage proof and the scheme).
//!
//! - a control opening (a quota-window slot, a usage-array leaf or sibling),
//!   bound by the head-committed root it must reach
//!   (`crate::control_circuit`).
//!
//! The scheme, asset and own-wallet limbs of the Request and of the
//! statement are the opened core cells, never fresh witnesses. Every hash
//! output is compared with the native reference ([`StepWitness::evaluate`])
//! while the witness is known, so a successful synthesis also proves digest
//! parity.

use iroha_pasta::poseidon::PoseidonField;
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{
    AbsorbInput, GlueChip, RunningSumChip, SpongeChip, U64, U128, UintChip, Word, WordHasher,
    pow5_fq::DuplexChip,
    statement::{
        EFFECT_UNION_FIELDS, STATEMENT_FIELDS, STATEMENT_VERSION, StatementCells, StepRelation,
        digest_fields, statement_digest,
    },
};

use crate::{
    circuit::{HashSite, Inventory, LanePlan, RelationOutput, RelationShape},
    control_circuit::ControlChips,
    witness::{
        CONTROL_ATTESTATION_LEASE, CONTROL_QUOTAS, CORE_FIELDS, CoreState, LIFECYCLE_ACTIVE,
        NativeStep, REQUEST_VERSION, RequestTerms, StepDigests, StepInputs, StepWitness,
        core_index, field_value,
    },
};

/// The chips a step lays out on.
pub struct Chips<F: PoseidonField> {
    /// The glue chip (on the glue lane's columns).
    pub glue: GlueChip<F>,
    /// The running-sum chip.
    pub range: RunningSumChip<F>,
    /// One sponge per lane.
    pub sponges: Vec<SpongeChip<F>>,
}

/// Where a step relation's hash sites run.
///
/// The σ circuit spreads its sites over Pow5 lanes by a static plan. A lean-lineage
/// A stage runs the same relation on its one RP57 operation lane. Both hash
/// `[domain, len, inputs]` identically ([`WordHasher`]), so every digest is equal.
pub enum RelationLanes<'s, F: PoseidonField> {
    /// One sponge per lane, each site on its planned lane.
    Sigma {
        /// One sponge per lane.
        sponges: &'s mut [SpongeChip<F>],
        /// The lane of every hash site.
        plan: &'s LanePlan,
    },
    /// One lane for every site.
    Single(&'s mut DuplexChip<F>),
}

impl<F: PoseidonField> RelationLanes<'_, F> {
    /// The hasher of `site`'s lane.
    pub(crate) fn site(&mut self, site: HashSite) -> Result<&mut dyn WordHasher<F>, Error> {
        let lane: &mut dyn WordHasher<F> = match self {
            Self::Sigma { sponges, plan } => sponges
                .get_mut(plan.lane_of(site))
                .ok_or(Error::Synthesis)?,
            Self::Single(lane) => &mut **lane,
        };
        Ok(lane)
    }
}

/// The relation's statement before any lane hashes it: the σ circuit hashes it into
/// its public digest, and a lean A stage binds its fields to A's own statement.
pub struct RelationStatement<F: PoseidonField> {
    step: StepRelation,
    relation_id: [Word<F>; 2],
    scheme_id: [Word<F>; 2],
    asset_digest: [Word<F>; 2],
    credential_digest: Word<F>,
    lifecycle: Word<F>,
    sequence: Word<F>,
    next_load: Word<F>,
    predecessor: Word<F>,
    successor: Word<F>,
    enabled_controls: Word<F>,
    lineage_burned_total: Option<Word<F>>,
    lineage_pending_outgoing_root: Option<Word<F>>,
    effect: Vec<Word<F>>,
    credit: Word<F>,
    chain: Word<F>,
}

impl<F: PoseidonField> RelationStatement<F> {
    /// The cells [`statement_digest`] hashes.
    fn cells(&self) -> StatementCells<'_, F> {
        StatementCells {
            relation_id: [&self.relation_id[0], &self.relation_id[1]],
            scheme_id: [&self.scheme_id[0], &self.scheme_id[1]],
            asset_digest: [&self.asset_digest[0], &self.asset_digest[1]],
            credential_digest: &self.credential_digest,
            lifecycle: &self.lifecycle,
            sequence: &self.sequence,
            next_load: &self.next_load,
            predecessor: &self.predecessor,
            successor: &self.successor,
            enabled_controls: &self.enabled_controls,
            lineage_burned_total: self.lineage_burned_total.as_ref(),
            lineage_pending_outgoing_root: self.lineage_pending_outgoing_root.as_ref(),
            effect: &self.effect,
        }
    }

    /// The [`STATEMENT_FIELDS`] statement inputs in digest order, constants included:
    /// exactly what [`statement_digest`] hashes under the statement domain.
    ///
    /// # Errors
    /// More than [`EFFECT_UNION_FIELDS`] effect elements.
    pub fn fields(&self) -> Result<Vec<AbsorbInput<'_, F>>, Error> {
        if self.effect.len() > EFFECT_UNION_FIELDS {
            return Err(Error::Synthesis);
        }
        fn optional<F: PoseidonField>(cell: Option<&Word<F>>) -> AbsorbInput<'_, F> {
            cell.map_or(AbsorbInput::Constant(F::ZERO), AbsorbInput::Word)
        }
        let word = AbsorbInput::Word;
        let mut inputs = vec![
            AbsorbInput::Constant(F::from(STATEMENT_VERSION)),
            word(&self.relation_id[0]),
            word(&self.relation_id[1]),
            word(&self.scheme_id[0]),
            word(&self.scheme_id[1]),
            word(&self.asset_digest[0]),
            word(&self.asset_digest[1]),
            word(&self.credential_digest),
            word(&self.lifecycle),
            word(&self.sequence),
            word(&self.next_load),
            word(&self.enabled_controls),
            optional(self.lineage_burned_total.as_ref()),
            optional(self.lineage_pending_outgoing_root.as_ref()),
            word(&self.predecessor),
            word(&self.successor),
            AbsorbInput::Constant(F::from(u64::from(self.step.effect_tag()))),
        ];
        inputs.extend(self.effect.iter().map(AbsorbInput::Word));
        inputs.resize(STATEMENT_FIELDS, AbsorbInput::Constant(F::ZERO));
        Ok(inputs)
    }
}

/// A value of the witness (unknown during key generation).
fn value<T, V>(source: Option<&T>, read: impl FnOnce(&T) -> V) -> Value<V> {
    source.map_or_else(Value::unknown, |source| Value::known(read(source)))
}

/// Free witnesses laid out four per glue row.
struct Batch<F> {
    values: Vec<Value<F>>,
}

impl<F: Copy> Batch<F> {
    /// Queues one value and returns its index.
    fn push(&mut self, value: Value<F>) -> usize {
        self.values.push(value);
        self.values.len() - 1
    }

    /// Queues two limbs.
    fn pair(&mut self, value: Value<[F; 2]>) -> [usize; 2] {
        let [lo, hi] = value.transpose_array();
        [self.push(lo), self.push(hi)]
    }
}

/// The word at `index` of a laid-out batch.
fn at<F: PoseidonField>(words: &[Word<F>], index: usize) -> Result<&Word<F>, Error> {
    words.get(index).ok_or(Error::Synthesis)
}

/// The two words of a laid-out pair.
fn pair_at<F: PoseidonField>(words: &[Word<F>], pair: [usize; 2]) -> Result<[&Word<F>; 2], Error> {
    Ok([at(words, pair[0])?, at(words, pair[1])?])
}

/// Fails when a known digest differs from the native reference.
fn check_digest<F: PoseidonField>(digest: &Word<F>, expected: Option<F>) -> Result<(), Error> {
    expected.map_or(Ok(()), |expected| {
        digest
            .value()
            .error_if_known_and(|value| *value != expected)
    })
}

/// Hashes `inputs` under the domain of `site` on the site's lane.
fn hash_site<F: PoseidonField>(
    lanes: &mut RelationLanes<'_, F>,
    region: &mut Region<'_, F>,
    shape: RelationShape,
    site: HashSite,
    inputs: &[AbsorbInput<'_, F>],
) -> Result<Word<F>, Error> {
    let &[(domain, arity)] = shape.site_hashes(site).as_slice() else {
        return Err(Error::Synthesis);
    };
    if inputs.len() != arity {
        return Err(Error::Synthesis);
    }
    lanes.site(site)?.hash_inputs(region, domain, inputs)
}

/// The words of `words`, as absorbed inputs.
fn absorb<'w, F: PoseidonField>(words: &[&'w Word<F>]) -> Vec<AbsorbInput<'w, F>> {
    words.iter().map(|word| AbsorbInput::Word(word)).collect()
}

/// The state commitment inputs: the core, then the rest digest.
fn commitment<'w, F: PoseidonField>(
    core: &[&'w Word<F>; CORE_FIELDS],
    rest_digest: &'w Word<F>,
) -> Vec<AbsorbInput<'w, F>> {
    let mut words = core.to_vec();
    words.push(rest_digest);
    absorb(&words)
}

/// The batch indices of the opened core fields that are not range-checked.
struct CoreSlots {
    lifecycle: usize,
    scheme: [usize; 2],
    asset: [usize; 2],
    wallet: [usize; 2],
    credential: usize,
    burned_total: usize,
    next_load: usize,
    next_redeem: usize,
    send_chain: usize,
    recv_chain: usize,
    roots: [usize; 5],
    enabled_controls: usize,
    quota_windows_root: usize,
    quota_bounds: Option<[usize; 2]>,
    /// The lease expiry, unless the lease control range-checks it.
    lease_expiry: Option<usize>,
    state_nonce: usize,
    /// `sigma_recv` only (`sigma_send` range-checks them): the send
    /// ordinal, the policy epoch and the accepted-time floor.
    unchecked: Option<[usize; 3]>,
}

/// The Request terms `sigma_send` does not range-check (indices into the
/// batch), or every term for `sigma_recv`.
struct TermSlots {
    receiver_credential: usize,
    send_ordinal: Option<usize>,
    fee: Option<usize>,
    fee_schedule: usize,
    policy_epoch: Option<usize>,
    scheme_policy: usize,
    request_time: Option<usize>,
    certificates: usize,
    nonce: [usize; 2],
}

/// The range-checked fields of `sigma_send`.
struct SendChecked<F: PoseidonField> {
    next_send: U128<F>,
    policy_epoch: U64<F>,
    floor: U64<F>,
    burned_in: U128<F>,
    fee: U128<F>,
    request_epoch: U64<F>,
    request_time: U64<F>,
    lower: U64<F>,
    upper: U64<F>,
    /// The lease expiry, with the lease control.
    lease: Option<U64<F>>,
    quota_bounds: Option<[U64<F>; 2]>,
}

/// The Request fields whose cells depend on the step.
struct StepCells<'a, F: PoseidonField> {
    payer: [&'a Word<F>; 2],
    receiver: [&'a Word<F>; 2],
    ordinal: &'a Word<F>,
    fee: &'a Word<F>,
    request_epoch: &'a Word<F>,
    request_time: &'a Word<F>,
}

/// Lays out one step relation and returns its public output, in-circuit
/// digests and inventory.
#[allow(
    clippy::too_many_lines,
    reason = "one straight-line layout of the step relation, in its order"
)]
pub fn assign<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    shape: RelationShape,
    plan: &LanePlan,
    witness: Option<(&StepWitness<F>, &NativeStep<F>)>,
) -> Result<RelationOutput<F>, Error> {
    let digests = witness.map(|(_, native)| native.digests);
    let Chips {
        glue,
        range,
        sponges,
    } = chips;
    let glue_start = glue.next_row();
    let mut uint = UintChip::new(glue, range);
    let body = relate(
        &mut uint,
        &mut RelationLanes::Sigma {
            sponges: sponges.as_mut_slice(),
            plan,
        },
        region,
        shape,
        witness,
    )?;

    // The statement digest.
    let statement_lane = plan.lane_of(HashSite::Statement);
    let statement = statement_digest(
        sponges.get_mut(statement_lane).ok_or(Error::Synthesis)?,
        region,
        body.step,
        &body.cells(),
    )?;
    check_digest(&statement, digests.map(|digests| digests.statement))?;

    let in_circuit = statement
        .value()
        .zip(body.predecessor.value())
        .zip(body.successor.value())
        .zip(body.credit.value())
        .zip(body.chain.value())
        .map(
            |((((statement, predecessor), successor), credit), chain)| StepDigests {
                predecessor,
                successor,
                credit,
                chain,
                statement,
            },
        );
    let public = vec![statement];
    let glue_end = uint.glue().next_row();
    let range_rows = uint.range().next_row();
    let glue_rows = glue_end
        .checked_sub(glue_start)
        .ok_or(Error::BoundsFailure)?;
    let lane_permutations: Vec<usize> = sponges
        .iter()
        .map(|sponge| sponge.lane().next_block())
        .collect();
    let mut lane_rows: Vec<usize> = sponges
        .iter()
        .map(|sponge| sponge.lane().rows_used())
        .collect();
    if let Some(rows) = lane_rows.get_mut(plan.glue_lane()) {
        *rows = glue_end.max(*rows);
    }
    let cells = lane_permutations
        .iter()
        .sum::<usize>()
        .checked_mul(iroha_plonk_gadgets::poseidon::CELLS_PER_PERMUTATION)
        .and_then(|cells| cells.checked_add(glue_rows.checked_mul(4)?))
        .and_then(|cells| cells.checked_add(range_rows))
        .ok_or(Error::BoundsFailure)?;
    Ok(RelationOutput {
        public,
        digests: in_circuit,
        inventory: Inventory {
            lane_permutations,
            lane_rows,
            glue_rows,
            range_rows,
            cells,
        },
    })
}

/// Lays out the relation on one RP57 lane and returns its statement, unhashed.
///
/// A lean-lineage A stage proves its own step this way instead of verifying the
/// step's σ: binding every [`RelationStatement::fields`] input to its own statement
/// field yields exactly the statement digest σ would have certified.
///
/// # Errors
/// As [`assign`].
pub fn assign_single<F: PoseidonField>(
    uint: &mut UintChip<'_, F>,
    lane: &mut DuplexChip<F>,
    region: &mut Region<'_, F>,
    shape: RelationShape,
    witness: Option<(&StepWitness<F>, &NativeStep<F>)>,
) -> Result<RelationStatement<F>, Error> {
    relate(
        uint,
        &mut RelationLanes::Single(lane),
        region,
        shape,
        witness,
    )
}

/// The step relation on any lane set, up to its unhashed statement.
fn relate<F: PoseidonField>(
    uint: &mut UintChip<'_, F>,
    lanes: &mut RelationLanes<'_, F>,
    region: &mut Region<'_, F>,
    shape: RelationShape,
    witness: Option<(&StepWitness<F>, &NativeStep<F>)>,
) -> Result<RelationStatement<F>, Error> {
    let relation = shape.relation;
    if witness.is_some_and(|(witness, _)| witness.relation() != relation.step()) {
        return Err(Error::Synthesis);
    }
    if witness.is_some_and(|(witness, _)| !witness.canonical_digests()) {
        return Err(Error::Synthesis);
    }
    let digests = witness.map(|(_, native)| native.digests);
    let witness = witness.map(|(witness, _)| witness);
    let state = witness.map(|witness| &witness.predecessor);
    let core = state.map(|state| &state.core);
    let send = witness.and_then(|witness| match &witness.inputs {
        StepInputs::Send(send) => Some(send.as_ref()),
        StepInputs::Receive(_) => None,
    });
    let receive = witness.and_then(|witness| match &witness.inputs {
        StepInputs::Receive(receive) => Some(receive.as_ref()),
        StepInputs::Send(_) => None,
    });
    let terms = witness.map(|witness| witness.inputs.terms());
    let is_send = relation.step() == StepRelation::Send;
    let lease = is_send && relation.enforces(CONTROL_ATTESTATION_LEASE);
    let quota = is_send && relation.enforces(CONTROL_QUOTAS);

    // Range-checked fields: the balance, the sequence and the amount always;
    // the send ordinal, policy epoch, accepted-time floor, lineage
    // `burned_total`, fee, Request epoch and times where `sigma_send`
    // compares them.
    let balance: U128<F> = uint.assign_u128(region, value(core, |core| core.balance))?;
    let sequence: U128<F> = uint.assign_u128(region, value(core, |core| core.sequence))?;
    let amount: U128<F> = uint.assign_u128(region, value(terms, |terms| terms.amount))?;
    let checked_send = if is_send {
        let controls = core.map(|core| &core.controls);
        Some(SendChecked {
            next_send: uint.assign_u128(region, value(core, |core| core.next_send))?,
            policy_epoch: uint.assign_u64(region, value(core, |core| core.policy_epoch))?,
            floor: uint.assign_u64(region, value(core, |core| core.accepted_time_floor_ms))?,
            burned_in: uint.assign_u128(region, value(send, |send| send.lineage.burned_total))?,
            fee: uint.assign_u128(region, value(terms, |terms| terms.fee))?,
            request_epoch: uint.assign_u64(region, value(terms, |terms| terms.policy_epoch))?,
            request_time: uint.assign_u64(region, value(terms, |terms| terms.request_time))?,
            lower: uint.assign_u64(region, value(send, |send| send.accepted_lower))?,
            upper: uint.assign_u64(region, value(send, |send| send.accepted_upper))?,
            quota_bounds: if quota {
                Some([
                    uint.assign_u64(
                        region,
                        value(controls, |controls| controls.quota_share_expires_at_ms),
                    )?,
                    uint.assign_u64(
                        region,
                        value(controls, |controls| controls.time_anchor_max_response_ms),
                    )?,
                ])
            } else {
                None
            },
            lease: if lease {
                Some(uint.assign_u64(
                    region,
                    value(controls, |controls| controls.lease_expires_at_ms),
                )?)
            } else {
                None
            },
        })
    } else {
        None
    };

    // Free witnesses, four per glue row.
    let mut batch = Batch { values: Vec::new() };
    let core_values = core.map(CoreState::fields);
    let core_field = |index: usize| value(core_values.as_ref(), |fields| fields[index]);
    let core_pair = |batch: &mut Batch<F>, index: usize| {
        [
            batch.push(core_field(index)),
            batch.push(core_field(index + 1)),
        ]
    };
    let slots = CoreSlots {
        lifecycle: batch.push(core_field(core_index::LIFECYCLE)),
        scheme: core_pair(&mut batch, core_index::SCHEME),
        asset: core_pair(&mut batch, core_index::ASSET),
        wallet: core_pair(&mut batch, core_index::WALLET),
        credential: batch.push(core_field(core_index::CREDENTIAL)),
        burned_total: batch.push(core_field(core_index::BURNED_TOTAL)),
        next_load: batch.push(core_field(core_index::NEXT_LOAD)),
        next_redeem: batch.push(core_field(core_index::NEXT_REDEEM)),
        send_chain: batch.push(core_field(core_index::SEND_CHAIN)),
        recv_chain: batch.push(core_field(core_index::RECEIVE_CHAIN)),
        roots: [
            batch.push(core_field(core_index::CONSUMED_CREDIT_ROOT)),
            batch.push(core_field(core_index::PENDING_OUTGOING_ROOT)),
            batch.push(core_field(core_index::LOAD_REDEEM_ROOT)),
            batch.push(core_field(core_index::FEE_CLAIM_ROOT)),
            batch.push(core_field(core_index::QUOTA_USAGE_ROOT)),
        ],
        enabled_controls: batch.push(core_field(core_index::ENABLED_CONTROLS)),
        quota_windows_root: batch.push(core_field(core_index::QUOTA_WINDOWS_ROOT)),
        quota_bounds: (!quota).then(|| {
            [
                batch.push(core_field(core_index::QUOTA_SHARE_EXPIRY)),
                batch.push(core_field(core_index::TIME_ANCHOR_MAX_RESPONSE)),
            ]
        }),
        lease_expiry: (!lease).then(|| batch.push(core_field(core_index::LEASE_EXPIRY))),
        state_nonce: batch.push(core_field(core_index::STATE_NONCE)),
        unchecked: (!is_send).then(|| {
            [
                batch.push(core_field(core_index::NEXT_SEND)),
                batch.push(core_field(core_index::POLICY_EPOCH)),
                batch.push(core_field(core_index::TIME_FLOOR)),
            ]
        }),
    };
    // The rest digest (no step relation opens the rest).
    let rest_digest = batch.push(value(state, |state| state.rest.digest::<F>()));
    // The scheme-level relation identity.
    let relation_id = batch.pair(value(witness, |witness| {
        digest_fields::<F>(&witness.relation_id)
    }));
    // Carried successor fields.
    let successor_nonce = batch.push(value(witness, |witness| witness.successor_nonce));
    // `sigma_send` updates the pending-outgoing and fee-claim roots,
    // `sigma_recv` the consumed-credit root (twice the same slot).
    let successor_roots = if is_send {
        [
            batch.push(value(send, |send| send.successor_pending_outgoing)),
            batch.push(value(send, |send| send.successor_fee_claim)),
        ]
    } else {
        let consumed = batch.push(value(receive, |receive| receive.successor_consumed_credit));
        [consumed, consumed]
    };
    // The lineage pending-outgoing input of `sigma_send`.
    let pending_in =
        is_send.then(|| batch.push(value(send, |send| send.lineage.pending_outgoing_root)));
    // The receiver wallet (`sigma_send`) or the payer wallet (`sigma_recv`).
    let counterparty = batch.pair(value(witness, |witness| match &witness.inputs {
        StepInputs::Send(send) => digest_fields::<F>(&send.receiver_wallet),
        StepInputs::Receive(receive) => digest_fields::<F>(&receive.payer_wallet),
    }));
    // Both account digests of the Request (owner answer A5): terms bound by
    // `credit_id`.
    let payer_account = batch.pair(value(witness, |witness| match &witness.inputs {
        StepInputs::Send(send) => digest_fields::<F>(&send.payer_account_digest),
        StepInputs::Receive(receive) => digest_fields::<F>(&receive.payer_account_digest),
    }));
    let receiver_account = batch.pair(value(witness, |witness| match &witness.inputs {
        StepInputs::Send(send) => digest_fields::<F>(&send.receiver_account_digest),
        StepInputs::Receive(receive) => digest_fields::<F>(&receive.receiver_account_digest),
    }));
    // The Request terms that are not range-checked.
    let term = |batch: &mut Batch<F>, read: fn(&RequestTerms) -> &[u8; 32]| {
        batch.push(value(terms, |terms| field_value::<F>(read(terms))))
    };
    // The Request digest the Send effect and chain bind (a witness:
    // `sigma_send` does not recompute the signed object's Poseidon digest; the statement
    // digest binds it).
    let request_digest =
        is_send.then(|| batch.push(value(send, |send| field_value::<F>(&send.request_digest))));
    let term_slots = TermSlots {
        // The Request's receiver credential digest is a term for both steps:
        // the receiver is matched by `wallet_id`, never by credential digest
        // (owner answer Q8).
        receiver_credential: batch.push(value(witness, |witness| match &witness.inputs {
            StepInputs::Send(send) => field_value::<F>(&send.receiver_credential_digest),
            StepInputs::Receive(receive) => field_value::<F>(&receive.receiver_credential_digest),
        })),
        send_ordinal: (!is_send)
            .then(|| batch.push(value(receive, |receive| F::from_u128(receive.send_ordinal)))),
        fee: (!is_send).then(|| batch.push(value(terms, |terms| F::from_u128(terms.fee)))),
        fee_schedule: term(&mut batch, |terms| &terms.fee_schedule),
        policy_epoch: (!is_send)
            .then(|| batch.push(value(terms, |terms| F::from(terms.policy_epoch)))),
        scheme_policy: term(&mut batch, |terms| &terms.scheme_policy),
        request_time: (!is_send)
            .then(|| batch.push(value(terms, |terms| F::from(terms.request_time)))),
        certificates: term(&mut batch, |terms| &terms.certificates),
        nonce: batch.pair(value(terms, |terms| digest_fields::<F>(&terms.nonce))),
    };
    let words = uint.glue().witnesses(region, &batch.values)?;
    let word = |index: usize| at(&words, index);

    // Lifecycle Active or Retiring (carried unchanged), a nonzero amount, a
    // sequence that does not overflow.
    let lifecycle = word(slots.lifecycle)?;
    let retiring =
        uint.glue()
            .add_constant(region, lifecycle, -F::from(u64::from(LIFECYCLE_ACTIVE)))?;
    uint.glue().assert_bool(region, &retiring)?;
    uint.assert_nonzero(region, &amount)?;
    let sequence_after = uint.checked_add_constant(region, &sequence, 1)?;
    let enabled_controls = word(slots.enabled_controls)?;

    // Distinct payer and receiver wallets: not (lo equal and hi equal).
    let wallet = pair_at(&words, slots.wallet)?;
    let counterparty = pair_at(&words, counterparty)?;
    let same_lo = uint.glue().is_equal(region, wallet[0], counterparty[0])?;
    let same_hi = uint.glue().is_equal(region, wallet[1], counterparty[1])?;
    let same_wallet = uint.glue().and(region, &same_lo, &same_hi)?;
    GlueChip::assert_constant(region, same_wallet.word(), F::ZERO)?;

    let scheme = pair_at(&words, slots.scheme)?;
    let asset = pair_at(&words, slots.asset)?;
    let credential = word(slots.credential)?;
    let receiver_credential = word(term_slots.receiver_credential)?;
    let fee_schedule = word(term_slots.fee_schedule)?;
    let scheme_policy = word(term_slots.scheme_policy)?;
    let certificates = word(term_slots.certificates)?;
    let nonce = pair_at(&words, term_slots.nonce)?;
    let payer_account = pair_at(&words, payer_account)?;
    let receiver_account = pair_at(&words, receiver_account)?;
    let quota_windows_root = word(slots.quota_windows_root)?;
    let quota_usage = word(slots.roots[4])?;
    let (quota_expiry, response_bound) = match (&checked_send, slots.quota_bounds) {
        (
            Some(SendChecked {
                quota_bounds: Some([expiry, bound]),
                ..
            }),
            None,
        ) => (expiry.word().clone(), bound.word().clone()),
        (_, Some([expiry, bound])) => (word(expiry)?.clone(), word(bound)?.clone()),
        _ => return Err(Error::Synthesis),
    };

    // The step: balance, ordinal and window checks; the Request fields that
    // depend on the step.
    let (next_send, policy_epoch, time_floor) = match (&checked_send, slots.unchecked) {
        (Some(checked), None) => (
            checked.next_send.word().clone(),
            checked.policy_epoch.word().clone(),
            checked.floor.word().clone(),
        ),
        (None, Some([ordinal, policy, floor])) => (
            word(ordinal)?.clone(),
            word(policy)?.clone(),
            word(floor)?.clone(),
        ),
        _ => return Err(Error::Synthesis),
    };
    let mut next_send_after = next_send.clone();
    let mut time_floor_after = time_floor.clone();
    let mut quota_usage_after = quota_usage.clone();
    let successor_balance: Word<F>;
    let burned_after: Word<F>;
    let request_cells = if let Some(checked) = &checked_send {
        // The core's enabled-controls mask is the relation's: the mask
        // selects this relation's verifying key (spec section 3.2).
        GlueChip::assert_constant(
            region,
            enabled_controls,
            F::from(u64::from(relation.enabled_controls())),
        )?;
        // spendable = balance - burned_total (the lineage input), and
        // amount + fee <= spendable, all checked.
        let debit = uint.checked_add(region, &amount, &checked.fee)?;
        let spendable = uint.checked_sub(region, &balance, &checked.burned_in)?;
        let remaining = uint.checked_sub(region, &spendable, &debit)?;
        // balance' = remaining + burned_total = balance - amount - fee.
        successor_balance = uint
            .glue()
            .add(region, remaining.word(), checked.burned_in.word())?;
        burned_after = checked.burned_in.word().clone();
        next_send_after = uint
            .checked_add_constant(region, &checked.next_send, 1)?
            .word()
            .clone();
        // The Request policy epoch is not newer than the payer's.
        uint.assert_le(region, &checked.request_epoch, &checked.policy_epoch)?;
        // max(floor, request time) <= lower <= upper; the successor floor
        // is `lower`, so accepted time never goes back.
        uint.assert_le(region, &checked.floor, &checked.lower)?;
        uint.assert_le(region, &checked.request_time, &checked.lower)?;
        uint.assert_le(region, &checked.lower, &checked.upper)?;
        time_floor_after = checked.lower.word().clone();
        // The lease control: the upper time is before the lease expiry.
        if let Some(lease) = &checked.lease {
            uint.assert_lt(region, &checked.upper, lease)?;
        }
        // The quota control: charge every touched window and update the
        // usage array.
        if quota {
            let [expiry, bound] = checked.quota_bounds.as_ref().ok_or(Error::Synthesis)?;
            uint.assert_lt(region, &checked.upper, expiry)?;
            let span = uint.checked_sub(region, &checked.upper, &checked.lower)?;
            uint.assert_le(region, &span, bound)?;
            quota_usage_after = ControlChips {
                uint: &mut *uint,
                lanes: &mut *lanes,
            }
            .quota(
                region,
                quota_windows_root,
                quota_usage,
                &checked.lower,
                &checked.upper,
                &debit,
                send.map(|send| send.quota.as_ref()),
            )?;
        }
        StepCells {
            payer: wallet,
            receiver: counterparty,
            ordinal: checked.next_send.word(),
            fee: checked.fee.word(),
            request_epoch: checked.request_epoch.word(),
            request_time: checked.request_time.word(),
        }
    } else {
        // The core mask still has only defined bits.
        let controls = core.map(|core| core.controls.enabled);
        let bits: Vec<_> = (0..2)
            .map(|bit| {
                uint.glue().boolean(
                    region,
                    value(controls.as_ref(), |mask| (*mask >> bit) & 1 == 1),
                )
            })
            .collect::<Result<_, _>>()?;
        let recomposed = uint.glue().linear(
            region,
            &[(F::ONE, bits[0].word()), (F::from(2_u64), bits[1].word())],
            F::ZERO,
        )?;
        GlueChip::assert_equal(region, &recomposed, enabled_controls)?;
        // balance + amount < 2^128.
        successor_balance = uint.checked_add(region, &balance, &amount)?.word().clone();
        burned_after = word(slots.burned_total)?.clone();
        StepCells {
            payer: counterparty,
            receiver: wallet,
            ordinal: word(term_slots.send_ordinal.ok_or(Error::Synthesis)?)?,
            fee: word(term_slots.fee.ok_or(Error::Synthesis)?)?,
            request_epoch: word(term_slots.policy_epoch.ok_or(Error::Synthesis)?)?,
            request_time: word(term_slots.request_time.ok_or(Error::Synthesis)?)?,
        }
    };

    // credit_id = P(kgwcrdt1, Request body): one element.
    let mut request = vec![AbsorbInput::Constant(F::from(REQUEST_VERSION))];
    request.extend(absorb(&[
        scheme[0],
        scheme[1],
        asset[0],
        asset[1],
        request_cells.payer[0],
        request_cells.payer[1],
        payer_account[0],
        payer_account[1],
        request_cells.receiver[0],
        request_cells.receiver[1],
        receiver_account[0],
        receiver_account[1],
        request_cells.ordinal,
        receiver_credential,
        amount.word(),
        fee_schedule,
        request_cells.fee,
        request_cells.request_epoch,
        scheme_policy,
        request_cells.request_time,
        certificates,
        nonce[0],
        nonce[1],
    ]));
    let credit = hash_site(lanes, region, shape, HashSite::Credit, &request)?;
    check_digest(&credit, digests.map(|digests| digests.credit))?;

    // The chain append and the effect.
    let send_chain = word(slots.send_chain)?;
    let recv_chain = word(slots.recv_chain)?;
    let (chain, effect) = if let Some(checked) = &checked_send {
        let request_digest = word(request_digest.ok_or(Error::Synthesis)?)?;
        let entry = absorb(&[
            send_chain,
            &credit,
            counterparty[0],
            counterparty[1],
            checked.next_send.word(),
            amount.word(),
            checked.fee.word(),
            request_digest,
        ]);
        let chain = hash_site(lanes, region, shape, HashSite::Chain, &entry)?;
        let effect = [
            &credit,
            counterparty[0],
            counterparty[1],
            checked.next_send.word(),
            amount.word(),
            checked.fee.word(),
            request_digest,
            checked.lower.word(),
            checked.upper.word(),
        ]
        .map(Clone::clone)
        .to_vec();
        (chain, effect)
    } else {
        let entry = absorb(&[
            recv_chain,
            &credit,
            counterparty[0],
            counterparty[1],
            amount.word(),
        ]);
        let chain = hash_site(lanes, region, shape, HashSite::Chain, &entry)?;
        let effect = [&credit, counterparty[0], counterparty[1], amount.word()]
            .map(Clone::clone)
            .to_vec();
        (chain, effect)
    };
    check_digest(&chain, digests.map(|digests| digests.chain))?;

    // Predecessor and successor commitments P(kgwcore1, core || rest).
    let rest_digest = word(rest_digest)?;
    let [consumed, pending, load_redeem, fee_claim, _] = slots.roots;
    let (consumed, pending, load_redeem, fee_claim) = (
        word(consumed)?,
        word(pending)?,
        word(load_redeem)?,
        word(fee_claim)?,
    );
    let next_load = word(slots.next_load)?;
    let next_redeem = word(slots.next_redeem)?;
    let lease_expiry = match (&checked_send, slots.lease_expiry) {
        (
            Some(SendChecked {
                lease: Some(lease), ..
            }),
            None,
        ) => lease.word(),
        (_, Some(lease)) => word(lease)?,
        _ => return Err(Error::Synthesis),
    };
    let burned_total = word(slots.burned_total)?;
    let state_nonce = word(slots.state_nonce)?;
    let predecessor_core: [&Word<F>; CORE_FIELDS] = [
        lifecycle,
        scheme[0],
        scheme[1],
        asset[0],
        asset[1],
        wallet[0],
        wallet[1],
        credential,
        balance.word(),
        burned_total,
        sequence.word(),
        &next_send,
        next_load,
        next_redeem,
        send_chain,
        recv_chain,
        consumed,
        pending,
        load_redeem,
        fee_claim,
        quota_usage,
        enabled_controls,
        quota_windows_root,
        &quota_expiry,
        &response_bound,
        lease_expiry,
        &policy_epoch,
        &time_floor,
        state_nonce,
    ];
    let (successor_send_chain, successor_recv_chain) = if is_send {
        (&chain, recv_chain)
    } else {
        (send_chain, &chain)
    };
    let successor_nonce = word(successor_nonce)?;
    let [updated_first, updated_second] = [word(successor_roots[0])?, word(successor_roots[1])?];
    let (consumed_after, pending_after, fee_claim_after) = if is_send {
        (consumed, updated_first, updated_second)
    } else {
        (updated_first, pending, fee_claim)
    };
    let successor_core: [&Word<F>; CORE_FIELDS] = [
        lifecycle,
        scheme[0],
        scheme[1],
        asset[0],
        asset[1],
        wallet[0],
        wallet[1],
        credential,
        &successor_balance,
        &burned_after,
        sequence_after.word(),
        &next_send_after,
        next_load,
        next_redeem,
        successor_send_chain,
        successor_recv_chain,
        consumed_after,
        pending_after,
        load_redeem,
        fee_claim_after,
        &quota_usage_after,
        enabled_controls,
        quota_windows_root,
        &quota_expiry,
        &response_bound,
        lease_expiry,
        &policy_epoch,
        &time_floor_after,
        successor_nonce,
    ];
    let predecessor = hash_site(
        lanes,
        region,
        shape,
        HashSite::Predecessor,
        &commitment(&predecessor_core, rest_digest),
    )?;
    check_digest(&predecessor, digests.map(|digests| digests.predecessor))?;
    let successor = hash_site(
        lanes,
        region,
        shape,
        HashSite::Successor,
        &commitment(&successor_core, rest_digest),
    )?;
    check_digest(&successor, digests.map(|digests| digests.successor))?;

    // The unhashed statement.
    let pending_in = pending_in.map(word).transpose()?;
    let [relation_lo, relation_hi] = pair_at(&words, relation_id)?;
    Ok(RelationStatement {
        step: relation.step(),
        relation_id: [relation_lo.clone(), relation_hi.clone()],
        scheme_id: [scheme[0].clone(), scheme[1].clone()],
        asset_digest: [asset[0].clone(), asset[1].clone()],
        credential_digest: credential.clone(),
        lifecycle: lifecycle.clone(),
        sequence: sequence_after.word().clone(),
        next_load: next_load.clone(),
        predecessor,
        successor,
        enabled_controls: enabled_controls.clone(),
        lineage_burned_total: checked_send
            .as_ref()
            .map(|checked| checked.burned_in.word().clone()),
        lineage_pending_outgoing_root: pending_in.cloned(),
        effect,
        credit,
        chain,
    })
}
