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
//!   carries and both wallets recompute from the Request body they hold);
//! - the Request digest of a Send (bound by the statement effect);
//! - the lineage inputs of `sigma_send` and the scheme-level relation
//!   identity (bound by the statement, which a consumer compares with the
//!   lineage proof and the scheme).
//!
//! The scheme, asset and own-wallet limbs of the Request and of the
//! statement are the opened core cells, never fresh witnesses. Every hash
//! output is compared with the native reference ([`StepWitness::evaluate`])
//! while the witness is known, so a successful synthesis also proves digest
//! parity.

use iroha_pasta::poseidon::PoseidonField;
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{
    AbsorbInput, GlueChip, RunningSumChip, SpongeChip, U64, U128, UintChip, Word,
    statement::{StatementCells, StepRelation, digest_fields, statement_digest},
};

use crate::{
    circuit::{HashSite, Inventory, LanePlan, RelationOutput, RelationShape},
    witness::{
        CONTROL_BLACKLIST, CORE_FIELDS, CoreState, LIFECYCLE_ACTIVE, NativeStep, REQUEST_VERSION,
        RequestTerms, StepDigests, StepInputs, StepWitness, core_index,
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
    sponges: &mut [SpongeChip<F>],
    region: &mut Region<'_, F>,
    shape: RelationShape,
    plan: &LanePlan,
    site: HashSite,
    inputs: &[AbsorbInput<'_, F>],
) -> Result<Word<F>, Error> {
    let (domain, arity) = shape.site_domain(site);
    if inputs.len() != arity {
        return Err(Error::Synthesis);
    }
    sponges
        .get_mut(plan.lane_of(site))
        .ok_or(Error::Synthesis)?
        .hash(region, domain, inputs)
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
    credential: [usize; 2],
    burned_total: usize,
    next_load: usize,
    next_redeem: usize,
    send_chain: usize,
    recv_chain: usize,
    roots: [usize; 5],
    enabled_controls: usize,
    quota_windows_root: usize,
    blacklist_version: usize,
    blacklist_root: usize,
    /// The blacklist issue time and maximum age, unless the blacklist
    /// control range-checks them.
    blacklist_age: Option<[usize; 2]>,
    lease_expiry: usize,
    state_nonce: usize,
    /// `sigma_recv` only (`sigma_send` range-checks them): the send
    /// ordinal, the policy epoch and the accepted-time floor.
    unchecked: Option<[usize; 3]>,
}

/// The Request terms `sigma_send` does not range-check (indices into the
/// batch), or every term for `sigma_recv`.
struct TermSlots {
    receiver_credential: [usize; 2],
    send_ordinal: Option<usize>,
    fee: Option<usize>,
    fee_schedule: [usize; 2],
    policy_epoch: Option<usize>,
    scheme_policy: [usize; 2],
    request_time: Option<usize>,
    certificates: [usize; 2],
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
    /// The blacklist issue time and maximum age, with the blacklist
    /// control.
    blacklist_age: Option<[U64<F>; 2]>,
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

/// The maximum-age rule of the blacklist control (owner answer Q5; the
/// native G1 `check_blacklist` age check). With `active = [version != 0
/// and max_age != 0]`, the gated slacks `active (upper - issued)` and
/// `active (issued + max_age - upper)` are range-checked to 64 and 65 bits:
/// with `issued`, `max_age` and `upper` below `2^64`, a negative slack is a
/// field element above `p - 2^65` and fails its check, and an inactive rule
/// gates both slacks to zero.
fn blacklist_age_rule<F: PoseidonField>(
    uint: &mut UintChip<'_, F>,
    region: &mut Region<'_, F>,
    version: &Word<F>,
    [issued, max_age]: &[U64<F>; 2],
    upper: &U64<F>,
) -> Result<(), Error> {
    let glue = uint.glue();
    let product = glue.mul(region, version, max_age.word())?;
    let inactive = glue.is_zero(region, &product)?;
    let active = glue.not(region, &inactive)?;
    let age = glue.sub(region, upper.word(), issued.word())?;
    let gated_age = glue.mul(region, active.word(), &age)?;
    let headroom = glue.linear(
        region,
        &[
            (F::ONE, issued.word()),
            (F::ONE, max_age.word()),
            (-F::ONE, upper.word()),
        ],
        F::ZERO,
    )?;
    let gated_headroom = glue.mul(region, active.word(), &headroom)?;
    uint.range().range_check(region, &gated_age, 64)?;
    uint.range().range_check(region, &gated_headroom, 65)?;
    Ok(())
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
    let relation = shape.relation;
    if witness.is_some_and(|(witness, _)| witness.relation() != relation.step()) {
        return Err(Error::Synthesis);
    }
    let digests = witness.map(|(_, native)| native.digests);
    let witness = witness.map(|(witness, _)| witness);
    let Chips {
        glue,
        range,
        sponges,
    } = chips;
    let glue_start = glue.next_row();
    let mut uint = UintChip::new(glue, range);
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
    let blacklist = relation.enforces(CONTROL_BLACKLIST);

    // Range-checked fields: the balance, the sequence and the amount always;
    // the send ordinal, policy epoch, accepted-time floor, lineage
    // `burned_total`, fee, Request epoch and times where `sigma_send`
    // compares them, and the blacklist issue time and maximum age where the
    // blacklist control compares them.
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
            blacklist_age: if blacklist {
                Some([
                    uint.assign_u64(
                        region,
                        value(controls, |controls| controls.blacklist_issued_at_ms),
                    )?,
                    uint.assign_u64(
                        region,
                        value(controls, |controls| controls.blacklist_max_age_ms),
                    )?,
                ])
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
        credential: core_pair(&mut batch, core_index::CREDENTIAL),
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
        blacklist_version: batch.push(core_field(core_index::BLACKLIST_VERSION)),
        blacklist_root: batch.push(core_field(core_index::BLACKLIST_ROOT)),
        blacklist_age: (!blacklist).then(|| {
            [
                batch.push(core_field(core_index::BLACKLIST_ISSUED_AT)),
                batch.push(core_field(core_index::BLACKLIST_MAX_AGE)),
            ]
        }),
        lease_expiry: batch.push(core_field(core_index::LEASE_EXPIRY)),
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
    // The Request terms that are not range-checked.
    let term = |batch: &mut Batch<F>, read: fn(&RequestTerms) -> &[u8; 32]| {
        batch.pair(value(terms, |terms| digest_fields::<F>(read(terms))))
    };
    // The Request digest the Send effect and chain bind (a witness:
    // `sigma_send` does not recompute the SHA-256 digest; the statement
    // digest binds it).
    let request_digest =
        is_send.then(|| batch.pair(value(send, |send| digest_fields::<F>(&send.request_digest))));
    let term_slots = TermSlots {
        // The Request's receiver credential digest is a term for both steps:
        // the receiver is matched by `wallet_id`, never by credential digest
        // (owner answer Q8).
        receiver_credential: batch.pair(value(witness, |witness| match &witness.inputs {
            StepInputs::Send(send) => digest_fields::<F>(&send.receiver_credential_digest),
            StepInputs::Receive(receive) => digest_fields::<F>(&receive.receiver_credential_digest),
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
        nonce: term(&mut batch, |terms| &terms.nonce),
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
    let credential = pair_at(&words, slots.credential)?;
    let receiver_credential = pair_at(&words, term_slots.receiver_credential)?;
    let fee_schedule = pair_at(&words, term_slots.fee_schedule)?;
    let scheme_policy = pair_at(&words, term_slots.scheme_policy)?;
    let certificates = pair_at(&words, term_slots.certificates)?;
    let nonce = pair_at(&words, term_slots.nonce)?;
    let blacklist_version = word(slots.blacklist_version)?;

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
    let (issued_at, max_age) = match (&checked_send, slots.blacklist_age) {
        (
            Some(SendChecked {
                blacklist_age: Some([issued, max_age]),
                ..
            }),
            None,
        ) => (issued.word().clone(), max_age.word().clone()),
        (_, Some([issued, max_age])) => (word(issued)?.clone(), word(max_age)?.clone()),
        _ => return Err(Error::Synthesis),
    };
    let mut next_send_after = next_send.clone();
    let mut time_floor_after = time_floor.clone();
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
        // The blacklist control: the maximum list age at the upper time.
        if let Some(age) = &checked.blacklist_age {
            blacklist_age_rule(&mut uint, region, blacklist_version, age, &checked.upper)?;
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
        request_cells.receiver[0],
        request_cells.receiver[1],
        request_cells.ordinal,
        receiver_credential[0],
        receiver_credential[1],
        amount.word(),
        fee_schedule[0],
        fee_schedule[1],
        request_cells.fee,
        request_cells.request_epoch,
        scheme_policy[0],
        scheme_policy[1],
        request_cells.request_time,
        certificates[0],
        certificates[1],
        nonce[0],
        nonce[1],
    ]));
    let credit = hash_site(sponges, region, shape, plan, HashSite::Credit, &request)?;
    check_digest(&credit, digests.map(|digests| digests.credit))?;

    // The chain append and the effect.
    let send_chain = word(slots.send_chain)?;
    let recv_chain = word(slots.recv_chain)?;
    let (chain, effect) = if let Some(checked) = &checked_send {
        let request_digest = pair_at(&words, request_digest.ok_or(Error::Synthesis)?)?;
        let entry = absorb(&[
            send_chain,
            &credit,
            counterparty[0],
            counterparty[1],
            checked.next_send.word(),
            amount.word(),
            checked.fee.word(),
            request_digest[0],
            request_digest[1],
        ]);
        let chain = hash_site(sponges, region, shape, plan, HashSite::Chain, &entry)?;
        let effect = [
            &credit,
            counterparty[0],
            counterparty[1],
            checked.next_send.word(),
            amount.word(),
            checked.fee.word(),
            request_digest[0],
            request_digest[1],
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
        let chain = hash_site(sponges, region, shape, plan, HashSite::Chain, &entry)?;
        let effect = [&credit, counterparty[0], counterparty[1], amount.word()]
            .map(Clone::clone)
            .to_vec();
        (chain, effect)
    };
    check_digest(&chain, digests.map(|digests| digests.chain))?;

    // Predecessor and successor commitments P(kgwcore1, core || rest).
    let rest_digest = word(rest_digest)?;
    let [consumed, pending, load_redeem, fee_claim, quota_usage] = slots.roots;
    let (consumed, pending, load_redeem, fee_claim, quota_usage) = (
        word(consumed)?,
        word(pending)?,
        word(load_redeem)?,
        word(fee_claim)?,
        word(quota_usage)?,
    );
    let next_load = word(slots.next_load)?;
    let next_redeem = word(slots.next_redeem)?;
    let quota_windows_root = word(slots.quota_windows_root)?;
    let blacklist_root = word(slots.blacklist_root)?;
    let lease_expiry = word(slots.lease_expiry)?;
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
        credential[0],
        credential[1],
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
        blacklist_version,
        blacklist_root,
        &issued_at,
        &max_age,
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
        credential[0],
        credential[1],
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
        quota_usage,
        enabled_controls,
        quota_windows_root,
        blacklist_version,
        blacklist_root,
        &issued_at,
        &max_age,
        lease_expiry,
        &policy_epoch,
        &time_floor_after,
        successor_nonce,
    ];
    let predecessor = hash_site(
        sponges,
        region,
        shape,
        plan,
        HashSite::Predecessor,
        &commitment(&predecessor_core, rest_digest),
    )?;
    check_digest(&predecessor, digests.map(|digests| digests.predecessor))?;
    let successor = hash_site(
        sponges,
        region,
        shape,
        plan,
        HashSite::Successor,
        &commitment(&successor_core, rest_digest),
    )?;
    check_digest(&successor, digests.map(|digests| digests.successor))?;

    // The statement digest.
    let pending_in = pending_in.map(word).transpose()?;
    let cells = StatementCells {
        relation_id: pair_at(&words, relation_id)?,
        scheme_id: scheme,
        asset_digest: asset,
        credential_digest: credential,
        lifecycle,
        sequence: sequence_after.word(),
        next_load,
        predecessor: &predecessor,
        successor: &successor,
        enabled_controls,
        lineage_burned_total: checked_send
            .as_ref()
            .map(|checked| checked.burned_in.word()),
        lineage_pending_outgoing_root: pending_in,
        effect: &effect,
    };
    let statement_lane = plan.lane_of(HashSite::Statement);
    let statement = statement_digest(
        sponges.get_mut(statement_lane).ok_or(Error::Synthesis)?,
        region,
        relation.step(),
        &cells,
    )?;
    check_digest(&statement, digests.map(|digests| digests.statement))?;

    let in_circuit = statement
        .value()
        .zip(predecessor.value())
        .zip(successor.value())
        .zip(credit.value())
        .zip(chain.value())
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
