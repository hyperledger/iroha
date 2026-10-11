//! Authenticated operation maps, OQ-3 burn cases and permanent first records.

use std::collections::BTreeMap;

use super::*;
use iroha_kagemusha_proof::operation_relation::map_effects::{
    ArchiveMapWitness, BLACKLIST_HISTORY_DOMAIN, CONSUMED_DOMAIN, CREDIT_DOMAIN, FEE_DOMAIN,
    InsertCells, LOAD_DOMAIN, MapEffectsChip, MapState, MapTransition, PENDING_DOMAIN,
    REDEEM_DOMAIN, ReceiveMapWitness, RemoveCells, SendMapWitness,
};
use iroha_plonk_gadgets::{
    Word,
    imt::{LEAF_DOMAIN, LeafCells, NODE_DOMAIN, OpeningCells, PathCells},
};
use iroha_plonk_recursion::obligation::{ModeCells, constrain_incoming_modes};

const D: usize = 3;
const MAP_K: u32 = 14;

/// Recompute sparse native levels independently of the circuit path updater.
#[derive(Clone)]
struct Tree<const N: usize = D> {
    slots: BTreeMap<u32, [Fp; 3]>,
}

impl<const N: usize> Tree<N> {
    fn empty() -> Self {
        Self {
            slots: BTreeMap::from([(0, [Fp::ZERO; 3])]),
        }
    }
    fn levels(&self) -> (Vec<BTreeMap<u32, Fp>>, Vec<Fp>) {
        let mut empty = vec![Fp::ZERO];
        let mut levels = vec![
            self.slots
                .iter()
                .map(|(i, leaf)| (*i, hash_with_domain(LEAF_DOMAIN, leaf)))
                .collect::<BTreeMap<_, _>>(),
        ];
        for height in 0..N {
            let mut next = BTreeMap::new();
            for index in levels[height].keys() {
                let left = levels[height]
                    .get(&(index & !1))
                    .copied()
                    .unwrap_or(empty[height]);
                let right = levels[height]
                    .get(&(index | 1))
                    .copied()
                    .unwrap_or(empty[height]);
                next.insert(index >> 1, hash_with_domain(NODE_DOMAIN, &[left, right]));
            }
            empty.push(hash_with_domain(NODE_DOMAIN, &[empty[height]; 2]));
            levels.push(next);
        }
        (levels, empty)
    }
    fn root(&self) -> Fp {
        self.levels().0[N][&0]
    }
    fn path(&self, index: u32) -> Vec<Fp> {
        let (levels, empty) = self.levels();
        let mut path = vec![Fp::from(u64::from(index))];
        for height in 0..N {
            path.push(
                levels[height]
                    .get(&((index >> height) ^ 1))
                    .copied()
                    .unwrap_or(empty[height]),
            );
        }
        path
    }
    fn opening(&self, index: u32) -> Vec<Fp> {
        let mut output = self.slots[&index].to_vec();
        output.extend(self.path(index));
        output
    }
    fn insert(&mut self, low: u32, index: u32, key: Fp, value: Fp) -> Vec<Fp> {
        let mut paths = self.opening(low);
        let next = self.slots[&low][2];
        self.slots.get_mut(&low).expect("low")[2] = key;
        paths.extend(self.path(index));
        self.slots.insert(index, [key, value, next]);
        paths
    }
    fn noop(&self, index: u32) -> Vec<Fp> {
        let mut paths = self.opening(index);
        paths.extend(self.path(index));
        paths
    }
    fn remove(&mut self, predecessor: u32, index: u32) -> Vec<Fp> {
        let mut paths = self.opening(predecessor);
        self.slots.get_mut(&predecessor).expect("predecessor")[2] = self.slots[&index][2];
        paths.extend(self.opening(index));
        self.slots.remove(&index);
        paths
    }
}

#[derive(Clone, Copy, Debug)]
enum ArchiveOwner {
    Both,
    Core,
    Lineage,
}

#[derive(Clone)]
struct MapCircuit<const N: usize = D> {
    split_send: bool,
    archive_owner: ArchiveOwner,
    variant: Variant,
    before: StateCircuit,
    after: StateCircuit,
    fields: [Fp; 26],
    inputs: Vec<Fp>,
    known: bool,
}

fn take_path<const N: usize>(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    words: &[Word<Fp>],
    at: &mut usize,
) -> Result<PathCells<Fp, N>, Error> {
    let result = PathCells::from_words(
        uint,
        region,
        &words[*at],
        ::core::array::from_fn(|i| words[*at + 1 + i].clone()),
    )?;
    *at += N + 1;
    Ok(result)
}
fn take_opening<const N: usize>(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    words: &[Word<Fp>],
    at: &mut usize,
) -> Result<OpeningCells<Fp, N>, Error> {
    let leaf = LeafCells::from_words(::core::array::from_fn(|i| words[*at + i].clone()));
    *at += 3;
    Ok(OpeningCells {
        leaf,
        path: take_path(uint, region, words, at)?,
    })
}
fn take_insert<const N: usize>(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    words: &[Word<Fp>],
    at: &mut usize,
) -> Result<InsertCells<N>, Error> {
    Ok(InsertCells {
        low: take_opening(uint, region, words, at)?,
        slot: take_path(uint, region, words, at)?,
    })
}

fn take_remove<const N: usize>(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    words: &[Word<Fp>],
    at: &mut usize,
) -> Result<RemoveCells<N>, Error> {
    Ok(RemoveCells {
        predecessor: take_opening(uint, region, words, at)?,
        removed: take_opening(uint, region, words, at)?,
    })
}

impl<const N: usize> Circuit<Fp> for MapCircuit<N> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        configure_columns(meta, 64)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        let mut sponge = SpongeChip::new(config.sponge);
        range.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "operation map effects",
            |mut region| {
                let values: Vec<_> = self
                    .fields
                    .iter()
                    .chain(&self.inputs)
                    .map(|f| {
                        if self.known {
                            Value::known(*f)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect();
                let words = glue.witnesses(&mut region, &values)?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let statement = StatementCells::constrain(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    self.variant,
                    &::core::array::from_fn(|i| words[i].clone()),
                )?;
                let (before, previous) = assign_state(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    &self.before,
                    self.known,
                )?;
                let (after, lineage) =
                    assign_state(&mut uint, &mut sponge, &mut region, &self.after, self.known)?;
                let transition = MapTransition {
                    statement: &statement,
                    predecessor: MapState {
                        state: &before,
                        lineage: &previous,
                    },
                    successor: MapState {
                        state: &after,
                        lineage: &lineage,
                    },
                };
                let inputs = &words[26..];
                if self.variant == Variant::Send {
                    let mut at = 1;
                    let witness = SendMapWitness {
                        fee_schedule: inputs[0].clone(),
                        pending: take_insert::<N>(&mut uint, &mut region, inputs, &mut at)?,
                        fee: take_insert::<N>(&mut uint, &mut region, inputs, &mut at)?,
                    };
                    assert_eq!(at, inputs.len());
                    let mut maps = MapEffectsChip::new(&mut glue, &mut range, &mut sponge);
                    if self.split_send {
                        maps.send_pending(&mut region, &transition, &witness.pending)?;
                        maps.send_fee_and_unchanged(
                            &mut region,
                            &transition,
                            &witness.fee,
                            &witness.fee_schedule,
                        )?;
                    } else {
                        maps.send(&mut region, &transition, &witness)?;
                    }
                } else if self.variant == Variant::RefreshBlacklist {
                    let mut at = 3;
                    let insertion = take_insert::<N>(&mut uint, &mut region, inputs, &mut at)?;
                    let lookup = take_opening::<N>(&mut uint, &mut region, inputs, &mut at)?;
                    assert_eq!(at, inputs.len());
                    let mut maps = MapEffectsChip::new(&mut glue, &mut range, &mut sponge);
                    maps.refresh_blacklist(&mut region, &transition, &insertion)?;
                    // A later Receive consults the history after this refresh.
                    let verdict = maps.recorded_blacklist(
                        &mut region,
                        &after,
                        &inputs[1],
                        &inputs[2],
                        &lookup,
                    )?;
                    GlueChip::assert_equal(&mut region, verdict.word(), &inputs[0])?;
                } else if matches!(self.variant, Variant::Load | Variant::Unload) {
                    let mut at = 1;
                    let witness = take_insert::<N>(&mut uint, &mut region, inputs, &mut at)?;
                    assert_eq!(at, inputs.len());
                    MapEffectsChip::new(&mut glue, &mut range, &mut sponge).recovery(
                        &mut region,
                        &transition,
                        &witness,
                    )?;
                } else if matches!(
                    self.variant,
                    Variant::ArchiveReceive | Variant::ArchiveStatus
                ) {
                    let valid = uint.glue().assert_bool(&mut region, &inputs[7])?;
                    let mut at = 8;
                    let witness = ArchiveMapWitness {
                        descriptor: ::core::array::from_fn(|i| inputs[i].clone()),
                        core: take_remove::<N>(&mut uint, &mut region, inputs, &mut at)?,
                        lineage: take_remove::<N>(&mut uint, &mut region, inputs, &mut at)?,
                    };
                    assert_eq!(at, inputs.len());
                    let mut maps = MapEffectsChip::new(&mut glue, &mut range, &mut sponge);
                    match self.archive_owner {
                        ArchiveOwner::Both => {
                            maps.archive(&mut region, &transition, &witness, &valid)?
                        }
                        ArchiveOwner::Core => maps.archive_core_pending(
                            &mut region,
                            &transition,
                            &witness.descriptor,
                            &witness.core,
                        )?,
                        ArchiveOwner::Lineage => maps.archive_lineage_pending(
                            &mut region,
                            &transition,
                            &witness.descriptor,
                            &witness.lineage,
                            &valid,
                        )?,
                    }
                } else {
                    let insert = uint.glue().assert_bool(&mut region, &inputs[3])?;
                    let other_soft = uint.glue().assert_bool(&mut region, &inputs[4])?;
                    let modes = ModeCells::constrain(
                        uint.glue(),
                        &mut region,
                        &::core::array::from_fn(|i| inputs[5 + i].clone()),
                    )?;
                    let mut at = 8;
                    let search = take_opening::<N>(&mut uint, &mut region, inputs, &mut at)?;
                    let witness = ReceiveMapWitness {
                        payment_digest: inputs[0].clone(),
                        inserted_key: inputs[1].clone(),
                        inserted_value: inputs[2].clone(),
                        insert,
                        consumed: take_insert::<N>(&mut uint, &mut region, inputs, &mut at)?,
                        credit: take_insert::<N>(&mut uint, &mut region, inputs, &mut at)?,
                    };
                    assert_eq!(at, inputs.len());
                    let absent = MapEffectsChip::new(&mut glue, &mut range, &mut sponge)
                        .receive_nonmembership(&mut region, &transition, &search)?;
                    let valid = constrain_incoming_modes(
                        &mut glue,
                        &mut region,
                        &[absent, other_soft],
                        &[modes],
                    )?;
                    MapEffectsChip::new(&mut glue, &mut range, &mut sponge).receive(
                        &mut region,
                        &transition,
                        &witness,
                        &valid,
                    )?;
                }
                let mut output = previous.fields().to_vec();
                output.extend_from_slice(lineage.fields());
                output.extend_from_slice(statement.fields());
                output.push(inputs[0].clone());
                output.push(statement.digest().clone());
                Ok(output)
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

impl<const N: usize> MapCircuit<N> {
    fn new(variant: Variant) -> Self {
        let mut before = basic();
        before.core[core::SEQUENCE] = Fp::from(4);
        before.core[core::BALANCE] = Fp::from(200);
        for index in 16..=20 {
            before.core[index] = Tree::<N>::empty().root();
        }
        before.lineage[14] = Fp::from(5);
        before.lineage[15] = Tree::<N>::empty().root();
        before.lineage[16] = Tree::<N>::empty().root();
        let mut after = before.clone();
        after.core[core::SEQUENCE] += Fp::ONE;
        Self {
            split_send: false,
            archive_owner: ArchiveOwner::Both,
            variant,
            before,
            after,
            fields: [Fp::ZERO; 26],
            inputs: vec![],
            known: true,
        }
    }
    fn rebind(&mut self) {
        self.before.rebind();
        self.after.rebind();
        self.fields[0] = Fp::ONE;
        self.fields[1..3].copy_from_slice(&self.after.lineage[3..5]);
        self.fields[3..7].copy_from_slice(&self.after.core[core::SCHEME..core::WALLET]);
        self.fields[7] = self.after.core[core::CREDENTIAL];
        self.fields[8] = self.after.core[core::LIFECYCLE];
        self.fields[9] = self.after.core[core::SEQUENCE];
        self.fields[10] = self.after.core[core::NEXT_LOAD];
        self.fields[11] = self.before.core[core::ENABLED_CONTROLS];
        if matches!(
            self.variant,
            Variant::Send | Variant::Unload | Variant::Retiring
        ) {
            self.fields[12] = self.before.lineage[14];
            self.fields[13] = self.before.lineage[15];
        }
        self.fields[14] = self.before.lineage[5];
        self.fields[15] = self.after.lineage[5];
    }
    fn public(&self) -> Vec<Fp> {
        let mut public = self.before.lineage.to_vec();
        public.extend(self.after.lineage);
        public.extend(self.fields);
        public.push(self.inputs[0]);
        public.push(hash_with_domain(STATEMENT_DOMAIN, &self.fields));
        public
    }
    fn accepts(&self) -> bool {
        check_circuit(
            self,
            if N == D { MAP_K } else { 16 },
            &[self.public()],
            CheckMode::Strict,
        )
        .is_ok_and(|r| r.is_satisfied())
    }
    fn assert_accept(&self) {
        let result = check_circuit(
            self,
            if N == D { MAP_K } else { 16 },
            &[self.public()],
            CheckMode::Strict,
        )
        .expect("layout");
        assert!(result.is_satisfied(), "{result:?}");
    }
    fn reject_rebound(&mut self) {
        self.rebind();
        assert!(!self.accepts());
    }
}

fn send_depth<const N: usize>(fee: u64) -> MapCircuit<N> {
    let mut result = MapCircuit::<N>::new(Variant::Send);
    result.fields[16] = Fp::from(3);
    for (i, value) in [20, 2, 3, 0, 12, fee, 77, 0, 0].into_iter().enumerate() {
        result.fields[17 + i] = Fp::from(value);
    }
    let descriptor = hash_with_domain(PENDING_DOMAIN, &result.fields[17..24]);
    let mut pending = Tree::<N>::empty();
    // A prior invalid Archive left a lineage leaf absent from the core.
    pending.insert(0, 1, Fp::from(30), Fp::from(99));
    result.before.lineage[15] = pending.root();
    let paths = pending.insert(0, 2, Fp::from(20), descriptor);
    result.after.core[core::PENDING_OUTGOING_ROOT] = pending.root();
    result.after.lineage[15] = pending.root();
    result.after.core[core::BURNED_TOTAL] = result.before.lineage[14];
    let schedule = Fp::from(88);
    let mut fees = Tree::<N>::empty();
    let fee_paths = if fee == 0 {
        fees.noop(0)
    } else {
        fees.insert(
            0,
            1,
            Fp::from(20),
            hash_with_domain(FEE_DOMAIN, &[Fp::from(20), Fp::from(fee), schedule]),
        )
    };
    result.after.core[core::FEE_CLAIM_ROOT] = fees.root();
    result.inputs = vec![schedule];
    result.inputs.extend(paths);
    result.inputs.extend(fee_paths);
    result.rebind();
    result
}

fn receive_depth<const N: usize>(duplicate: bool, other_soft: bool, insert: bool) -> MapCircuit<N> {
    let mut result = MapCircuit::<N>::new(Variant::Receive);
    result.fields[16] = Fp::from(4);
    result.fields[17..21].copy_from_slice(&[Fp::from(20), Fp::from(2), Fp::from(3), Fp::from(12)]);
    let valid = !duplicate && other_soft;
    let mut consumed = Tree::<N>::empty();
    let mut credits = Tree::<N>::empty();
    if duplicate {
        consumed.insert(0, 1, Fp::from(20), Fp::from(77));
        credits.insert(
            0,
            1,
            Fp::from(20),
            hash_with_domain(CREDIT_DOMAIN, &[Fp::from(20), Fp::from(77), Fp::ZERO]),
        );
    }
    result.before.core[core::CONSUMED_CREDIT_ROOT] = consumed.root();
    result.before.lineage[16] = credits.root();
    let search = consumed.opening(u32::from(duplicate));
    let key = Fp::from(if valid || !duplicate { 20 } else { 30 });
    let value = hash_with_domain(CONSUMED_DOMAIN, &[key, Fp::from(12), Fp::from(5)]);
    let paths = if insert {
        consumed.insert(
            u32::from(duplicate),
            if duplicate { 2 } else { 1 },
            key,
            value,
        )
    } else {
        consumed.noop(0)
    };
    result.after.core[core::CONSUMED_CREDIT_ROOT] = consumed.root();
    let credit_paths = if duplicate {
        credits.noop(1)
    } else {
        credits.insert(
            0,
            1,
            Fp::from(20),
            hash_with_domain(
                CREDIT_DOMAIN,
                &[Fp::from(20), Fp::from(88), Fp::from(u64::from(!valid))],
            ),
        )
    };
    result.after.lineage[16] = credits.root();
    if !valid {
        result.after.lineage[14] += Fp::from(12);
    }
    result.inputs = vec![
        Fp::from(88),
        key,
        value,
        Fp::from(u64::from(insert)),
        Fp::from(u64::from(other_soft)),
        Fp::from(u64::from(valid)),
        Fp::from(u64::from(!valid)),
        Fp::ZERO,
    ];
    result.inputs.extend(search);
    result.inputs.extend(paths);
    result.inputs.extend(credit_paths);
    result.rebind();
    result
}

fn send(fee: u64) -> MapCircuit {
    send_depth::<D>(fee)
}
fn archive_depth<const N: usize>(variant: Variant, valid: bool) -> MapCircuit<N> {
    let mut result = MapCircuit::new(variant);
    result.fields[16] = Fp::from(5);
    result.fields[17] = Fp::from(20);
    result.fields[18] = Fp::from(99);
    let descriptor = [20, 2, 3, 0, 12, 3, 77].map(Fp::from);
    let value = hash_with_domain(PENDING_DOMAIN, &descriptor);
    let mut pending = Tree::<N>::empty();
    pending.insert(0, 1, Fp::from(20), value);
    let mut adjusted = pending.clone();
    adjusted.insert(1, 2, Fp::from(30), Fp::from(99));
    result.before.core[core::PENDING_OUTGOING_ROOT] = pending.root();
    result.before.lineage[15] = adjusted.root();
    let core_paths = pending.remove(0, 1);
    let lineage_paths = adjusted.remove(0, 1);
    result.after.core[core::PENDING_OUTGOING_ROOT] = pending.root();
    result.after.lineage[15] = if valid {
        adjusted.root()
    } else {
        result.before.lineage[15]
    };
    result.inputs = descriptor.to_vec();
    result.inputs.push(Fp::from(u64::from(valid)));
    result.inputs.extend(core_paths);
    result.inputs.extend(lineage_paths);
    result.rebind();
    result
}
fn receive(duplicate: bool, other_soft: bool, insert: bool) -> MapCircuit {
    receive_depth::<D>(duplicate, other_soft, insert)
}

fn recovery_depth<const N: usize>(variant: Variant, charge: u64) -> MapCircuit<N> {
    use iroha_kagemusha_proof::operation_relation::administrative::NULLIFIER_DOMAIN;
    let mut c = MapCircuit::<N>::new(variant);
    let ordinal = Fp::from(2);
    c.before.core[core::NEXT_LOAD] = ordinal;
    c.before.core[core::NEXT_REDEEM] = ordinal;
    c.after.core[core::NEXT_LOAD] = ordinal;
    c.after.core[core::NEXT_REDEEM] = ordinal;
    c.fields[16] = Fp::from(if variant == Variant::Load { 2 } else { 6 });
    c.fields[17] = Fp::from(77);
    c.fields[18] = ordinal;
    c.fields[19] = Fp::from(12);
    c.fields[20] = Fp::from(charge);
    let kind = if variant == Variant::Load {
        c.after.core[core::BALANCE] += Fp::from(12);
        c.after.core[core::NEXT_LOAD] += Fp::ONE;
        1_u64
    } else {
        c.fields[17] = hash_with_domain(
            NULLIFIER_DOMAIN,
            &[
                c.before.core[core::SCHEME],
                c.before.core[core::SCHEME + 1],
                c.before.core[core::WALLET],
                c.before.core[core::WALLET + 1],
                ordinal,
            ],
        );
        c.fields[21] = if charge == 0 { Fp::ZERO } else { Fp::from(88) };
        c.after.core[core::BALANCE] -= Fp::from(12);
        c.after.core[core::NEXT_REDEEM] += Fp::ONE;
        c.after.core[core::BURNED_TOTAL] = c.before.lineage[14];
        c.after.core[core::PENDING_OUTGOING_ROOT] = c.before.lineage[15];
        2_u64
    };
    let two_to_128 = Fp::from_u128(1_u128 << 127).double();
    let key = Fp::from(kind) * two_to_128 + ordinal;
    let mut preimage = vec![ordinal, c.fields[17], c.fields[19]];
    if kind == 2 {
        preimage.push(c.fields[20]);
    }
    let value = hash_with_domain(
        if kind == 1 {
            LOAD_DOMAIN
        } else {
            REDEEM_DOMAIN
        },
        &preimage,
    );
    let mut tree = Tree::<N>::empty();
    // A different recovery kind at the same ordinal is a different key.
    tree.insert(
        0,
        1,
        Fp::from(3 - kind) * two_to_128 + ordinal,
        Fp::from(111),
    );
    c.before.core[core::LOAD_REDEEM_ROOT] = tree.root();
    let paths = tree.insert(u32::from(kind != 1), 2, key, value);
    c.after.core[core::LOAD_REDEEM_ROOT] = tree.root();
    c.inputs = vec![Fp::ZERO];
    c.inputs.extend(paths);
    c.rebind();
    c
}

#[test]
fn send_exact_pending_fee_and_adjusted_roots() {
    for (fee, split_send) in [(0, false), (3, false), (0, true), (3, true)] {
        let mut c = send(fee);
        c.split_send = split_send;
        c.assert_accept();
        for index in [
            core::CONSUMED_CREDIT_ROOT,
            core::PENDING_OUTGOING_ROOT,
            core::LOAD_REDEEM_ROOT,
            core::FEE_CLAIM_ROOT,
            core::BURNED_TOTAL,
        ] {
            let mut wrong = c.clone();
            wrong.after.core[index] += Fp::ONE;
            wrong.reject_rebound();
        }
        for index in [14, 15, 16] {
            let mut wrong = c.clone();
            wrong.after.lineage[index] += Fp::ONE;
            wrong.reject_rebound();
        }
        for index in 17..24 {
            let mut wrong = c.clone();
            wrong.fields[index] += Fp::ONE;
            assert!(!wrong.accepts());
        }
        let mut wrong_base = c.clone();
        wrong_base.before.lineage[15] = wrong_base.before.core[core::PENDING_OUTGOING_ROOT];
        wrong_base.reject_rebound();
        if fee != 0 {
            let mut schedule = c.clone();
            schedule.inputs[0] += Fp::ONE;
            assert!(!schedule.accepts());
            schedule.inputs[0] = Fp::ZERO;
            assert!(!schedule.accepts());
        }
    }
}

#[test]
fn receive_accept_burn_duplicate_and_first_record() {
    for (duplicate, other_soft, insert) in [
        (false, true, true),
        (false, false, true),
        (false, false, false),
        (true, true, false),
        (true, true, true),
        (true, false, false),
    ] {
        let c = receive(duplicate, other_soft, insert);
        c.assert_accept();
        for index in [
            core::CONSUMED_CREDIT_ROOT,
            core::PENDING_OUTGOING_ROOT,
            core::LOAD_REDEEM_ROOT,
            core::FEE_CLAIM_ROOT,
            core::BURNED_TOTAL,
        ] {
            let mut wrong = c.clone();
            wrong.after.core[index] += Fp::ONE;
            wrong.reject_rebound();
        }
        for index in [14, 15, 16] {
            let mut wrong = c.clone();
            wrong.after.lineage[index] += Fp::ONE;
            wrong.reject_rebound();
        }
        if duplicate {
            // The same first record survives a different incoming Payment.
            let mut another = c.clone();
            another.inputs[0] += Fp::ONE;
            another.assert_accept();
            let mut overwritten = c.clone();
            let mut tree = Tree::<D>::empty();
            tree.insert(
                0,
                1,
                Fp::from(20),
                hash_with_domain(CREDIT_DOMAIN, &[Fp::from(20), Fp::from(88), Fp::ONE]),
            );
            overwritten.after.lineage[16] = tree.root();
            overwritten.reject_rebound();
        } else {
            let mut another = c.clone();
            another.inputs[0] += Fp::ONE;
            assert!(!another.accepts());
        }
    }
    assert!(
        !receive(false, true, false).accepts(),
        "accept cannot select no-op"
    );
    let mut wrong_key = receive(false, true, true);
    wrong_key.inputs[1] += Fp::ONE;
    assert!(!wrong_key.accepts());
    let mut wrong_value = receive(false, true, true);
    wrong_value.inputs[2] += Fp::ONE;
    assert!(!wrong_value.accepts());
}

#[test]
fn authenticated_routes_fixed_layout_and_burn_overflow() {
    for case in 0..5 {
        let c = match case {
            0 => send(0),
            1 => send(3),
            2 => receive(false, true, true),
            3 => receive(false, false, false),
            _ => receive(true, true, true),
        };
        let known = synthesize(&c, MAP_K, Some(&[c.public()])).expect("known");
        let unknown = synthesize(&c.without_witnesses(), MAP_K, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        for i in (if c.variant == Variant::Send { 1 } else { 8 })..c.inputs.len() {
            let mut wrong = c.clone();
            wrong.inputs[i] += Fp::ONE;
            assert!(!wrong.accepts(), "input {i}");
        }
    }
    let mut overflow = receive(false, false, true);
    overflow.before.lineage[14] = Fp::from_u128(u128::MAX);
    overflow.after.lineage[14] = Fp::from(11);
    overflow.reject_rebound();
    // True membership cannot be turned into absence using the sentinel.
    let mut bad_route = receive(true, true, false);
    let mut tree = Tree::<D>::empty();
    tree.insert(0, 1, Fp::from(20), Fp::from(77));
    bad_route.inputs[8..8 + 4 + D].copy_from_slice(&tree.opening(0));
    assert!(!bad_route.accepts());
}

#[test]
fn production_depth_send_and_receive_maps_fit_k16() {
    for case in 0..6 {
        let c = match case {
            0 => send_depth::<32>(3),
            1 => receive_depth::<32>(false, true, true),
            2 => receive_depth::<32>(true, true, false),
            3 => archive_depth::<32>(Variant::ArchiveStatus, false),
            4 => recovery_depth::<32>(Variant::Unload, 3),
            _ => blacklist_depth::<32>(1, 81),
        };
        c.assert_accept();
        let layout = synthesize(&c, 16, Some(&[c.public()])).expect("production depth");
        let rows: Vec<_> = layout
            .tables
            .advice_assigned()
            .iter()
            .map(|column| column.iter().rposition(|used| *used).map_or(0, |i| i + 1))
            .collect();
        eprintln!("production map {:?} rows={rows:?}", c.variant);
        let mut forged = c.clone();
        let last = forged.inputs.len() - 1;
        forged.inputs[last] += Fp::ONE;
        assert!(!forged.accepts());
    }
}

#[test]
fn archive_clears_core_and_only_valid_evidence_clears_lineage() {
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        for valid in [true, false] {
            let c = archive_depth::<D>(variant, valid);
            c.assert_accept();
            for index in 0..CORE_FIELDS {
                if index == core::STATE_NONCE {
                    continue;
                }
                let mut wrong = c.clone();
                wrong.after.core[index] += Fp::ONE;
                wrong.reject_rebound();
            }
            for index in 0..REST_FIELDS {
                let mut wrong = c.clone();
                wrong.after.rest[index] += Fp::ONE;
                wrong.reject_rebound();
            }
            for index in [14, 15, 16] {
                let mut wrong = c.clone();
                wrong.after.lineage[index] += Fp::ONE;
                wrong.reject_rebound();
            }
            let mut uncleared = c.clone();
            uncleared.after.core[core::PENDING_OUTGOING_ROOT] =
                uncleared.before.core[core::PENDING_OUTGOING_ROOT];
            uncleared.reject_rebound();
            for i in 0..c.inputs.len() {
                let mut wrong = c.clone();
                wrong.inputs[i] += Fp::ONE;
                assert!(!wrong.accepts(), "{variant:?} {valid} input{i}");
            }
        }
    }
}

#[test]
fn archive_separate_owners_authenticate_descriptor_paths_and_exact_roots() {
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        for valid in [true, false] {
            for owner in [ArchiveOwner::Core, ArchiveOwner::Lineage] {
                let mut c = archive_depth::<D>(variant, valid);
                c.archive_owner = owner;
                c.assert_accept();
                let path_start = match owner {
                    ArchiveOwner::Core => 8,
                    ArchiveOwner::Lineage => 8 + 2 * (D + 4),
                    ArchiveOwner::Both => unreachable!(),
                };
                // Every descriptor word and both openings of this owner bind,
                // including the adjusted path when valid is false.
                for i in (0..7).chain(path_start..path_start + 2 * (D + 4)) {
                    let mut wrong = c.clone();
                    wrong.inputs[i] += Fp::ONE;
                    assert!(
                        !wrong.accepts(),
                        "{variant:?} {owner:?} valid={valid} input={i}"
                    );
                }
                let mut root = c.clone();
                match owner {
                    ArchiveOwner::Core => root.after.core[core::PENDING_OUTGOING_ROOT] += Fp::ONE,
                    ArchiveOwner::Lineage => root.after.lineage[15] += Fp::ONE,
                    ArchiveOwner::Both => unreachable!(),
                }
                root.reject_rebound();
                let mut old_root = c.clone();
                match owner {
                    ArchiveOwner::Core => {
                        old_root.before.core[core::PENDING_OUTGOING_ROOT] += Fp::ONE
                    }
                    ArchiveOwner::Lineage => old_root.before.lineage[15] += Fp::ONE,
                    ArchiveOwner::Both => unreachable!(),
                }
                old_root.reject_rebound();
                let mut credit = c.clone();
                credit.fields[17] += Fp::ONE;
                assert!(!credit.accepts());
                if matches!(owner, ArchiveOwner::Lineage) {
                    let mut mode = c.clone();
                    mode.inputs[7] = Fp::from(u64::from(!valid));
                    assert!(!mode.accepts());
                    let mut policy = c.clone();
                    policy.after.rest[rest::PERMITTED] = Fp::from(7);
                    policy.reject_rebound();
                }
            }
        }
    }
}

#[test]
fn archive_separate_production_owners_fit_and_have_fixed_unknown_layouts() {
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        for owner in [ArchiveOwner::Core, ArchiveOwner::Lineage] {
            let mut c = archive_depth::<32>(variant, false);
            c.archive_owner = owner;
            c.assert_accept();
            let known = synthesize(&c, 16, Some(&[c.public()])).expect("known map owner");
            let unknown = synthesize(&c.without_witnesses(), 16, None).expect("unknown map owner");
            assert_eq!(known.tables.fixed(), unknown.tables.fixed());
            assert_eq!(known.tables.selectors(), unknown.tables.selectors());
            assert_eq!(known.tables.permutation(), unknown.tables.permutation());
            assert_eq!(
                known.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
            let max_rows = known
                .tables
                .advice_assigned()
                .iter()
                .map(|column| column.iter().rposition(|used| *used).map_or(0, |i| i + 1))
                .max()
                .expect("advice lanes");
            eprintln!(
                "ARCHIVE_MAP_OWNER variant={variant:?} owner={owner:?} max_rows={max_rows} depth=32 known_unknown_equal=true full_chain_qualified=false"
            );
            assert!(max_rows <= 65_529);
        }
    }
}

#[test]
fn archive_cannot_change_credential_counters_or_held_policy() {
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        for valid in [true, false] {
            let c = archive_depth::<D>(variant, valid);
            for index in [
                core::CREDENTIAL,
                core::NEXT_SEND,
                core::NEXT_LOAD,
                core::NEXT_REDEEM,
            ] {
                let mut wrong = c.clone();
                wrong.after.core[index] += Fp::ONE;
                wrong.reject_rebound();
            }
            let mut wrong = c.clone();
            wrong.after.rest[rest::PERMITTED] = Fp::from(7);
            wrong.reject_rebound();
        }
    }
}

#[test]
fn recovery_map_binds_kind_ordinal_value_and_charge() {
    for variant in [Variant::Load, Variant::Unload] {
        for charge in [0, 3] {
            let c = recovery_depth::<D>(variant, charge);
            c.assert_accept();
            let mut root = c.clone();
            root.after.core[core::LOAD_REDEEM_ROOT] = root.before.core[core::LOAD_REDEEM_ROOT];
            root.reject_rebound();
            for index in 17..20 {
                let mut wrong = c.clone();
                wrong.fields[index] += Fp::ONE;
                assert!(!wrong.accepts());
            }
            if variant == Variant::Unload {
                let mut wrong = c.clone();
                wrong.fields[20] = Fp::from(2);
                wrong.fields[21] = Fp::from(88);
                assert!(!wrong.accepts());
            }
            for index in 1..c.inputs.len() {
                let mut wrong = c.clone();
                wrong.inputs[index] += Fp::ONE;
                assert!(!wrong.accepts(), "{variant:?} path{index}");
            }
        }
    }
}

fn blacklist_depth<const N: usize>(recorded: u64, root: u64) -> MapCircuit<N> {
    let mut c = MapCircuit::<N>::new(Variant::RefreshBlacklist);
    let mut tree = Tree::<N>::empty();
    let first = hash_with_domain(BLACKLIST_HISTORY_DOMAIN, &[Fp::ONE, Fp::from(81)]);
    tree.insert(0, 1, Fp::ONE, first);
    c.before.rest[rest::BLACKLIST_HISTORY] = tree.root();
    c.before.rest[rest::BLACKLIST] = Fp::from(71);
    c.before.core[core::BLACKLIST_VERSION] = Fp::ONE;
    c.before.core[core::BLACKLIST_ROOT] = Fp::from(81);
    c.after.rest[rest::BLACKLIST] = Fp::from(72);
    c.after.core[core::BLACKLIST_VERSION] = Fp::from(2);
    c.after.core[core::BLACKLIST_ROOT] = Fp::from(82);
    let second = hash_with_domain(BLACKLIST_HISTORY_DOMAIN, &[Fp::from(2), Fp::from(82)]);
    let paths = tree.insert(1, 2, Fp::from(2), second);
    c.after.rest[rest::BLACKLIST_HISTORY] = tree.root();
    c.fields[16] = Fp::from(7);
    c.fields[17] = Fp::from(3);
    c.fields[18] = Fp::from(72);
    let valid = matches!((recorded, root), (1, 81) | (2, 82));
    c.inputs = vec![
        Fp::from(u64::from(valid)),
        Fp::from(recorded),
        Fp::from(root),
    ];
    c.inputs.extend(paths);
    c.inputs
        .extend(tree.opening(if recorded == 1 { 1 } else { 2 }));
    c.rebind();
    c
}

#[test]
fn blacklist_history_retains_recorded_pairs_and_authenticates_soft_failure() {
    for (version, root) in [(1, 81), (2, 82), (1, 82), (3, 83)] {
        let c = blacklist_depth::<D>(version, root);
        c.assert_accept();
        let mut inverted = c.clone();
        inverted.inputs[0] = Fp::ONE - inverted.inputs[0];
        assert!(!inverted.accepts());
        for i in 3..c.inputs.len() {
            let mut bad = c.clone();
            bad.inputs[i] += Fp::ONE;
            assert!(!bad.accepts(), "path {version} {root} {i}");
        }
        let mut changed = c.clone();
        changed.after.rest[rest::BLACKLIST_HISTORY] += Fp::ONE;
        changed.reject_rebound();
    }
    let mut duplicate = blacklist_depth::<D>(1, 81);
    duplicate.after.core[core::BLACKLIST_VERSION] = Fp::ONE;
    duplicate.reject_rebound();
    let mut no_version = blacklist_depth::<D>(1, 81);
    no_version.inputs[1] = Fp::ZERO;
    assert!(!no_version.accepts());
    let mut wide = blacklist_depth::<D>(1, 81);
    wide.inputs[1] = Fp::from_u128(1 << 64);
    assert!(!wide.accepts());
    let mut no_root = blacklist_depth::<D>(1, 81);
    no_root.inputs[2] = Fp::ZERO;
    assert!(!no_root.accepts());
}
