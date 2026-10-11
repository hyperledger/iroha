//! Native confidential transfer and redemption constraints on the pinned RP57 sponge.

use super::super::{
    CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3 as LEAF,
    CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3 as NODE,
    CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3 as NOTE,
    CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3 as NULLIFIER,
    CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3 as OWNER, ConfidentialMerklePathV2,
};
use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value},
};
use iroha_plonk_gadgets::{
    Bit, GlueChip, GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip,
    RunningSumConfig, SpongeChip, SpongeConfig, Word,
};
use zeroize::Zeroize;

/// Transfer, full redemption and redemption with optional change are separate
/// compiled relations, even when two of them have equally sized public columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Transfer,
    Full,
    Change,
}
impl Kind {
    pub(crate) const fn rows(self) -> usize {
        if matches!(self, Self::Full) { 8 } else { 9 }
    }
}

/// Canonical private relation inputs. Raw nonces are mapped to field elements
/// before synthesis, as specified by the note commitment, and never logged.
#[derive(Clone)]
pub(super) struct Input {
    pub(super) present: bool,
    pub(super) amount: u128,
    pub(super) rho: Fp,
    pub(super) diversifier: Fp,
    pub(super) path: ConfidentialMerklePathV2,
}
impl Drop for Input {
    fn drop(&mut self) {
        self.present.zeroize();
        self.amount.zeroize();
        self.rho.zeroize();
        self.diversifier.zeroize();
        self.path.zeroize();
    }
}
#[derive(Clone)]
pub(super) struct Output {
    pub(super) present: bool,
    pub(super) amount: u128,
    pub(super) rho: Fp,
    pub(super) owner: Fp,
}
impl Drop for Output {
    fn drop(&mut self) {
        self.present.zeroize();
        self.amount.zeroize();
        self.rho.zeroize();
        self.owner.zeroize();
    }
}
#[derive(Clone)]
pub(super) struct Opening {
    pub(super) inputs: [Input; 2],
    pub(super) outputs: [Output; 2],
    pub(super) spend: Fp,
    pub(super) asset: Fp,
    pub(super) network: Fp,
}
impl Drop for Opening {
    fn drop(&mut self) {
        self.spend.zeroize();
        self.asset.zeroize();
        self.network.zeroize();
    }
}

#[derive(Clone)]
pub(super) struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    hash: SpongeConfig<Fp>,
    instance: Column<Instance>,
}
impl Config {
    fn configure(meta: &mut ConstraintSystem<Fp>, kind: Kind) -> Self {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let range_column = meta.advice_column();
        let range = RunningSumConfig::configure(meta, range_column, LimbBits::new(8).unwrap());
        let lane = Pow5Columns::allocate(meta);
        let round_constants = RoundConstantColumns::allocate(meta);
        let hash = SpongeConfig::configure(
            meta,
            lane,
            round_constants,
            &[(OWNER, 2), (NOTE, 4), (NULLIFIER, 4), (LEAF, 1), (NODE, 2)],
        );
        let instance = meta.instance_column(kind.rows());
        meta.enable_equality(instance);
        Self {
            glue,
            range,
            hash,
            instance,
        }
    }
}

/// MODE is circuit-fixed: 0 transfer, 1 full redemption, 2 redemption with change.
#[derive(Clone)]
pub(super) struct NativeCircuit<const MODE: u8, const DEPTH: usize> {
    pub(super) opening: Option<Opening>,
}
impl<const MODE: u8, const DEPTH: usize> NativeCircuit<MODE, DEPTH> {
    const fn kind() -> Kind {
        match MODE {
            0 => Kind::Transfer,
            1 => Kind::Full,
            2 => Kind::Change,
            _ => panic!("invalid confidential relation"),
        }
    }
}
impl<const MODE: u8, const DEPTH: usize> Circuit<Fp> for NativeCircuit<MODE, DEPTH> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self { opening: None }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Config::configure(meta, Self::kind())
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut range = RunningSumChip::new(config.range);
        range.load_table(&mut layouter)?;
        let public = layouter.assign_region(
            || "native confidential relation",
            |mut region| {
                let mut chips = Chips {
                    glue: GlueChip::new(config.glue),
                    range: &mut range,
                    hash: SpongeChip::new(config.hash.clone()),
                };
                chips.assign::<DEPTH>(&mut region, Self::kind(), self.opening.as_ref())
            },
        )?;
        for (row, word) in public.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, row)?;
        }
        Ok(())
    }
}

struct Chips<'a> {
    glue: GlueChip<Fp>,
    range: &'a mut RunningSumChip<Fp>,
    hash: SpongeChip<Fp>,
}
struct InputCells {
    present: Bit<Fp>,
    amount: Word<Fp>,
    commitment: Word<Fp>,
    nullifier: Word<Fp>,
}
impl Chips<'_> {
    fn word(&mut self, region: &mut Region<'_, Fp>, value: Option<Fp>) -> Result<Word<Fp>, Error> {
        self.glue
            .witness(region, value.map_or(Value::unknown(), Value::known))
    }
    fn amount(
        &mut self,
        region: &mut Region<'_, Fp>,
        value: Option<u128>,
    ) -> Result<Word<Fp>, Error> {
        let word = self.word(region, value.map(Fp::from_u128))?;
        self.range.range_check(region, &word, 128)?;
        Ok(word)
    }
    fn present(
        &mut self,
        region: &mut Region<'_, Fp>,
        value: Option<bool>,
    ) -> Result<Bit<Fp>, Error> {
        self.glue
            .boolean(region, value.map_or(Value::unknown(), Value::known))
    }
    fn zero(&self, region: &mut Region<'_, Fp>, word: &Word<Fp>) -> Result<(), Error> {
        GlueChip::assert_constant(region, word, Fp::ZERO)
    }
    fn optional_nonzero(
        &mut self,
        region: &mut Region<'_, Fp>,
        word: &Word<Fp>,
        present: &Bit<Fp>,
    ) -> Result<(), Error> {
        let zero = self.glue.is_zero(region, word)?;
        let absent = self.glue.not(region, present)?;
        GlueChip::assert_equal(region, zero.word(), absent.word())
    }
    fn unequal_when(
        &mut self,
        region: &mut Region<'_, Fp>,
        left: &Word<Fp>,
        right: &Word<Fp>,
        present: &Bit<Fp>,
    ) -> Result<(), Error> {
        let equal = self.glue.is_equal(region, left, right)?;
        let selected = self.glue.and(region, &equal, present)?;
        self.zero(region, selected.word())
    }
    fn hash(
        &mut self,
        region: &mut Region<'_, Fp>,
        domain: u64,
        words: &[Word<Fp>],
    ) -> Result<Word<Fp>, Error> {
        self.hash.hash_words(region, domain, words)
    }
    fn input(
        &mut self,
        region: &mut Region<'_, Fp>,
        input: Option<&Input>,
        spend: &Word<Fp>,
        asset: &Word<Fp>,
        network: &Word<Fp>,
        mandatory: bool,
    ) -> Result<InputCells, Error> {
        let present = self.present(region, input.map(|i| i.present))?;
        if mandatory {
            GlueChip::assert_constant(region, present.word(), Fp::ONE)?;
        }
        let amount = self.amount(region, input.map(|i| i.amount))?;
        let rho = self.word(region, input.map(|i| i.rho))?;
        let diversifier = self.word(region, input.map(|i| i.diversifier))?;
        for word in [&amount, &rho, &diversifier] {
            self.optional_nonzero(region, word, &present)?;
        }
        let owner = self.hash(region, OWNER, &[spend.clone(), diversifier])?;
        let commitment = self.hash(
            region,
            NOTE,
            &[amount.clone(), rho.clone(), owner, asset.clone()],
        )?;
        let nullifier = self.hash(
            region,
            NULLIFIER,
            &[spend.clone(), rho, asset.clone(), network.clone()],
        )?;
        if mandatory {
            self.glue.assert_nonzero(region, &commitment)?;
            self.glue.assert_nonzero(region, &nullifier)?;
        }
        Ok(InputCells {
            present,
            amount,
            commitment,
            nullifier,
        })
    }
    fn root<const DEPTH: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        commitment: Word<Fp>,
        path: Option<&ConfidentialMerklePathV2>,
    ) -> Result<Word<Fp>, Error> {
        if path.is_some_and(|p| {
            p.siblings.len() != DEPTH
                || p.directions.len() != DEPTH
                || p.witness_nodes.len() != DEPTH
        }) {
            return Err(Error::Synthesis);
        }
        let decode = |bytes| Option::<Fp>::from(Fp::from_repr(bytes)).ok_or(Error::Synthesis);
        let mut node = self.hash(region, LEAF, &[commitment])?;
        for level in 0..DEPTH {
            let sibling =
                self.word(region, path.map(|p| decode(p.siblings[level])).transpose()?)?;
            let direction_value = path
                .map(|p| match p.directions[level] {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(Error::Synthesis),
                })
                .transpose()?;
            let direction = self.present(region, direction_value)?;
            let left = self.glue.select(region, &direction, &sibling, &node)?;
            let right = self.glue.select(region, &direction, &node, &sibling)?;
            node = self.hash(region, NODE, &[left, right])?;
            let carried = self.word(
                region,
                path.map(|p| decode(p.witness_nodes[level])).transpose()?,
            )?;
            GlueChip::assert_equal(region, &node, &carried)?;
        }
        let carried_root = self.word(region, path.map(|p| decode(p.root)).transpose()?)?;
        GlueChip::assert_equal(region, &node, &carried_root)?;
        Ok(node)
    }
    fn output(
        &mut self,
        region: &mut Region<'_, Fp>,
        output: Option<&Output>,
        asset: &Word<Fp>,
        mandatory: bool,
        owner: Option<&Word<Fp>>,
    ) -> Result<(Bit<Fp>, Word<Fp>, Word<Fp>), Error> {
        let present = self.present(region, output.map(|o| o.present))?;
        if mandatory {
            GlueChip::assert_constant(region, present.word(), Fp::ONE)?;
        }
        let amount = self.amount(region, output.map(|o| o.amount))?;
        let rho = self.word(region, output.map(|o| o.rho))?;
        for word in [&amount, &rho] {
            self.optional_nonzero(region, word, &present)?;
        }
        let owner = match owner {
            Some(owner) => owner.clone(),
            None => {
                let owner = self.word(region, output.map(|o| o.owner))?;
                self.optional_nonzero(region, &owner, &present)?;
                owner
            }
        };
        let commitment = self.hash(region, NOTE, &[amount.clone(), rho, owner, asset.clone()])?;
        if mandatory {
            self.glue.assert_nonzero(region, &commitment)?;
        }
        Ok((present, amount, commitment))
    }
    fn assign<const DEPTH: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        kind: Kind,
        opening: Option<&Opening>,
    ) -> Result<Vec<Word<Fp>>, Error> {
        let spend = self.word(region, opening.map(|w| w.spend))?;
        let asset = self.word(region, opening.map(|w| w.asset))?;
        let network = self.word(region, opening.map(|w| w.network))?;
        for word in [&spend, &asset, &network] {
            self.glue.assert_nonzero(region, word)?;
        }
        let first = self.input(
            region,
            opening.map(|w| &w.inputs[0]),
            &spend,
            &asset,
            &network,
            true,
        )?;
        let second = self.input(
            region,
            opening.map(|w| &w.inputs[1]),
            &spend,
            &asset,
            &network,
            false,
        )?;
        self.unequal_when(region, &first.nullifier, &second.nullifier, &second.present)?;
        let second_commitment = self
            .glue
            .mul(region, second.present.word(), &second.commitment)?;
        let second_nullifier = self
            .glue
            .mul(region, second.present.word(), &second.nullifier)?;
        let root = self.root::<DEPTH>(
            region,
            first.commitment.clone(),
            opening.map(|w| &w.inputs[0].path),
        )?;
        let second_root = self.root::<DEPTH>(
            region,
            second_commitment.clone(),
            opening.map(|w| &w.inputs[1].path),
        )?;
        let delta = self.glue.sub(region, &root, &second_root)?;
        let claimed_delta = self.glue.mul(region, &delta, second.present.word())?;
        self.zero(region, &claimed_delta)?;
        let total = self.glue.add(region, &first.amount, &second.amount)?;
        let mut public = vec![
            first.commitment.clone(),
            second_commitment,
            first.nullifier,
            second_nullifier,
        ];
        match kind {
            Kind::Transfer => {
                let (present0, amount0, output0) =
                    self.output(region, opening.map(|w| &w.outputs[0]), &asset, true, None)?;
                let (present1, amount1, output1) =
                    self.output(region, opening.map(|w| &w.outputs[1]), &asset, false, None)?;
                let output_total = self.glue.add(region, &amount0, &amount1)?;
                GlueChip::assert_equal(region, &total, &output_total)?;
                self.unequal_when(region, &output0, &output1, &present1)?;
                // First output's presence is constrained to one by output().
                GlueChip::assert_constant(region, present0.word(), Fp::ONE)?;
                public.push(output0);
                public.push(self.glue.mul(region, present1.word(), &output1)?);
                public.extend([root, asset, network]);
            }
            Kind::Full => {
                self.range.range_check(region, &total, 128)?;
                self.glue.assert_nonzero(region, &total)?;
                public.extend([root, total, asset, network]);
            }
            Kind::Change => {
                let one = self.glue.constant(region, Fp::ONE)?;
                let owner = self.hash(region, OWNER, &[spend, one])?;
                let (present, amount, output) = self.output(
                    region,
                    opening.map(|w| &w.outputs[0]),
                    &asset,
                    false,
                    Some(&owner),
                )?;
                for input in [&first.commitment, &second.commitment] {
                    self.unequal_when(region, &output, input, &present)?;
                }
                let output = self.glue.mul(region, present.word(), &output)?;
                self.optional_nonzero(region, &output, &present)?;
                let redeemed = self.glue.sub(region, &total, &amount)?;
                self.range.range_check(region, &redeemed, 128)?;
                self.glue.assert_nonzero(region, &redeemed)?;
                public.extend([output, root, redeemed, asset, network]);
            }
        }
        Ok(public)
    }
}
