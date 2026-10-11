//! Exact ordinary Load receipt transcript bound to the native-authorized Advance.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    GlueChip, U64, U128, UintChip, Word, WordHasher,
    bytes::{
        PBytes, chunk_segments,
        element::{le_max, modulus_max},
        tape::{ByteRun, SegmentSpec},
    },
};

/// Structurally valid ordinary Load terms and their exact packed-byte identity.
/// The type conveys no certificate verification, inclusion or spend authority.
#[derive(Clone, Debug)]
pub struct LoadReceiptCells {
    scheme: [Word<Fp>; 2],
    asset: [Word<Fp>; 2],
    wallet: [Word<Fp>; 2],
    request: [Word<Fp>; 2],
    ordinal: U128<Fp>,
    amount: U128<Fp>,
    online_charge: U128<Fp>,
    charge_quote: Word<Fp>,
    transaction: [Word<Fp>; 2],
    height: U64<Fp>,
    payer: [Word<Fp>; 2],
    digest: Word<Fp>,
}

impl LoadReceiptCells {
    /// Exact transcript byte count, including the canonical payer account digest.
    pub const BYTES: usize = 282;
    /// Native `P_bytes` domain `kgwolod1`.
    pub const DOMAIN: u64 = u64::from_le_bytes(*b"kgwolod1");

    /// Complete primary chunks of the original transcript, independent of witness data.
    #[must_use]
    pub fn primary_segments() -> Vec<usize> {
        chunk_segments(0, Self::BYTES)
    }

    /// Exact little-endian term views on the same original transcript.
    #[must_use]
    pub fn secondary_segments() -> Vec<SegmentSpec> {
        let mut segments = vec![SegmentSpec::little(0, 2)];
        for offset in [2, 34, 66, 98, 178, 210, 250] {
            segments.push(SegmentSpec::little(offset, 16));
            segments.push(SegmentSpec::little(offset + 16, 16));
        }
        for offset in [130, 146, 162] {
            segments.push(SegmentSpec::little(offset, 16));
        }
        segments.push(SegmentSpec::little(242, 8));
        segments.sort_by_key(|segment| segment.start);
        segments
    }

    /// Constrain the exact native shape, amount/debit/ordinal bounds and quote rules.
    /// Every exported field and the digest use the same byte tape. A canonical field
    /// encoding is proved before recomposing the quote; modular aliases cannot pass.
    ///
    /// # Errors
    /// Returns layout errors or a wrong transcript shape. Malformed terms produce
    /// unsatisfied constraints, without a witness-dependent host acceptance branch.
    pub fn from_run(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
    ) -> Result<Self, Error> {
        if run.len() != Self::BYTES {
            return Err(Error::Synthesis);
        }
        let part = |offset, length| {
            run.secondary_segment(SegmentSpec::little(offset, length))
                .map(|segment| segment.word().clone())
        };
        GlueChip::assert_constant(region, &part(0, 2)?, Fp::ONE)?;
        let identity = |offset| Ok::<_, Error>([part(offset, 16)?, part(offset + 16, 16)?]);
        let scheme = identity(2)?;
        let asset = identity(34)?;
        let wallet = identity(66)?;
        let request = identity(98)?;
        let transaction = identity(210)?;
        for id in [&scheme, &asset, &wallet, &request, &transaction] {
            // Both halves are bounded by their tape segments, so their sum cannot
            // wrap in Fp and is zero exactly when both halves are zero.
            let sum = uint.glue().add(region, &id[0], &id[1])?;
            uint.glue().assert_nonzero(region, &sum)?;
        }
        let ordinal = uint.range_check::<128>(region, &part(130, 16)?)?;
        let amount = uint.range_check::<128>(region, &part(146, 16)?)?;
        let online_charge = uint.range_check::<128>(region, &part(162, 16)?)?;
        uint.checked_add_constant(region, &ordinal, 1)?;
        uint.assert_nonzero(region, &amount)?;
        uint.checked_add(region, &amount, &online_charge)?;
        let quote_low = uint.range_check::<128>(region, &part(178, 16)?)?;
        let quote_high = uint.range_check::<128>(region, &part(194, 16)?)?;
        let canonical_quote = le_max(uint, region, &quote_low, &quote_high, modulus_max::<Fp>())?;
        GlueChip::assert_constant(region, canonical_quote.word(), Fp::ONE)?;
        let charge_quote = uint.glue().linear(
            region,
            &[
                (Fp::ONE, quote_low.word()),
                (Fp::from_u128(1_u128 << 127).double(), quote_high.word()),
            ],
            Fp::ZERO,
        )?;
        let charge_zero = uint.glue().is_zero(region, online_charge.word())?;
        let quote_zero = uint.glue().is_zero(region, &charge_quote)?;
        GlueChip::assert_equal(region, charge_zero.word(), quote_zero.word())?;
        let height = uint.range_check::<64>(region, &part(242, 8)?)?;
        let first = uint.constant::<64>(region, 2)?;
        uint.assert_le(region, &first, &height)?;
        let payer = identity(250)?;
        let mut tape = PBytes::new();
        for segment in run.primary() {
            tape.push_bounded(segment.bounded().ok_or(Error::Synthesis)?)?;
        }
        if tape.len() != Self::BYTES {
            return Err(Error::Synthesis);
        }
        let digest = tape.digest(uint.glue(), hash, region, Self::DOMAIN)?;
        Ok(Self {
            scheme,
            asset,
            wallet,
            request,
            ordinal,
            amount,
            online_charge,
            charge_quote,
            transaction,
            height,
            payer,
            digest,
        })
    }

    /// Scheme identity as two unsigned 128-bit little-endian halves.
    #[must_use]
    pub const fn scheme(&self) -> &[Word<Fp>; 2] {
        &self.scheme
    }
    /// Asset identity as two unsigned 128-bit little-endian halves.
    #[must_use]
    pub const fn asset(&self) -> &[Word<Fp>; 2] {
        &self.asset
    }
    /// Wallet identity as two unsigned 128-bit little-endian halves.
    #[must_use]
    pub const fn wallet(&self) -> &[Word<Fp>; 2] {
        &self.wallet
    }
    /// Original request identity as two unsigned 128-bit little-endian halves.
    #[must_use]
    pub const fn request(&self) -> &[Word<Fp>; 2] {
        &self.request
    }
    /// Exact accepted Load ordinal, whose successor also fits u128.
    #[must_use]
    pub const fn ordinal(&self) -> &U128<Fp> {
        &self.ordinal
    }
    /// Net offline value funded by this receipt.
    #[must_use]
    pub const fn amount(&self) -> &U128<Fp> {
        &self.amount
    }
    /// Additional online debit, excluded from the offline principal.
    #[must_use]
    pub const fn online_charge(&self) -> &U128<Fp> {
        &self.online_charge
    }
    /// Canonical quote digest, zero exactly when the charge is zero.
    #[must_use]
    pub const fn charge_quote(&self) -> &Word<Fp> {
        &self.charge_quote
    }
    /// Original signed transaction hash as two unsigned little-endian halves.
    #[must_use]
    pub const fn transaction(&self) -> &[Word<Fp>; 2] {
        &self.transaction
    }
    /// Original successful block height, at least two.
    #[must_use]
    pub const fn height(&self) -> &U64<Fp> {
        &self.height
    }
    /// Canonical payer account digest as two unsigned little-endian halves.
    #[must_use]
    pub const fn payer(&self) -> &[Word<Fp>; 2] {
        &self.payer
    }
    /// Packed-byte receipt identity, to bind to the certified typed event.
    #[must_use]
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
}

#[cfg(test)]
mod tests;
