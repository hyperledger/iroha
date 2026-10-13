//! Rescue-Prime over Goldilocks, width 12 (development-only prototype).
//!
//! The permutation is the `Rp64_256` instance published by the Winterfell
//! project (`winter-crypto` 0.13.1, MIT licence): the Rescue-Prime design of
//! Szepieniec, Ashur and Dhooghe ("Rescue-Prime: a Standard Specification
//! (`SoK`)", 2020) with `alpha = 7`, seven rounds, the circulant MDS matrix whose
//! first row is `7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8` and the round
//! constants below. A round applies the S-box, the MDS matrix and the first
//! constants, then the inverse S-box, the MDS matrix and the second constants.
//! The permutation is pinned by that crate's published known-answer vector for
//! the input `0, 1, .., 11`.
//!
//! This is Rescue-Prime, not Rescue-Prime Optimized (Ashur et al., 2022): RPO
//! orders the layers differently and has other round constants, which were not
//! available to this prototype. RPO has the same width, rate, capacity, S-boxes
//! and round count, so its trace geometry equals this permutation's; nothing
//! else about RPO is measured or implied here.
//!
//! The round count is the published one; this module makes no security claim
//! for it. TODO(G.3): delete, or move the selected profile to its owner.

use std::sync::LazyLock;

use super::hash::Permutation12;
use crate::{
    air::PolynomialField,
    field::{mul_base, sub_base},
};

/// State width.
pub const WIDTH: usize = 12;
/// Rounds.
pub const ROUNDS: usize = 7;
/// Inverse of the S-box exponent 7 modulo `p - 1`.
pub const INVERSE_ALPHA: u64 = 10_540_996_611_094_048_183;

/// First row of the circulant MDS matrix.
pub const MDS_ROW: [u64; WIDTH] = [7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8];

/// Constants added after the first MDS layer of each round.
const ARK1: [[u64; WIDTH]; ROUNDS] = [
    [
        13_917_550_007_135_091_859,
        16_002_276_252_647_722_320,
        4_729_924_423_368_391_595,
        10_059_693_067_827_680_263,
        9_804_807_372_516_189_948,
        15_666_751_576_116_384_237,
        10_150_587_679_474_953_119,
        13_627_942_357_577_414_247,
        2_323_786_301_545_403_792,
        615_170_742_765_998_613,
        8_870_655_212_817_778_103,
        10_534_167_191_270_683_080,
    ],
    [
        14_572_151_513_649_018_290,
        9_445_470_642_301_863_087,
        6_565_801_926_598_404_534,
        12_667_566_692_985_038_975,
        7_193_782_419_267_459_720,
        11_874_811_971_940_314_298,
        17_906_868_010_477_466_257,
        1_237_247_437_760_523_561,
        6_829_882_458_376_718_831,
        2_140_011_966_759_485_221,
        1_624_379_354_686_052_121,
        50_954_653_459_374_206,
    ],
    [
        16_288_075_653_722_020_941,
        13_294_924_199_301_620_952,
        13_370_596_140_726_871_456,
        611_533_288_599_636_281,
        12_865_221_627_554_828_747,
        12_269_498_015_480_242_943,
        8_230_863_118_714_645_896,
        13_466_591_048_726_906_480,
        10_176_988_631_229_240_256,
        14_951_460_136_371_189_405,
        5_882_405_912_332_577_353,
        18_125_144_098_115_032_453,
    ],
    [
        6_076_976_409_066_920_174,
        7_466_617_867_456_719_866,
        5_509_452_692_963_105_675,
        14_692_460_717_212_261_752,
        12_980_373_618_703_329_746,
        1_361_187_191_725_412_610,
        6_093_955_025_012_408_881,
        5_110_883_082_899_748_359,
        8_578_179_704_817_414_083,
        9_311_749_071_195_681_469,
        16_965_242_536_774_914_613,
        5_747_454_353_875_601_040,
    ],
    [
        13_684_212_076_160_345_083,
        19_445_754_899_749_561,
        16_618_768_069_125_744_845,
        278_225_951_958_825_090,
        4_997_246_680_116_830_377,
        782_614_868_534_172_852,
        16_423_767_594_935_000_044,
        9_990_984_633_405_879_434,
        16_757_120_847_103_156_641,
        2_103_861_168_279_461_168,
        16_018_697_163_142_305_052,
        6_479_823_382_130_993_799,
    ],
    [
        13_957_683_526_597_936_825,
        9_702_819_874_074_407_511,
        18_357_323_897_135_139_931,
        3_029_452_444_431_245_019,
        1_809_322_684_009_991_117,
        12_459_356_450_895_788_575,
        11_985_094_908_667_810_946,
        12_868_806_590_346_066_108,
        7_872_185_587_893_926_881,
        10_694_372_443_883_124_306,
        8_644_995_046_789_277_522,
        1_422_920_069_067_375_692,
    ],
    [
        17_619_517_835_351_328_008,
        6_173_683_530_634_627_901,
        15_061_027_706_054_897_896,
        4_503_753_322_633_415_655,
        11_538_516_425_871_008_333,
        12_777_459_872_202_073_891,
        17_842_814_708_228_807_409,
        13_441_695_826_912_633_916,
        5_950_710_620_243_434_509,
        17_040_450_522_225_825_296,
        8_787_650_312_632_423_701,
        7_431_110_942_091_427_450,
    ],
];

/// Constants added after the second MDS layer of each round.
const ARK2: [[u64; WIDTH]; ROUNDS] = [
    [
        7_989_257_206_380_839_449,
        8_639_509_123_020_237_648,
        6_488_561_830_509_603_695,
        5_519_169_995_467_998_761,
        2_972_173_318_556_248_829,
        14_899_875_358_187_389_787,
        14_160_104_549_881_494_022,
        5_969_738_169_680_657_501,
        5_116_050_734_813_646_528,
        12_120_002_089_437_618_419,
        17_404_470_791_907_152_876,
        2_718_166_276_419_445_724,
    ],
    [
        2_485_377_440_770_793_394,
        14_358_936_485_713_564_605,
        3_327_012_975_585_973_824,
        6_001_912_612_374_303_716,
        17_419_159_457_659_073_951,
        11_810_720_562_576_658_327,
        14_802_512_641_816_370_470,
        751_963_320_628_219_432,
        9_410_455_736_958_787_393,
        16_405_548_341_306_967_018,
        6_867_376_949_398_252_373,
        13_982_182_448_213_113_532,
    ],
    [
        10_436_926_105_997_283_389,
        13_237_521_312_283_579_132,
        668_335_841_375_552_722,
        2_385_521_647_573_044_240,
        3_874_694_023_045_931_809,
        12_952_434_030_222_726_182,
        1_972_984_540_857_058_687,
        14_000_313_505_684_510_403,
        976_377_933_822_676_506,
        8_407_002_393_718_726_702,
        338_785_660_775_650_958,
        4_208_211_193_539_481_671,
    ],
    [
        2_284_392_243_703_840_734,
        4_500_504_737_691_218_932,
        3_976_085_877_224_857_941,
        2_603_294_837_319_327_956,
        5_760_259_105_023_371_034,
        2_911_579_958_858_769_248,
        18_415_938_932_239_013_434,
        7_063_156_700_464_743_997,
        16_626_114_991_069_403_630,
        163_485_390_956_217_960,
        11_596_043_559_919_659_130,
        2_976_841_507_452_846_995,
    ],
    [
        15_090_073_748_392_700_862,
        3_496_786_927_732_034_743,
        8_646_735_362_535_504_000,
        2_460_088_694_130_347_125,
        3_944_675_034_557_577_794,
        14_781_700_518_249_159_275,
        2_857_749_437_648_203_959,
        8_505_429_584_078_195_973,
        18_008_150_643_764_164_736,
        720_176_627_102_578_275,
        7_038_653_538_629_322_181,
        8_849_746_187_975_356_582,
    ],
    [
        17_427_790_390_280_348_710,
        1_159_544_160_012_040_055,
        17_946_663_256_456_930_598,
        6_338_793_524_502_945_410,
        17_715_539_080_731_926_288,
        4_208_940_652_334_891_422,
        12_386_490_721_239_135_719,
        10_010_817_080_957_769_535,
        5_566_101_162_185_411_405,
        12_520_146_553_271_266_365,
        4_972_547_404_153_988_943,
        5_597_076_522_138_709_717,
    ],
    [
        18_338_863_478_027_005_376,
        115_128_380_230_345_639,
        4_427_489_889_653_730_058,
        10_890_727_269_603_281_956,
        7_094_492_770_210_294_530,
        7_345_573_238_864_544_283,
        6_834_103_517_673_002_336,
        14_002_814_950_696_095_900,
        15_939_230_865_809_555_943,
        12_717_309_295_554_119_359,
        4_130_723_396_860_574_906,
        7_706_153_020_203_677_238,
    ],
];

/// First round constants of round `round`, in `0..ROUNDS`.
#[must_use]
pub fn first_constants(round: usize) -> &'static [u64; WIDTH] {
    &ARK1[round]
}

/// Second round constants of round `round`, in `0..ROUNDS`.
#[must_use]
pub fn second_constants(round: usize) -> &'static [u64; WIDTH] {
    &ARK2[round]
}

/// Entry `(row, column)` of the circulant MDS matrix.
#[must_use]
pub const fn mds_entry(row: usize, column: usize) -> u64 {
    MDS_ROW[(column + WIDTH - row) % WIDTH]
}

/// Inverse of the MDS matrix, by Gauss-Jordan elimination over the field.
static INVERSE_MDS: LazyLock<[[u64; WIDTH]; WIDTH]> = LazyLock::new(|| {
    let mut left: [[u64; WIDTH]; WIDTH] =
        core::array::from_fn(|row| core::array::from_fn(|column| mds_entry(row, column)));
    let mut right: [[u64; WIDTH]; WIDTH] =
        core::array::from_fn(|row| core::array::from_fn(|column| u64::from(row == column)));
    for pivot in 0..WIDTH {
        let source = (pivot..WIDTH)
            .find(|row| left[*row][pivot] != 0)
            .expect("the published MDS matrix is invertible");
        left.swap(pivot, source);
        right.swap(pivot, source);
        let scale = left[pivot][pivot]
            .inverse()
            .expect("a nonzero pivot is invertible");
        for column in 0..WIDTH {
            left[pivot][column] = mul_base(left[pivot][column], scale);
            right[pivot][column] = mul_base(right[pivot][column], scale);
        }
        for row in 0..WIDTH {
            let factor = left[row][pivot];
            if row == pivot || factor == 0 {
                continue;
            }
            for column in 0..WIDTH {
                left[row][column] =
                    sub_base(left[row][column], mul_base(factor, left[pivot][column]));
                right[row][column] =
                    sub_base(right[row][column], mul_base(factor, right[pivot][column]));
            }
        }
    }
    right
});

/// Multiply a state by the MDS matrix.
#[must_use]
pub fn mds_layer<F: PolynomialField>(state: &[F; WIDTH]) -> [F; WIDTH] {
    core::array::from_fn(|row| {
        (0..WIDTH).fold(F::ZERO, |sum, column| {
            sum.add(state[column].scale_base(mds_entry(row, column)))
        })
    })
}

/// Multiply a state by the inverse of the MDS matrix.
#[must_use]
pub fn inverse_mds_layer<F: PolynomialField>(state: &[F; WIDTH]) -> [F; WIDTH] {
    let inverse = &*INVERSE_MDS;
    core::array::from_fn(|row| {
        (0..WIDTH).fold(F::ZERO, |sum, column| {
            sum.add(state[column].scale_base(inverse[row][column]))
        })
    })
}

/// `x^7`.
#[must_use]
pub fn sbox<F: PolynomialField>(value: F) -> F {
    let square = value.mul(value);
    let cube = square.mul(value);
    cube.mul(square.mul(square))
}

/// `base^(2^squarings) * tail`.
fn square_then_multiply(base: u64, tail: u64, squarings: usize) -> u64 {
    let mut value = base;
    for _ in 0..squarings {
        value = mul_base(value, value);
    }
    mul_base(value, tail)
}

/// `x^(1/7)`: the published 72-multiplication addition chain for
/// [`INVERSE_ALPHA`].
#[must_use]
pub fn inverse_sbox(value: u64) -> u64 {
    let t1 = mul_base(value, value);
    let t2 = mul_base(t1, t1);
    let t3 = square_then_multiply(t2, t2, 3);
    let t4 = square_then_multiply(t3, t3, 6);
    let t5 = square_then_multiply(t4, t4, 12);
    let t6 = square_then_multiply(t5, t3, 6);
    let t7 = square_then_multiply(t6, t6, 31);
    let head = mul_base(mul_base(t7, t7), t6);
    let head = mul_base(head, head);
    let head = mul_base(head, head);
    mul_base(head, mul_base(mul_base(t1, t2), value))
}

/// The state after the first half of round `round`: `MDS(x^7) + ARK1`.
///
/// The second half inverts the S-box, so a relation checks a whole round as
/// `(MDS^-1(next - ARK2))^7 = first_half(current)` without auxiliary columns.
#[must_use]
pub fn first_half<F: PolynomialField>(state: &[F; WIDTH], constants: &[F; WIDTH]) -> [F; WIDTH] {
    let boxed: [F; WIDTH] = core::array::from_fn(|index| sbox(state[index]));
    let mixed = mds_layer(&boxed);
    core::array::from_fn(|index| mixed[index].add(constants[index]))
}

/// One complete round.
#[must_use]
pub fn round(state: &[u64; WIDTH], round: usize) -> [u64; WIDTH] {
    let middle = first_half(state, &ARK1[round]);
    let unboxed: [u64; WIDTH] = core::array::from_fn(|index| inverse_sbox(middle[index]));
    let mixed = mds_layer(&unboxed);
    core::array::from_fn(|index| crate::field::add_base(mixed[index], ARK2[round][index]))
}

/// Every state of one permutation: the input and the state after each round.
/// `ROUNDS + 1` rows.
#[must_use]
pub fn permutation_states(input: [u64; WIDTH]) -> Vec<[u64; WIDTH]> {
    let mut states = Vec::with_capacity(ROUNDS + 1);
    states.push(input);
    let mut state = input;
    for index in 0..ROUNDS {
        state = round(&state, index);
        states.push(state);
    }
    states
}

/// The Rescue-Prime permutation.
pub fn permute(state: &mut [u64; WIDTH]) {
    for index in 0..ROUNDS {
        *state = round(state, index);
    }
}

/// Rescue-Prime over Goldilocks, width 12, as a sponge permutation.
#[derive(Clone, Copy, Debug, Default)]
pub struct RescuePrime64;

impl Permutation12 for RescuePrime64 {
    const NAME: &'static str = "rescue-prime-rp64-256-goldilocks-t12-n7-x7/sponge-r8-c4";

    fn permute(state: &mut [u64; 12]) {
        permute(state);
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::field::GOLDILOCKS_MODULUS_V1;

    /// `winter-crypto` 0.13.1, `rp64_256::tests::apply_permutation`: "expected
    /// values are obtained by executing sage reference implementation code".
    const KNOWN_ANSWER: [u64; WIDTH] = [
        11_084_501_481_526_603_421,
        6_291_559_951_628_160_880,
        13_626_645_864_671_311_919,
        18_397_438_323_058_963_117,
        7_443_014_167_353_970_324,
        17_930_833_023_906_771_425,
        4_275_355_080_008_025_761,
        7_676_681_476_902_901_785,
        3_460_534_574_143_792_217,
        11_912_731_278_641_497_187,
        8_104_899_243_369_883_110,
        674_509_706_691_634_438,
    ];

    #[test]
    fn permutation_reproduces_the_published_known_answer_vector() {
        let mut state: [u64; WIDTH] = core::array::from_fn(|index| index as u64);
        permute(&mut state);
        assert_eq!(state, KNOWN_ANSWER);
        let mut via_trait: [u64; WIDTH] = core::array::from_fn(|index| index as u64);
        RescuePrime64::permute(&mut via_trait);
        assert_eq!(via_trait, KNOWN_ANSWER);
        let states = permutation_states(core::array::from_fn(|index| index as u64));
        assert_eq!(states.len(), ROUNDS + 1);
        assert_eq!(states[ROUNDS], KNOWN_ANSWER);
        assert_eq!(states[1], round(&states[0], 0));
    }

    #[test]
    fn published_constants_are_canonical_and_pinned() {
        let mut hasher = Sha256::new();
        for table in [&ARK1, &ARK2] {
            for row in table {
                for word in row {
                    assert!(*word < GOLDILOCKS_MODULUS_V1);
                    hasher.update(word.to_le_bytes());
                }
            }
        }
        assert_eq!(
            hex::encode(hasher.finalize()),
            "c9764151a80abac28c7459ddd65af5e951ff077b1e7e3077e47d516d8a28faa7"
        );
        assert_eq!(first_constants(0)[0], 13_917_550_007_135_091_859);
        assert_eq!(
            second_constants(ROUNDS - 1)[WIDTH - 1],
            7_706_153_020_203_677_238
        );
        assert_eq!(mds_entry(0, 1), 23);
        assert_eq!(mds_entry(1, 0), 8);
        assert_eq!(mds_entry(11, 0), 23);
    }

    #[test]
    fn inverse_layers_invert_their_layers() {
        let state: [u64; WIDTH] =
            core::array::from_fn(|index| 0x1234_5678_9abc_def1 + index as u64);
        assert_eq!(inverse_mds_layer(&mds_layer(&state)), state);
        assert_eq!(mds_layer(&inverse_mds_layer(&state)), state);
        for value in [
            0_u64,
            1,
            2,
            7,
            GOLDILOCKS_MODULUS_V1 - 1,
            0xdead_beef_0bad_f00d,
        ] {
            assert_eq!(inverse_sbox(sbox(value)), value);
            assert_eq!(sbox(inverse_sbox(value)), value);
            assert_eq!(inverse_sbox(value), value.power(INVERSE_ALPHA));
        }
        // 7 * INVERSE_ALPHA = 1 modulo p - 1.
        let product = u128::from(INVERSE_ALPHA) * 7;
        assert_eq!(product % u128::from(GOLDILOCKS_MODULUS_V1 - 1), 1);
    }

    #[test]
    fn a_round_satisfies_the_relation_form_without_the_inverse_sbox() {
        let state: [u64; WIDTH] = core::array::from_fn(|index| 99 * index as u64 + 5);
        for index in 0..ROUNDS {
            let next = round(&state, index);
            let lifted: [u64; WIDTH] =
                core::array::from_fn(|word| sub_base(next[word], ARK2[index][word]));
            let unmixed = inverse_mds_layer(&lifted);
            let boxed: [u64; WIDTH] = core::array::from_fn(|word| sbox(unmixed[word]));
            assert_eq!(boxed, first_half(&state, &ARK1[index]));
        }
    }
}
