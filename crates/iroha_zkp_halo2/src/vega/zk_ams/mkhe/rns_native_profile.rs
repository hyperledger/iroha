//! Corrected 40-limb RNS-native profile for the replacement MKHE proof.
//!
//! This profile is parameter-complete but deliberately non-authorizing until
//! its exact estimator transcript, composite proof KAT, and measured resource
//! evidence are installed through the release manifest.

use super::{
    BgvProfile, PlaintextModulus, ZkAmsMkheErrorV1,
    manifest::{
        ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1, ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1,
        ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1,
    },
    modulus_product_bit_len,
};
#[cfg(test)]
use crate::vega::sponge::Keccak256;

#[cfg(test)]
const RNS_NATIVE_PROFILE_MANIFEST_TAG_V1: [u8; 4] = *b"ZAMN";

/// Number of RNS limbs in the corrected replacement profile.
pub const ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1: usize = 40;
/// Exact full-product bit length for the corrected modulus chain.
pub const ZK_AMS_MKHE_RNS_NATIVE_MODULUS_BITS_V1: u16 = 2_400;
/// Centered capacity below `Q/2`.
pub const ZK_AMS_MKHE_RNS_NATIVE_CENTERED_CAPACITY_BITS_V1: u16 = 2_399;
/// Corrected worst-case Phase-II/III residual magnitude.
pub const ZK_AMS_MKHE_RNS_NATIVE_RESIDUAL_BITS_V1: u16 = 2_287;
/// Strict residual headroom under the centered capacity.
pub const ZK_AMS_MKHE_RNS_NATIVE_HEADROOM_BITS_V1: u16 = 112;
/// Canonical minimal signed response bytes for the corrected residual width.
#[cfg(test)]
pub const ZK_AMS_MKHE_RNS_NATIVE_WIDE_RESPONSE_BYTES_V1: u16 = 258;
/// Hard complete composite-proof ceiling.
pub const ZK_AMS_MKHE_RNS_NATIVE_PROOF_MAX_BYTES_V1: u64 = 40 * 1024 * 1024;
/// Hard in-process proof workspace ceiling.
pub const ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1: u64 = 512 * 1024 * 1024;
/// Hard retained authenticated spool ceiling.
pub const ZK_AMS_MKHE_RNS_NATIVE_SPOOL_MAX_BYTES_V1: u64 = 16 * 1024 * 1024 * 1024;
/// Hard aggregate authenticated I/O ceiling.
pub const ZK_AMS_MKHE_RNS_NATIVE_IO_MAX_BYTES_V1: u64 = 64 * 1024 * 1024 * 1024;
/// Hard instrumented primitive-operation ceiling.
pub const ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1: u64 = 128_000_000_000;
/// Required classical security strength of the replacement estimator result.
pub const ZK_AMS_MKHE_RNS_NATIVE_TARGET_SECURITY_BITS_V1: u16 = 128;
/// Exact canonical bytes in one replacement-profile manifest.
#[cfg(test)]
pub const ZK_AMS_MKHE_RNS_NATIVE_PROFILE_MANIFEST_BYTES_V1: usize = 244;

/// Canonical number of committed opening families.
pub const ZK_AMS_MKHE_RNS_NATIVE_FAMILY_COUNT_V1: usize = 6;
/// Canonical number of committed records: `X1,U16,E16,rE1,W8,rW1`.
pub const ZK_AMS_MKHE_RNS_NATIVE_OPENING_COUNT_V1: u8 = 43;
/// Number of aggregated RNS RLWE equations proved together.
pub const ZK_AMS_MKHE_RNS_NATIVE_RLWE_EQUATION_COUNT_V1: u8 = 2;
/// Number of Fiat--Shamir cross-field evaluation points.
pub const ZK_AMS_MKHE_RNS_NATIVE_CROSS_FIELD_POINT_COUNT_V1: u8 = 5;
/// Base-two logarithm of the Fq2 LDE domain.
pub const ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1: u8 = 19;
/// Number of common qPCS queries.
pub const ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1: u16 = 160;
/// Number of correlated FRI folds.
pub const ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1: u8 = 18;
/// Radix digit width used by the cross-field lookup.
pub const ZK_AMS_MKHE_RNS_NATIVE_RADIX_LOG2_V1: u8 = 15;
/// Governed signed quotient width.
pub const ZK_AMS_MKHE_RNS_NATIVE_QUOTIENT_BITS_V1: u8 = 103;
/// Number of global-lookup sumcheck rounds.
pub const ZK_AMS_MKHE_RNS_NATIVE_SUMCHECK_ROUNDS_V1: u8 = 29;
/// Exact bounded initial qPCS multiproof contribution at 40 limbs.
pub const ZK_AMS_MKHE_RNS_NATIVE_INITIAL_MULTIPROOF_MAX_BYTES_V1: u64 = 4_313_088;
/// Exact bounded correlated-FRI contribution at 40 limbs.
pub const ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1: u64 = 26_409_984;
/// Exact bounded qPCS wire contribution at 40 limbs.
pub const ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1: u64 = 30_740_352;

/// Canonical record-family discriminator for the replacement RNS-native proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZkAmsMkheRnsNativeFamilyV1 {
    /// One statement/input record.
    X = 0,
    /// Sixteen `U` chunks.
    U = 1,
    /// Sixteen `E` chunks.
    E = 2,
    /// One encryption-randomness record for `E`.
    RE = 3,
    /// Eight `W` chunks.
    W = 4,
    /// One encryption-randomness record for `W`.
    RW = 5,
}

impl ZkAmsMkheRnsNativeFamilyV1 {
    /// Return the exact number of records in this family.
    #[must_use]
    pub const fn record_count(self) -> u8 {
        match self {
            Self::X | Self::RE | Self::RW => 1,
            Self::U | Self::E => 16,
            Self::W => 8,
        }
    }
}

/// Sole canonical family order for transcript and source traversal.
pub const ZK_AMS_MKHE_RNS_NATIVE_FAMILY_ORDER_V1: [ZkAmsMkheRnsNativeFamilyV1;
    ZK_AMS_MKHE_RNS_NATIVE_FAMILY_COUNT_V1] = [
    ZkAmsMkheRnsNativeFamilyV1::X,
    ZkAmsMkheRnsNativeFamilyV1::U,
    ZkAmsMkheRnsNativeFamilyV1::E,
    ZkAmsMkheRnsNativeFamilyV1::RE,
    ZkAmsMkheRnsNativeFamilyV1::W,
    ZkAmsMkheRnsNativeFamilyV1::RW,
];

/// Digest-bound dimensions of the replacement composite proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheRnsNativeTopologyV1 {
    /// Topology schema version.
    pub version: u8,
    /// Ordered family record counts.
    pub family_record_counts: [u8; ZK_AMS_MKHE_RNS_NATIVE_FAMILY_COUNT_V1],
    /// Total committed openings.
    pub opening_count: u8,
    /// Simultaneously checked RNS RLWE equations.
    pub rlwe_equation_count: u8,
    /// Cross-field evaluation-point count.
    pub cross_field_point_count: u8,
    /// Base-two logarithm of the Fq2 LDE domain.
    pub lde_domain_log2: u8,
    /// Common qPCS query count.
    pub query_count: u16,
    /// Correlated FRI round count.
    pub fri_rounds: u8,
    /// Radix digit width.
    pub radix_log2: u8,
    /// Signed quotient width.
    pub quotient_bits: u8,
    /// Global-lookup sumcheck round count.
    pub sumcheck_rounds: u8,
    /// Complete proof byte ceiling.
    pub max_proof_bytes: u64,
    /// Initial qPCS multiproof byte ceiling.
    pub max_initial_multiproof_bytes: u64,
    /// Correlated-FRI byte ceiling.
    pub max_correlated_fri_bytes: u64,
    /// qPCS section byte ceiling.
    pub max_qpcs_bytes: u64,
    /// Digest of every preceding field and canonical family tag.
    pub topology_digest: [u8; 32],
}

impl ZkAmsMkheRnsNativeTopologyV1 {
    /// Validate the sole supported topology and its self digest.
    pub fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        let expected_counts =
            ZK_AMS_MKHE_RNS_NATIVE_FAMILY_ORDER_V1.map(ZkAmsMkheRnsNativeFamilyV1::record_count);
        let opening_count = self
            .family_record_counts
            .into_iter()
            .try_fold(0_u8, u8::checked_add)
            .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
        let qpcs_parts_fit = match self
            .max_initial_multiproof_bytes
            .checked_add(self.max_correlated_fri_bytes)
        {
            Some(subtotal) => subtotal <= self.max_qpcs_bytes,
            None => false,
        };
        if self.version != 1
            || self.family_record_counts != expected_counts
            || opening_count != ZK_AMS_MKHE_RNS_NATIVE_OPENING_COUNT_V1
            || self.opening_count != opening_count
            || self.rlwe_equation_count != ZK_AMS_MKHE_RNS_NATIVE_RLWE_EQUATION_COUNT_V1
            || self.cross_field_point_count != ZK_AMS_MKHE_RNS_NATIVE_CROSS_FIELD_POINT_COUNT_V1
            || self.lde_domain_log2 != ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1
            || self.query_count != ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1
            || self.fri_rounds != ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1
            || self.radix_log2 != ZK_AMS_MKHE_RNS_NATIVE_RADIX_LOG2_V1
            || self.quotient_bits != ZK_AMS_MKHE_RNS_NATIVE_QUOTIENT_BITS_V1
            || self.sumcheck_rounds != ZK_AMS_MKHE_RNS_NATIVE_SUMCHECK_ROUNDS_V1
            || self.max_proof_bytes != ZK_AMS_MKHE_RNS_NATIVE_PROOF_MAX_BYTES_V1
            || self.max_initial_multiproof_bytes
                != ZK_AMS_MKHE_RNS_NATIVE_INITIAL_MULTIPROOF_MAX_BYTES_V1
            || self.max_correlated_fri_bytes != ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1
            || self.max_qpcs_bytes != ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1
            || !qpcs_parts_fit
            || self.max_qpcs_bytes >= self.max_proof_bytes
            || self.topology_digest == [0; 32]
            || self.topology_digest != topology_digest_v1(self)
        {
            return Err(ZkAmsMkheErrorV1::InvalidProfile);
        }
        Ok(())
    }
}

/// Return the sole digest-bound replacement proof topology.
pub fn zk_ams_mkhe_rns_native_topology_v1() -> Result<ZkAmsMkheRnsNativeTopologyV1, ZkAmsMkheErrorV1>
{
    let mut topology = ZkAmsMkheRnsNativeTopologyV1 {
        version: 1,
        family_record_counts: ZK_AMS_MKHE_RNS_NATIVE_FAMILY_ORDER_V1
            .map(ZkAmsMkheRnsNativeFamilyV1::record_count),
        opening_count: ZK_AMS_MKHE_RNS_NATIVE_OPENING_COUNT_V1,
        rlwe_equation_count: ZK_AMS_MKHE_RNS_NATIVE_RLWE_EQUATION_COUNT_V1,
        cross_field_point_count: ZK_AMS_MKHE_RNS_NATIVE_CROSS_FIELD_POINT_COUNT_V1,
        lde_domain_log2: ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1,
        query_count: ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1,
        fri_rounds: ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1,
        radix_log2: ZK_AMS_MKHE_RNS_NATIVE_RADIX_LOG2_V1,
        quotient_bits: ZK_AMS_MKHE_RNS_NATIVE_QUOTIENT_BITS_V1,
        sumcheck_rounds: ZK_AMS_MKHE_RNS_NATIVE_SUMCHECK_ROUNDS_V1,
        max_proof_bytes: ZK_AMS_MKHE_RNS_NATIVE_PROOF_MAX_BYTES_V1,
        max_initial_multiproof_bytes: ZK_AMS_MKHE_RNS_NATIVE_INITIAL_MULTIPROOF_MAX_BYTES_V1,
        max_correlated_fri_bytes: ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1,
        max_qpcs_bytes: ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1,
        topology_digest: [0; 32],
    };
    topology.topology_digest = topology_digest_v1(topology);
    topology.validate()?;
    Ok(topology)
}

fn topology_digest_v1(topology: ZkAmsMkheRnsNativeTopologyV1) -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Parameter,
        b"iroha.zk-ams.v1.mkhe.rns-native-topology",
        8 + ZK_AMS_MKHE_RNS_NATIVE_FAMILY_ORDER_V1.len(),
    );
    hash.push_field(&[topology.version])
        .expect("fixed bounded MKHE identity field");
    for (family, count) in ZK_AMS_MKHE_RNS_NATIVE_FAMILY_ORDER_V1
        .into_iter()
        .zip(topology.family_record_counts)
    {
        hash.push_field(&[family as u8, count])
            .expect("fixed bounded MKHE identity field");
    }
    hash.push_field(&[
        topology.opening_count,
        topology.rlwe_equation_count,
        topology.cross_field_point_count,
        topology.lde_domain_log2,
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&topology.query_count.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        topology.fri_rounds,
        topology.radix_log2,
        topology.quotient_bits,
        topology.sumcheck_rounds,
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&topology.max_proof_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&topology.max_initial_multiproof_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&topology.max_correlated_fri_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&topology.max_qpcs_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}

/// Exact current proof hash, field encoding, and Fiat-Shamir sampling contract.
///
/// This descriptor is public profile identity metadata; its typed BLAKE3 identity
/// is not a commitment or transcript implementation. It binds the native proof's
/// sole six-lane hash and wire interpretation before a proof root is accepted.
pub(super) const ZK_AMS_MKHE_RNS_NATIVE_PROOF_HASH_WIRE_SCHEMA_V1: &[u8] = concat!(
    "iroha.zk-ams.rns-native.proof-hash-wire.v1;",
    "digest=Poseidon-x7-Goldilocks-six-independent-width3-lanes;",
    "digest-parameters=shared-GOLDILOCKS_DIGEST384_PARAMETER_SHA3_256_V1;",
    "digest-wire=48bytes-six-canonical-u64le-words;",
    "envelope=three-ordered-sections-kind1-terminal-kind2-qpcs-kind3-cross-global;header357;",
    "terminal-roots=cross-field,global-lookup;no-detached-padding-inventory;",
    "terminal-schedule=27seeds;global-purpose9-ordinal25;composite-purpose11-ordinal26;",
    "terminal-discharge=concrete-cross-root-and-global-membership-root;exact-post-cross-and-pre-global-capability;final-global-root-equality;independent-composite-seed-and-final-state-replay;",
    "source-padding=mandatory-full-logical65536-slot-base-subfield-conjugacy-and-tail-validation-before-used-slot-callback;X89,rE1024,rW512;",
    "source-terminal-anchor=610byte-fixed-header;16-exact-position-identities;native48-ordinals=0,6,7,12,13;other11-public32;",
    "source-mapping-bridge=terminal-bridge/binding/level3/index0/counter0;full-current-mapping-seed48-and-public-curve-axes;terminal-hyrax-bridge=index1;mapping-root48-and-exact-opening-hyrax-aggregate-identities;",
    "global-qpcs-binding=transcript/binding/level6/index0/counter0;current-parameter32-and-exact200-ordered-limb-u8-repetition-u8-modulus-u64be-product-u64be-quotient-u64be-records;",
    "global-pre-z=13-physical-roles39634-points;scalar-wire=exact2-point33-multiplicity-then-inverse-product-mask;header56;inverse-product-mask-purpose14;post-z-inverse-roles15-through21;existing-inverse11696-added20712;",
    "global-clean-bridge=terminal-bridge/binding/level2/index0/counter0;ten-verified-curve32-identities-z32-U-sum33-M33-and-pre-global-native48;",
    "carrier-binding=transcript/binding/level7/index0/counter0;60-fixed-fields2382bytes;current-version1;full-public32-and-native48-role-widths;two-equation-and40-limb-native48-roots;536-framed-words-per-lane;",

    "catalog=sole-privacy-exact12-commitment;",
    "frame=shared-length-framed-catalog,protocol,profile,role,phase,level,index,counter,lane,fields;",
    "tree-roles=initial-tree,quotient-tree,fri-tree;transcript-role=transcript;",
    "leaf=payload384-then-index-bound384;sole-construction;",
    "payload-role=oracle-payload;phase=leaf;position=oracle-layer,index0,counter0;",
    "payload-fields=canonical-leaf-payload-domain,version,oracle-kind-layer,tree-length-u32be,coordinate-count-u16be,15-byte-packing-tag,payload-length-u32be,all-canonical-packed-bytes;",
    "leaf-phase=leaf;position=level0,exact-leaf-index,counter0;",
    "leaf-fields=index-bound-leaf-domain,version,oracle-kind-layer,tree-length-u32be,coordinate-count-u16be,15-byte-packing-tag,payload-length-u32be,all48-payload-digest-bytes;",
    "payload-cache=one-borrowed-canonical-public-payload;exact-byte-equality;no-witness-cache;",
    "curve-bridge-role=terminal-bridge;phase=binding;position=level0,index0,counter0;",
    "curve-bridge=verified-independent-T256-kernel32-and-complete-current-context-statement-proof;",
    "direct-curve-bridge=terminal-bridge/binding/level1/index0/counter0;complete-current-native-context-plus-independent-curve-context-and-all-four-ordered-7981byte-GBP-proofs;",
    "direct-wire=32303byte-owned-frame;six-curve32-identities-and-native48-q-mask-root-and-relation-seed-in-fixed-positions;",
    "q-mask-root=transcript/binding/level4/index0/counter0;fields=domain,version,profile32,source32,formula32,mapping32,rns-seed48,parameter32,pre-relation-state48,direct-manifest32,6400-u32be,6400-ordered-ordinal-u32be-axis4-canonical-point33-records;",
    "q-mask-last-field=262400bytes-exact-shared-stream;one-source-traversal;bounded-six-lane-state-and41byte-point-record;no-heap-tape-or-source-replay-per-lane;",
    "claimed-numeric-binding=one-owner;transcript/binding/level2/index2/counter0;fields=domain,version,anchor48,preflight48,public-bundle32,source-parameter32,source-transcript48,source-schedule48,evaluation48,residual48,schedule-parameter32,q-mask48,pre-relation48,relation-seed48,final-transcript48,exact200-u64be-triples;",
    "claimed-numeric-parameter=both-parameters-equal-current-canonical-profile;",
    "numeric-handoff-binding=transcript/binding/level5/index0/counter0;one-V1-domain-and-version;29-fixed-fields-824bytes;native-schedule-and-proof-state-full48;public-source-receipt-identities32;248-framed-words-per-lane;744-lane-permutations;",
    "public-reader-schedule=transcript/binding/level4/index1/counter0;fields=domain,version,parameter32,q-mask48,pre-relation48,relation-seed48,limbs-u16be,repetitions-u16be,40-ordered-limb-u16be-modulus-u64be-five-repetition-u16be-point-u64be-records;",
    "source-anchor=898byte-fixed-header;23-exact-position-identities;native48-ordinals=1,2,3,4,19,20,21,22;other15-public32;downstream-length-u32be;no-width-tags-or-aliases;",
    "source-packing-post-equation-binding=native48-source-anchor-and-final-aggregation-schedule-ordinals0,1;17-ordered-public-curve32-components;640-component-bytes;combined-curve32-ordinal19;full-width-absorption-and-tagged-zero-alias-checks;outer-bindings-admitted-only-after-child-equation;",
    "phases=initial,absorb,opening,challenge,ratchet,leaf,node,binding;",
    "fq2-wire=15byte-big-endian-c0-high60-c1-low60;",
    "fq2-canonical=c0<limb-modulus-and-c1<limb-modulus;",
    "transcript-state-and-seeds=full48bytes;",
    "sampling-word=digest.words()[0]-canonical-Goldilocks-not-uniform-u64;",
    "sampling-frame=transcript/challenge/level0/index0/counter-attempt;",
    "sampling-fields=typed-role,exact-five-coordinate-bytes,modulus-u64be,complete-seed48;",
    "sampling-roles=query-index,relation-point,rlwe-aggregation,batch-coefficient,fri-fold;",
    "sampling-coordinates=query-u16be-plus-three-zero-bytes;point-limb-repetition-plus-three-zero-bytes;",
    "sampling-coordinates=batch-limb-row-coefficient-component-zero;fold-layer-limb-row-component-zero;",
    "sampling-coordinates=aggregation-limb-repetition-coefficient-zero-zero;",
    "aggregation-seed=transcript/binding/level3/index0/counter0;fields=native-rlwe-aggregation-seed,prior48,formula32,mapping32;",
    "aggregation=nonzero-distinct-per-limb-ten-values;cross-limb-pairs-distinct;",
    "sampling-accept=word<pG-(pG%target-modulus);",
    "sampling-value=word%target-modulus;",
    "sampling-domain=verifier-owned-role,phase,layer,limb,row,coefficient,component,ordinal,attempt;",
    "sampling-attempts=256-fail-closed;",
    "query-schedule=160-distinct-indices-in-2pow18;",
    "relation-points=nonzero-distinct-per-limb-excluding-native-NTT-subgroups;",
    "fq2-challenges=nonzero-pair;",
    "no32byte-proof-digest-no16byte-fq2-no-alternate-wire",
).as_bytes();

/// Canonical ordered 40-prime NTT chain.
pub const ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1: [u64; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1] = [
    1_152_921_504_606_584_833,
    1_152_921_504_598_720_513,
    1_152_921_504_592_429_057,
    1_152_921_504_581_419_009,
    1_152_921_504_580_894_721,
    1_152_921_504_578_273_281,
    1_152_921_504_577_748_993,
    1_152_921_504_577_486_849,
    1_152_921_504_568_836_097,
    1_152_921_504_565_166_081,
    1_152_921_504_563_331_073,
    1_152_921_504_556_515_329,
    1_152_921_504_555_466_753,
    1_152_921_504_554_156_033,
    1_152_921_504_552_583_169,
    1_152_921_504_542_883_841,
    1_152_921_504_538_951_681,
    1_152_921_504_537_378_817,
    1_152_921_504_531_873_793,
    1_152_921_504_521_650_177,
    1_152_921_504_509_853_697,
    1_152_921_504_508_280_833,
    1_152_921_504_506_970_113,
    1_152_921_504_495_697_921,
    1_152_921_504_491_241_473,
    1_152_921_504_488_620_033,
    1_152_921_504_479_444_993,
    1_152_921_504_470_794_241,
    1_152_921_504_468_172_801,
    1_152_921_504_462_929_921,
    1_152_921_504_462_667_777,
    1_152_921_504_455_589_889,
    1_152_921_504_447_987_713,
    1_152_921_504_442_482_689,
    1_152_921_504_436_191_233,
    1_152_921_504_427_278_337,
    1_152_921_504_419_414_017,
    1_152_921_504_409_190_401,
    1_152_921_504_403_947_521,
    1_152_921_504_396_869_633,
];

/// Canonical primitive `2N`-th roots paired with the 40-prime chain.
pub const ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1: [u64; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1] = [
    720_645_352_895_426_071,
    282_755_386_997_791_573,
    1_129_868_644_045_593_393,
    853_812_227_483_389_373,
    313_941_090_484_177_697,
    430_486_680_513_317_260,
    143_942_864_930_673_074,
    807_173_726_984_510_404,
    191_722_530_547_666_486,
    467_567_141_367_137_610,
    941_895_608_111_266_529,
    164_841_987_874_738_392,
    662_956_088_516_163_749,
    418_880_473_612_227_419,
    392_461_511_604_930_516,
    764_249_630_711_722_482,
    864_013_988_376_557_277,
    705_763_476_696_323_117,
    1_036_023_418_809_922_092,
    1_093_496_573_364_979_026,
    465_626_502_647_312_456,
    108_719_633_419_962_724,
    1_009_384_194_290_538_050,
    926_844_163_581_853_650,
    935_039_477_417_276_816,
    950_668_019_576_080_971,
    551_479_639_661_014_597,
    612_386_825_931_585_809,
    452_213_060_731_776_498,
    215_387_729_362_370_611,
    506_439_537_974_696_847,
    1_138_741_943_693_016_536,
    378_985_449_492_583_188,
    143_344_989_960_478_445,
    879_283_036_444_379_690,
    150_226_471_703_910_190,
    1_049_010_867_608_938_030,
    533_899_346_966_036_544,
    22_173_257_170_052_426,
    24_990_432_311_765_759,
];

/// Parameter-complete replacement profile plus its intentionally open evidence pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheRnsNativeProfileV1 {
    /// Consensus digest of the complete BGV parameter profile.
    pub profile_digest: [u8; 32],
    /// Exact ring degree.
    pub ring_degree: u32,
    /// Exact T256 slot count.
    pub slot_count: u32,
    /// Fixed party count.
    pub roster_size: u8,
    /// Exact RNS-limb count.
    pub rns_limb_count: u8,
    /// Exact full-product bit length.
    pub ciphertext_modulus_bits: u16,
    /// Corrected residual bit length.
    pub residual_bits: u16,
    /// Centered capacity below `Q/2`.
    pub centered_capacity_bits: u16,
    /// Strict residual headroom.
    pub headroom_bits: u16,
    /// Required classical security strength.
    pub target_security_bits: u16,
    /// Digest of the sole canonical composite proof topology.
    pub proof_topology_digest: [u8; 32],
    /// Digest of the exact estimator result; zero means absent.
    pub security_certificate_digest: [u8; 32],
    /// Digest of the complete composite proof KAT; zero means absent.
    pub release_kat_digest: [u8; 32],
    /// Digest of measured proof/RSS/work/I/O evidence; zero means absent.
    pub resource_evidence_digest: [u8; 32],
}

impl ZkAmsMkheRnsNativeProfileV1 {
    /// Return true only after all three external evidence classes are installed.
    #[must_use]
    pub fn evidence_complete(self) -> bool {
        [
            self.security_certificate_digest,
            self.release_kat_digest,
            self.resource_evidence_digest,
        ]
        .into_iter()
        .all(|digest| digest.iter().any(|byte| *byte != 0))
    }
}

fn profile_id_v1() -> [u8; 32] {
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Parameter,
        b"iroha.zk-ams.v1.mkhe.rns-native-profile",
        5 + 2 * ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1.len(),
    );
    hash.push_field(ZK_AMS_MKHE_RNS_NATIVE_PROOF_HASH_WIRE_SCHEMA_V1)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&fastpq_isi::GOLDILOCKS_DIGEST384_PARAMETER_SHA3_256_V1)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u64).to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1 as u64).to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 as u64).to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    for (&modulus, &root) in ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1
        .iter()
        .zip(ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1.iter())
    {
        hash.push_field(&modulus.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
        hash.push_field(&root.to_be_bytes())
            .expect("fixed bounded MKHE identity field");
    }
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}

pub(super) fn candidate_profile_v1() -> BgvProfile {
    // TODO: Replace these static ceilings with the authenticated measurements
    // bound by the release-evidence records before this profile can authorize.
    BgvProfile {
        profile_id: profile_id_v1(),
        ring_degree: ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1,
        moduli: &ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1,
        negacyclic_roots: &ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1,
        plaintext_modulus: PlaintextModulus::T256,
        error_eta: 2,
        hybrid_rns_decomposition: true,
        gadget_base_log: 60,
        gadget_digits: ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1,
        max_ciphertext_bytes: 96 * 1024 * 1024,
        max_evaluated_key_bytes: 2 * 1024 * 1024 * 1024,
        max_round_bytes: 64 * 1024 * 1024,
        max_share_bytes: 64 * 1024 * 1024,
        max_workspace_bytes: ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1 as usize,
        max_work_units: ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1,
    }
}

/// Validate and return the corrected replacement profile.
///
/// The returned evidence digests remain zero until generated by governed
/// release jobs, so this function cannot authorize production by itself.
///
/// # Errors
///
/// Returns an error when a modulus/root, capacity, or static resource invariant fails.
pub fn zk_ams_mkhe_rns_native_profile_v1() -> Result<ZkAmsMkheRnsNativeProfileV1, ZkAmsMkheErrorV1>
{
    let profile = candidate_profile_v1();
    profile.validate()?;
    let modulus_bits = u16::try_from(modulus_product_bit_len(profile.moduli)?)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?;
    let centered_capacity_bits = modulus_bits
        .checked_sub(1)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    let headroom_bits = centered_capacity_bits
        .checked_sub(ZK_AMS_MKHE_RNS_NATIVE_RESIDUAL_BITS_V1)
        .ok_or(ZkAmsMkheErrorV1::InvalidProfile)?;
    if modulus_bits != ZK_AMS_MKHE_RNS_NATIVE_MODULUS_BITS_V1
        || centered_capacity_bits != ZK_AMS_MKHE_RNS_NATIVE_CENTERED_CAPACITY_BITS_V1
        || headroom_bits != ZK_AMS_MKHE_RNS_NATIVE_HEADROOM_BITS_V1
    {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let topology = zk_ams_mkhe_rns_native_topology_v1()?;
    Ok(ZkAmsMkheRnsNativeProfileV1 {
        profile_digest: profile.digest()?,
        ring_degree: u32::try_from(profile.ring_degree)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        slot_count: u32::try_from(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        roster_size: u8::try_from(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        rns_limb_count: u8::try_from(profile.moduli.len())
            .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?,
        ciphertext_modulus_bits: modulus_bits,
        residual_bits: ZK_AMS_MKHE_RNS_NATIVE_RESIDUAL_BITS_V1,
        centered_capacity_bits,
        headroom_bits,
        target_security_bits: ZK_AMS_MKHE_RNS_NATIVE_TARGET_SECURITY_BITS_V1,
        proof_topology_digest: topology.topology_digest,
        security_certificate_digest: [0; 32],
        release_kat_digest: [0; 32],
        resource_evidence_digest: [0; 32],
    })
}

/// Canonical fixed-width manifest for the non-authorizing replacement profile.
///
/// The profile and topology digests bind the exact 40-limb parameter set and
/// proof shape.  The certified-security and external-evidence pins are frozen
/// to zero in this schema, so a syntactically valid record cannot authorize a
/// production runtime.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsMkheRnsNativeProfileManifestV1 {
    /// Manifest schema version.
    pub version: u8,
    /// Digest of the exact 40-limb BGV profile.
    pub profile_digest: [u8; 32],
    /// Digest of the sole replacement proof topology.
    pub proof_topology_digest: [u8; 32],
    /// Exact number of RNS limbs.
    pub rns_limb_count: u8,
    /// Fixed signed response width.
    pub wide_response_bytes: u16,
    /// Required classical security strength.
    pub target_security_bits: u16,
    /// Independently certified security strength; zero means absent.
    pub certified_security_bits: u16,
    /// Complete composite-proof byte ceiling.
    pub max_proof_bytes: u64,
    /// In-process proof workspace ceiling.
    pub max_workspace_bytes: u64,
    /// Retained authenticated spool ceiling.
    pub max_spool_bytes: u64,
    /// Aggregate authenticated I/O ceiling.
    pub max_authenticated_io_bytes: u64,
    /// Instrumented primitive-operation ceiling.
    pub max_work_units: u64,
    /// Estimator certificate digest; zero means no result is installed.
    pub security_certificate_digest: [u8; 32],
    /// Composite release-KAT digest; zero means no KAT is installed.
    pub release_kat_digest: [u8; 32],
    /// Authenticated resource-review digest; zero means no review is installed.
    pub resource_review_digest: [u8; 32],
    /// Digest of every preceding field.
    pub manifest_digest: [u8; 32],
}

#[cfg(test)]
impl ZkAmsMkheRnsNativeProfileManifestV1 {
    /// Validate the sole fixed, deliberately non-authorizing manifest.
    pub fn validate(self) -> Result<(), ZkAmsMkheErrorV1> {
        let profile = zk_ams_mkhe_rns_native_profile_v1()?;
        if self.version != 1
            || self.profile_digest != profile.profile_digest
            || self.proof_topology_digest != profile.proof_topology_digest
            || self.rns_limb_count
                != u8::try_from(ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1)
                    .map_err(|_| ZkAmsMkheErrorV1::InvalidProfile)?
            || self.wide_response_bytes != ZK_AMS_MKHE_RNS_NATIVE_WIDE_RESPONSE_BYTES_V1
            || self.target_security_bits != ZK_AMS_MKHE_RNS_NATIVE_TARGET_SECURITY_BITS_V1
            || self.certified_security_bits != 0
            || self.max_proof_bytes != ZK_AMS_MKHE_RNS_NATIVE_PROOF_MAX_BYTES_V1
            || self.max_workspace_bytes != ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1
            || self.max_spool_bytes != ZK_AMS_MKHE_RNS_NATIVE_SPOOL_MAX_BYTES_V1
            || self.max_authenticated_io_bytes != ZK_AMS_MKHE_RNS_NATIVE_IO_MAX_BYTES_V1
            || self.max_work_units != ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1
            || self.security_certificate_digest != [0; 32]
            || self.release_kat_digest != [0; 32]
            || self.resource_review_digest != [0; 32]
            || self.manifest_digest == [0; 32]
            || self.manifest_digest != profile_manifest_digest_v1(self)
        {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }

    /// Return whether this record can authorize a production runtime.
    ///
    /// Version 1 requires all external evidence pins to be zero, so this is
    /// intentionally always false for a valid record.
    #[must_use]
    pub fn authorizes_release(self) -> bool {
        self.validate().is_ok()
            && self.certified_security_bits >= self.target_security_bits
            && self.security_certificate_digest != [0; 32]
            && self.release_kat_digest != [0; 32]
            && self.resource_review_digest != [0; 32]
    }

    /// Encode the sole fixed-width canonical representation.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest is not the frozen replacement
    /// profile or its self digest is invalid.
    pub fn to_canonical_bytes_v1(
        self,
    ) -> Result<[u8; ZK_AMS_MKHE_RNS_NATIVE_PROFILE_MANIFEST_BYTES_V1], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; ZK_AMS_MKHE_RNS_NATIVE_PROFILE_MANIFEST_BYTES_V1];
        let mut cursor = 0;
        write_profile_manifest(&mut bytes, &mut cursor, &RNS_NATIVE_PROFILE_MANIFEST_TAG_V1)?;
        write_profile_manifest(&mut bytes, &mut cursor, &[self.version])?;
        write_profile_manifest(&mut bytes, &mut cursor, &self.profile_digest)?;
        write_profile_manifest(&mut bytes, &mut cursor, &self.proof_topology_digest)?;
        write_profile_manifest(&mut bytes, &mut cursor, &[self.rns_limb_count])?;
        for value in [
            self.wide_response_bytes,
            self.target_security_bits,
            self.certified_security_bits,
        ] {
            write_profile_manifest(&mut bytes, &mut cursor, &value.to_be_bytes())?;
        }
        for value in [
            self.max_proof_bytes,
            self.max_workspace_bytes,
            self.max_spool_bytes,
            self.max_authenticated_io_bytes,
            self.max_work_units,
        ] {
            write_profile_manifest(&mut bytes, &mut cursor, &value.to_be_bytes())?;
        }
        for digest in [
            self.security_certificate_digest,
            self.release_kat_digest,
            self.resource_review_digest,
            self.manifest_digest,
        ] {
            write_profile_manifest(&mut bytes, &mut cursor, &digest)?;
        }
        if cursor != bytes.len() {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(bytes)
    }

    /// Decode and validate exactly one canonical representation.
    ///
    /// # Errors
    ///
    /// Returns an error for every wrong length, tag, field, evidence pin, or
    /// digest.
    pub fn from_canonical_bytes_exact_v1(bytes: &[u8]) -> Result<Self, ZkAmsMkheErrorV1> {
        if bytes.len() != ZK_AMS_MKHE_RNS_NATIVE_PROFILE_MANIFEST_BYTES_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let mut decoder = ProfileManifestDecoder::new(bytes);
        if decoder.array::<4>()? != RNS_NATIVE_PROFILE_MANIFEST_TAG_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let manifest = Self {
            version: decoder.u8()?,
            profile_digest: decoder.array()?,
            proof_topology_digest: decoder.array()?,
            rns_limb_count: decoder.u8()?,
            wide_response_bytes: decoder.u16()?,
            target_security_bits: decoder.u16()?,
            certified_security_bits: decoder.u16()?,
            max_proof_bytes: decoder.u64()?,
            max_workspace_bytes: decoder.u64()?,
            max_spool_bytes: decoder.u64()?,
            max_authenticated_io_bytes: decoder.u64()?,
            max_work_units: decoder.u64()?,
            security_certificate_digest: decoder.array()?,
            release_kat_digest: decoder.array()?,
            resource_review_digest: decoder.array()?,
            manifest_digest: decoder.array()?,
        };
        decoder.finish()?;
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Build the canonical, deliberately non-authorizing replacement manifest.
///
/// # Errors
///
/// Returns an error if the replacement profile, topology, resource fields, or
/// manifest digest fail validation.
#[cfg(test)]
pub fn zk_ams_mkhe_rns_native_profile_manifest_v1()
-> Result<ZkAmsMkheRnsNativeProfileManifestV1, ZkAmsMkheErrorV1> {
    let profile = zk_ams_mkhe_rns_native_profile_v1()?;
    let mut manifest = ZkAmsMkheRnsNativeProfileManifestV1 {
        version: 1,
        profile_digest: profile.profile_digest,
        proof_topology_digest: profile.proof_topology_digest,
        rns_limb_count: profile.rns_limb_count,
        wide_response_bytes: ZK_AMS_MKHE_RNS_NATIVE_WIDE_RESPONSE_BYTES_V1,
        target_security_bits: profile.target_security_bits,
        certified_security_bits: 0,
        max_proof_bytes: ZK_AMS_MKHE_RNS_NATIVE_PROOF_MAX_BYTES_V1,
        max_workspace_bytes: ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1,
        max_spool_bytes: ZK_AMS_MKHE_RNS_NATIVE_SPOOL_MAX_BYTES_V1,
        max_authenticated_io_bytes: ZK_AMS_MKHE_RNS_NATIVE_IO_MAX_BYTES_V1,
        max_work_units: ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1,
        security_certificate_digest: [0; 32],
        release_kat_digest: [0; 32],
        resource_review_digest: [0; 32],
        manifest_digest: [0; 32],
    };
    manifest.manifest_digest = profile_manifest_digest_v1(manifest);
    manifest.validate()?;
    Ok(manifest)
}

/// Return the domain-separated identity of the non-authorizing replacement candidate.
///
/// This deliberately does not reuse the legacy 38-limb release-manifest
/// digest. It identifies the corrected 40-limb profile, topology, and open
/// evidence slots, but cannot authorize production while those slots remain
/// zero and the global readiness gate remains closed.
///
/// # Errors
///
/// Returns an error when the replacement profile manifest is not canonical.
#[cfg(test)]
pub(super) fn zk_ams_mkhe_rns_native_release_candidate_digest_v1()
-> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let manifest = zk_ams_mkhe_rns_native_profile_manifest_v1()?;
    manifest.validate()?;
    let mut hash = Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.rns-native-release-candidate");
    hash.update(&[manifest.version]);
    hash.update(&manifest.manifest_digest);
    hash.update(&manifest.profile_digest);
    hash.update(&manifest.proof_topology_digest);
    let digest = hash.finalize();
    if digest == [0; 32] || digest == manifest.manifest_digest {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(digest)
}

#[cfg(test)]
fn profile_manifest_digest_v1(manifest: ZkAmsMkheRnsNativeProfileManifestV1) -> [u8; 32] {
    let mut hash = Keccak256::new();
    hash.update(b"iroha.zk-ams.v1.mkhe.rns-native-profile-manifest");
    hash.update(&[manifest.version]);
    hash.update(&manifest.profile_digest);
    hash.update(&manifest.proof_topology_digest);
    hash.update(&[manifest.rns_limb_count]);
    hash.update(&manifest.wide_response_bytes.to_be_bytes());
    hash.update(&manifest.target_security_bits.to_be_bytes());
    hash.update(&manifest.certified_security_bits.to_be_bytes());
    for value in [
        manifest.max_proof_bytes,
        manifest.max_workspace_bytes,
        manifest.max_spool_bytes,
        manifest.max_authenticated_io_bytes,
        manifest.max_work_units,
    ] {
        hash.update(&value.to_be_bytes());
    }
    hash.update(&manifest.security_certificate_digest);
    hash.update(&manifest.release_kat_digest);
    hash.update(&manifest.resource_review_digest);
    hash.finalize()
}

#[cfg(test)]
fn write_profile_manifest<const N: usize>(
    destination: &mut [u8; N],
    cursor: &mut usize,
    source: &[u8],
) -> Result<(), ZkAmsMkheErrorV1> {
    let end = cursor
        .checked_add(source.len())
        .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?;
    destination
        .get_mut(*cursor..end)
        .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?
        .copy_from_slice(source);
    *cursor = end;
    Ok(())
}

#[cfg(test)]
struct ProfileManifestDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

#[cfg(test)]
impl<'a> ProfileManifestDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZkAmsMkheErrorV1> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?
            .try_into()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ZkAmsMkheErrorV1> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ZkAmsMkheErrorV1> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ZkAmsMkheErrorV1> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.cursor != self.bytes.len() {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn native_profile_rejects_former_three_point_global_mask_contract() {
        use super::*;
        // Independently reconstructed complete canonical descriptor preimages.
        assert_eq!(
            profile_id_v1(),
            [
                0xc8, 0xd8, 0x56, 0xf6, 0x04, 0xd2, 0x6d, 0x2d, 0x53, 0x71, 0x82, 0x4b, 0xff, 0x55,
                0x5e, 0xd6, 0x24, 0x13, 0xaa, 0x1e, 0x31, 0x01, 0x39, 0xdb, 0x62, 0x18, 0xc6, 0x0b,
                0x32, 0x26, 0xeb, 0xec
            ]
        );
        // Canonical frame geometry changes every dependent identity.
        // These fixed values were derived independently from the complete frames.
        let current = zk_ams_mkhe_rns_native_profile_manifest_v1().expect("current manifest");
        assert_eq!(
            candidate_profile_v1()
                .digest()
                .expect("current BGV profile"),
            [
                0xba, 0x9f, 0x14, 0x2c, 0x16, 0xec, 0xa4, 0x73, 0x59, 0x94, 0x11, 0x49, 0x5a, 0xc1,
                0x97, 0x95, 0x83, 0x1a, 0xe8, 0x5b, 0x28, 0xad, 0xdf, 0xa4, 0x7e, 0x13, 0xf8, 0x01,
                0xb2, 0xa8, 0x1a, 0x1a
            ]
        );
        assert_eq!(
            current.profile_digest,
            candidate_profile_v1()
                .digest()
                .expect("current BGV profile")
        );
        assert_eq!(
            current.manifest_digest,
            [
                0xfa, 0x8f, 0x09, 0xf4, 0xa0, 0x4b, 0x9f, 0x01, 0x1d, 0xf2, 0xd0, 0xed, 0x69, 0x9f,
                0x0c, 0x6a, 0x00, 0xdf, 0x10, 0xfb, 0xc7, 0xbf, 0xe4, 0xbc, 0x9c, 0x3e, 0x15, 0x46,
                0xd0, 0x00, 0xc2, 0x3e
            ]
        );
        assert_eq!(
            zk_ams_mkhe_rns_native_release_candidate_digest_v1().expect("current candidate"),
            [
                0x4f, 0xfa, 0xc4, 0xf9, 0xb7, 0x57, 0x28, 0x5e, 0x07, 0xf2, 0x00, 0xb0, 0xbe, 0x96,
                0x3a, 0x51, 0x15, 0x4f, 0x34, 0x79, 0xa2, 0x5f, 0xfe, 0x0f, 0xf5, 0x9d, 0x93, 0x51,
                0xbe, 0xfb, 0xb0, 0xfd
            ]
        );
        let mut stale_frame_parameters = candidate_profile_v1();
        stale_frame_parameters.profile_id = [
            0x58, 0x0c, 0x09, 0x39, 0x8e, 0xe4, 0xd6, 0x6f, 0xa6, 0x47, 0xec, 0x89, 0xac, 0x2d,
            0xe2, 0xb7, 0x16, 0x3b, 0x4e, 0x47, 0x89, 0x2a, 0x42, 0x45, 0xc1, 0xf6, 0x20, 0xb3,
            0x3e, 0x0e, 0x26, 0x75,
        ];
        let mut stale_frame = current;
        stale_frame.profile_digest = stale_frame_parameters
            .digest()
            .expect("self-consistent stale frame profile");
        stale_frame.manifest_digest = profile_manifest_digest_v1(stale_frame);
        assert!(stale_frame.validate().is_err());
        let mut retired_parameters = candidate_profile_v1();
        retired_parameters.profile_id = [
            0x79, 0xd8, 0x4e, 0xb4, 0x82, 0x8a, 0x38, 0x4b, 0xc8, 0xc3, 0xdc, 0x71, 0x77, 0xa2,
            0xea, 0x0d, 0xa7, 0xed, 0x3f, 0xd2, 0x45, 0x01, 0x62, 0xde, 0x3d, 0xe2, 0x20, 0x95,
            0xd3, 0xd5, 0x81, 0x82,
        ];
        let mut retired = zk_ams_mkhe_rns_native_profile_manifest_v1().expect("current manifest");
        retired.profile_digest = retired_parameters
            .digest()
            .expect("retired descriptor identity");
        retired.manifest_digest = profile_manifest_digest_v1(retired);
        assert!(retired.validate().is_err());
    }

    #[test]
    fn revised_proof_contract_changes_profile_identity_and_rejects_old_manifest() {
        use super::*;
        let mut retired = Keccak256::new();
        retired.update(b"iroha.zk-ams.v1.mkhe.rns-native-profile");
        retired.update(&(ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u64).to_be_bytes());
        retired.update(&(ZK_AMS_MKHE_RELEASE_SLOT_COUNT_V1 as u64).to_be_bytes());
        retired.update(&(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 as u64).to_be_bytes());
        for (&modulus, &root) in ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1
            .iter()
            .zip(ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1.iter())
        {
            retired.update(&modulus.to_be_bytes());
            retired.update(&root.to_be_bytes());
        }
        let retired_profile = retired.finalize();
        assert_ne!(profile_id_v1(), retired_profile);
        let mut retired_parameters = candidate_profile_v1();
        retired_parameters.profile_id = retired_profile;
        let retired_profile_digest = retired_parameters.digest().unwrap();
        let current = zk_ams_mkhe_rns_native_profile_manifest_v1().unwrap();
        current.validate().unwrap();
        assert_ne!(current.profile_digest, retired_profile_digest);
        let mut old_profile = current;
        old_profile.profile_digest = retired_profile_digest;
        // Recompute the outer identity, so rejection proves the profile cutover
        // rather than a stale checksum after an unrelated field mutation.
        old_profile.manifest_digest = profile_manifest_digest_v1(old_profile);
        assert!(old_profile.validate().is_err());
        assert_eq!(
            ZK_AMS_MKHE_RNS_NATIVE_INITIAL_MULTIPROOF_MAX_BYTES_V1,
            4_313_088
        );
        assert_eq!(
            ZK_AMS_MKHE_RNS_NATIVE_CORRELATED_FRI_MAX_BYTES_V1,
            26_409_984
        );
        assert_eq!(ZK_AMS_MKHE_RNS_NATIVE_QPCS_MAX_BYTES_V1, 30_740_352);
        assert_eq!(ZK_AMS_MKHE_RNS_NATIVE_PROOF_MAX_BYTES_V1, 40 * 1024 * 1024);
    }
    use super::*;
    use crate::vega::zk_ams::mkhe::mod_pow;

    #[test]
    fn governed_native_chain_owns_the_release_prefix_and_reproduces_every_root() {
        use super::super::manifest::{RELEASE_MODULI_V1, RELEASE_NEGACYCLIC_ROOTS_V1};
        assert_eq!(
            &ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1[..RELEASE_MODULI_V1.len()],
            &RELEASE_MODULI_V1
        );
        assert_eq!(
            &ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1[..RELEASE_NEGACYCLIC_ROOTS_V1.len()],
            &RELEASE_NEGACYCLIC_ROOTS_V1
        );
        let order = 2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u64;
        for (index, (&modulus, &root)) in ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1
            .iter()
            .zip(ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1.iter())
            .enumerate()
        {
            let base = (2..=64)
                .find(|base| mod_pow(*base, (modulus - 1) / 2, modulus) == modulus - 1)
                .expect("every governed prime has a small quadratic nonresidue");
            assert_eq!(
                root,
                mod_pow(base, (modulus - 1) / order, modulus),
                "limb {index}"
            );
        }
    }

    #[test]
    fn malformed_native_roots_are_rejected_by_the_actual_profile_validator() {
        const BAD_FIRST: [u64; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1] = {
            let mut roots = ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1;
            roots[13] = 418_880_473_610_227_419;
            roots
        };
        const BAD_SECOND: [u64; ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1] = {
            let mut roots = ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1;
            roots[27] = 610_386_825_931_585_809;
            roots
        };
        let mut profile = candidate_profile_v1();
        profile.validate().expect("canonical native profile");
        for bad_roots in [&BAD_FIRST, &BAD_SECOND] {
            profile.negacyclic_roots = bad_roots;
            assert_eq!(profile.validate(), Err(ZkAmsMkheErrorV1::InvalidProfile));
        }
    }

    #[test]
    fn corrected_chain_is_prime_unique_and_negacyclic() {
        let twice_degree = 2 * ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u64;
        for (index, (&modulus, &root)) in ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1
            .iter()
            .zip(ZK_AMS_MKHE_RNS_NATIVE_NEGACYCLIC_ROOTS_V1.iter())
            .enumerate()
        {
            assert!(super::super::is_prime_u64(modulus));
            assert_eq!(modulus % twice_degree, 1);
            assert_eq!(mod_pow(root, twice_degree, modulus), 1);
            assert_eq!(
                mod_pow(root, ZK_AMS_MKHE_RELEASE_RING_DEGREE_V1 as u64, modulus),
                modulus - 1
            );
            assert!(!ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1[..index].contains(&modulus));
        }
    }

    #[test]
    fn corrected_capacity_has_the_governed_headroom() {
        let profile = zk_ams_mkhe_rns_native_profile_v1().expect("valid corrected profile");
        assert_eq!(profile.rns_limb_count, 40);
        assert_eq!(profile.ciphertext_modulus_bits, 2_400);
        assert_eq!(profile.centered_capacity_bits, 2_399);
        assert_eq!(profile.residual_bits, 2_287);
        assert_eq!(profile.headroom_bits, 112);
        assert_eq!(
            profile.proof_topology_digest,
            zk_ams_mkhe_rns_native_topology_v1()
                .unwrap()
                .topology_digest
        );
        assert_ne!(profile.profile_digest, [0; 32]);
    }

    #[test]
    fn replacement_topology_is_exact_and_digest_bound() {
        let topology = zk_ams_mkhe_rns_native_topology_v1().unwrap();
        assert_eq!(topology.family_record_counts, [1, 16, 16, 1, 8, 1]);
        assert_eq!(topology.opening_count, 43);
        assert_eq!(topology.rlwe_equation_count, 2);
        assert_eq!(topology.cross_field_point_count, 5);
        assert_eq!(topology.lde_domain_log2, 19);
        assert_eq!(topology.query_count, 160);
        assert_eq!(topology.fri_rounds, 18);
        assert_eq!(topology.radix_log2, 15);
        assert_eq!(topology.quotient_bits, 103);
        assert_eq!(topology.sumcheck_rounds, 29);
        assert_eq!(topology.max_initial_multiproof_bytes, 4_313_088);
        assert_eq!(topology.max_correlated_fri_bytes, 26_409_984);
        assert_eq!(topology.max_qpcs_bytes, 30_740_352);
        assert_eq!(topology.max_proof_bytes, 40 * 1024 * 1024);
        assert_ne!(topology.topology_digest, [0; 32]);

        let mut changed = topology;
        changed.query_count -= 1;
        assert_eq!(changed.validate(), Err(ZkAmsMkheErrorV1::InvalidProfile));
    }

    #[test]
    fn replacement_candidate_identity_is_distinct_from_legacy_and_profile_manifests() {
        let manifest = zk_ams_mkhe_rns_native_profile_manifest_v1().unwrap();
        let candidate = zk_ams_mkhe_rns_native_release_candidate_digest_v1().unwrap();
        assert_ne!(candidate, [0; 32]);
        assert_ne!(candidate, manifest.manifest_digest);
        assert_ne!(
            candidate,
            super::super::manifest::zk_ams_mkhe_manifest_digest_v1().unwrap()
        );
        assert_eq!(
            candidate,
            zk_ams_mkhe_rns_native_release_candidate_digest_v1().unwrap()
        );
    }

    #[test]
    fn parameter_profile_is_not_release_evidence() {
        let profile = zk_ams_mkhe_rns_native_profile_v1().expect("valid corrected profile");
        assert!(!profile.evidence_complete());
        assert_eq!(profile.security_certificate_digest, [0; 32]);
        assert_eq!(profile.release_kat_digest, [0; 32]);
        assert_eq!(profile.resource_evidence_digest, [0; 32]);
    }

    #[test]
    fn replacement_manifest_roundtrips_exact_fixed_width() {
        let manifest = zk_ams_mkhe_rns_native_profile_manifest_v1().unwrap();
        let bytes = manifest.to_canonical_bytes_v1().unwrap();

        assert_eq!(
            bytes.len(),
            ZK_AMS_MKHE_RNS_NATIVE_PROFILE_MANIFEST_BYTES_V1
        );
        assert_eq!(&bytes[..4], &RNS_NATIVE_PROFILE_MANIFEST_TAG_V1);
        assert_eq!(
            ZkAmsMkheRnsNativeProfileManifestV1::from_canonical_bytes_exact_v1(&bytes).unwrap(),
            manifest
        );
        assert_ne!(manifest.manifest_digest, [0; 32]);
        assert!(!manifest.authorizes_release());
    }

    #[test]
    fn replacement_manifest_pins_exact_dimensions_caps_and_absent_evidence() {
        let manifest = zk_ams_mkhe_rns_native_profile_manifest_v1().unwrap();

        assert_eq!(manifest.rns_limb_count, 40);
        assert_eq!(manifest.wide_response_bytes, 258);
        assert_eq!(manifest.target_security_bits, 128);
        assert_eq!(manifest.certified_security_bits, 0);
        assert_eq!(manifest.max_proof_bytes, 40 * 1024 * 1024);
        assert_eq!(manifest.max_workspace_bytes, 512 * 1024 * 1024);
        assert_eq!(manifest.max_spool_bytes, 16 * 1024 * 1024 * 1024);
        assert_eq!(manifest.max_authenticated_io_bytes, 64 * 1024 * 1024 * 1024);
        assert_eq!(manifest.max_work_units, 128_000_000_000);
        assert_eq!(manifest.security_certificate_digest, [0; 32]);
        assert_eq!(manifest.release_kat_digest, [0; 32]);
        assert_eq!(manifest.resource_review_digest, [0; 32]);
        assert_eq!(
            manifest.proof_topology_digest,
            zk_ams_mkhe_rns_native_topology_v1()
                .unwrap()
                .topology_digest
        );
    }

    #[test]
    fn replacement_manifest_exact_decoder_rejects_every_wrong_length() {
        let bytes = zk_ams_mkhe_rns_native_profile_manifest_v1()
            .unwrap()
            .to_canonical_bytes_v1()
            .unwrap();
        for length in 0..bytes.len() {
            assert_eq!(
                ZkAmsMkheRnsNativeProfileManifestV1::from_canonical_bytes_exact_v1(
                    &bytes[..length]
                ),
                Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
            );
        }
        for trailing_bytes in 1..=8 {
            let mut extended = bytes.to_vec();
            extended.resize(bytes.len() + trailing_bytes, 0);
            assert_eq!(
                ZkAmsMkheRnsNativeProfileManifestV1::from_canonical_bytes_exact_v1(&extended),
                Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
            );
        }
    }

    #[test]
    fn replacement_manifest_rejects_every_single_byte_mutation() {
        let bytes = zk_ams_mkhe_rns_native_profile_manifest_v1()
            .unwrap()
            .to_canonical_bytes_v1()
            .unwrap();
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert_eq!(
                ZkAmsMkheRnsNativeProfileManifestV1::from_canonical_bytes_exact_v1(&changed),
                Err(ZkAmsMkheErrorV1::InvalidWireEncoding),
                "mutation at byte {index} was accepted"
            );
        }
    }

    #[test]
    fn replacement_manifest_rejects_self_consistent_evidence_substitution() {
        let manifest = zk_ams_mkhe_rns_native_profile_manifest_v1().unwrap();
        let mut changed_records = [
            ZkAmsMkheRnsNativeProfileManifestV1 {
                certified_security_bits: manifest.target_security_bits,
                ..manifest
            },
            ZkAmsMkheRnsNativeProfileManifestV1 {
                security_certificate_digest: [1; 32],
                ..manifest
            },
            ZkAmsMkheRnsNativeProfileManifestV1 {
                release_kat_digest: [1; 32],
                ..manifest
            },
            ZkAmsMkheRnsNativeProfileManifestV1 {
                resource_review_digest: [1; 32],
                ..manifest
            },
        ];
        for changed in &mut changed_records {
            changed.manifest_digest = profile_manifest_digest_v1(*changed);
            assert_eq!(
                changed.validate(),
                Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
            );
            assert!(!changed.authorizes_release());
        }
    }
}
