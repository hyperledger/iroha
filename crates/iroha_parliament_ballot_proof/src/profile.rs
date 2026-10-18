//! The two experimental parameter rows and the fixed descriptor of the
//! construction (evaluation record sections 6.1, 6.3 and 6.6).
//!
//! **Neither row is selected or qualified.** [`Row::Candidate`] is the fast row
//! `(lambda, tau, w_grind, T_open, d_zk) = (256, 33, 8, 229, 7)` with 704 CRT
//! gates, the sole integration candidate; `Row::Comparator` is the small row
//! `(256, 22, 6, 225, 7)` with 696 gates, a measurement comparator only. A row is
//! always chosen by the caller: nothing in this crate detects a row from proof
//! bytes.
//!
//! The comparator row is test and diagnostic support (integration decision 6): it
//! exists only in this crate's own unit tests and in builds with the non-default
//! `diagnostics` feature, which only the measurement and diagnostic tooling enables
//! (the comparator examples, the comparator integration tests, the fuzz crate and
//! the separately built diagnostic drivers). Node, wallet and native-bridge
//! dependencies never enable it, so production builds compile the candidate row
//! only and [`Row::ALL`] is `[Row::Candidate]` there.
//!
//! A [`Profile`] is the compiled descriptor of one row: the CRT table digest
//! `T_crt`, the descriptor `DESC`, its digest `D`, the role namespaces `NS_REG`
//! and `NS_VOTE` and the 77-byte prefixes `PREFIX_R` that every backend hash call
//! of a ballot proof absorbs first. It is recomputed from the backend's embedded
//! tables whenever it is built (there is no global or lazily initialised state)
//! and pinned by tests to the digest values printed in the record.

#[cfg(any(test, feature = "diagnostics"))]
use iroha_zkp_vole::params::FAEST_256S;
use iroha_zkp_vole::{
    crt::{CrtError, codec::encode_words},
    hash::{HashError, Namespace, Xof},
    params::{D_ZK, FAEST_256F, SecurityLevel, VoleParams},
    proof::{ProofContext, ProofError},
};
use thiserror::Error;

use crate::{
    framing::{DIGEST_BYTES, Digest64, FramingError, frame_bytes, frame_digest},
    layout::{
        REGISTRATION_CONSTRAINTS, REGISTRATION_WITNESS_BITS, VOTE_CONSTRAINTS, VOTE_WITNESS_BITS,
    },
};

/// The 16-byte construction domain `P16`: ASCII `PARL-SHAKE-V1` and three zero
/// bytes. An identifier, not a security parameter. It is not the public profile
/// identifier, which is the candidate descriptor digest `D`.
pub const P16: [u8; 16] = *b"PARL-SHAKE-V1\0\0\0";

/// `SUITE`: the 129-byte name of the frozen relation, constraint order, encodings,
/// transcript and randomness rules. Not an options string.
pub const SUITE: &[u8; 129] =
    b"KECCAK-F1600/2R-FWD/SEL-32X32-PREFIX/PAD-256/TAPE-112/CTR-U20-LE32/NS-PREFIX77/NF-1024/VAUTH-512/SALT-256/H5-SALT/LEAF-AFFINE-896";

/// The backend label of the descriptor.
pub const BACKEND_LABEL: &[u8; 9] = b"FAEST-3.0";

/// The ASCII literal that starts every role prefix.
pub const PREFIX_LITERAL: &[u8; 13] = b"PARL/FAEST/v1";

/// Length of `PREFIX_R` in bytes.
pub const PREFIX_BYTES: usize = PREFIX_LITERAL.len() + DIGEST_BYTES;

/// Length of `DESC` in bytes, on both rows.
pub const DESCRIPTOR_BYTES: usize = 286;

/// The security level of both rows.
pub const LEVEL: SecurityLevel = SecurityLevel::L256;

/// Errors of building a [`Profile`]. None is reachable from untrusted input: they
/// report a backend without the expected embedded tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProfileError {
    /// The backend has no embedded CRT tables for the row.
    #[error(transparent)]
    Tables(#[from] CrtError),
    /// A descriptor frame could not be built.
    #[error(transparent)]
    Framing(#[from] FramingError),
    /// The descriptor does not have its fixed length.
    #[error("the descriptor is {actual} bytes long instead of {DESCRIPTOR_BYTES}")]
    DescriptorLength {
        /// Length produced.
        actual: usize,
    },
    /// The backend rejected the role prefix as a namespace.
    #[error(transparent)]
    Namespace(#[from] HashError),
    /// The backend rejected the proof context.
    #[error(transparent)]
    Context(#[from] ProofError),
}

/// One of the two experimental parameter rows. Neither is selected or qualified.
///
/// The comparator variant is compiled only for this crate's unit tests and with the
/// `diagnostics` feature; see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Row {
    /// The fast row `(256, 33, 8, 229, 7)`, 704 gates: the integration candidate.
    Candidate,
    /// The small row `(256, 22, 6, 225, 7)`, 696 gates: a measurement comparator for
    /// tests and diagnostics, never compiled into production builds.
    #[cfg(any(test, feature = "diagnostics"))]
    Comparator,
}

/// The two relations, which are also the two transcript roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Registration, role string `REG`.
    Registration,
    /// Vote, role string `VOTE`.
    Vote,
}

impl Role {
    /// Both roles.
    pub const ALL: [Self; 2] = [Self::Registration, Self::Vote];

    /// The ASCII role string of the namespace frame.
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Registration => b"REG",
            Self::Vote => b"VOTE",
        }
    }

    /// Witness length `l` of the role's relation in bits.
    pub const fn witness_bits(self) -> usize {
        match self {
            Self::Registration => REGISTRATION_WITNESS_BITS,
            Self::Vote => VOTE_WITNESS_BITS,
        }
    }

    /// Total constraint count `N_c` of the role's relation, Booleanity included.
    pub const fn constraints(self) -> usize {
        match self {
            Self::Registration => REGISTRATION_CONSTRAINTS,
            Self::Vote => VOTE_CONSTRAINTS,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Registration => 0,
            Self::Vote => 1,
        }
    }
}

/// A field of the naked proof, in layout order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofField {
    /// `c_1 || ... || c_(tau-1)`.
    Corrections,
    /// `c_mult`.
    MultCorrections,
    /// `u_tilde`.
    UTilde,
    /// The masked witness `d`.
    MaskedWitness,
    /// `a_1 || ... || a_6`.
    Coefficients,
    /// The `tau` hidden-leaf commitments of the opening.
    HiddenLeafCommitments,
    /// The seed area of the opening, `T_open` slots of 32 bytes.
    NodeSeeds,
    /// `chall_3`.
    Challenge,
    /// `iv_pre`.
    IvPre,
    /// The public 32-byte salt.
    Salt,
    /// `u32_le(ctr)`.
    Counter,
}

/// One field of the naked proof with its position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProofSegment {
    /// The field.
    pub field: ProofField,
    /// Offset of its first byte.
    pub offset: usize,
    /// Its length in bytes.
    pub len: usize,
}

impl Row {
    /// Every compiled row: the candidate and, in test and diagnostic builds, the
    /// comparator.
    #[cfg(any(test, feature = "diagnostics"))]
    pub const ALL: [Self; 2] = [Self::Candidate, Self::Comparator];

    /// Every compiled row: the candidate only, in production builds.
    #[cfg(not(any(test, feature = "diagnostics")))]
    pub const ALL: [Self; 1] = [Self::Candidate];

    /// The backend row: the VOLE geometry of FAEST-256f (candidate) or FAEST-256s
    /// (comparator), with the official CRT tables.
    pub const fn vole(self) -> VoleParams {
        match self {
            Self::Candidate => *FAEST_256F.vole(),
            #[cfg(any(test, feature = "diagnostics"))]
            Self::Comparator => *FAEST_256S.vole(),
        }
    }

    /// The exact length in bytes of every proof of `role` on this row.
    pub const fn proof_bytes(self, role: Role) -> usize {
        match (self, role) {
            (Self::Candidate, Role::Registration) => 160_148,
            (Self::Candidate, Role::Vote) => 233_012,
            #[cfg(any(test, feature = "diagnostics"))]
            (Self::Comparator, Role::Registration) => 109_498,
            #[cfg(any(test, feature = "diagnostics"))]
            (Self::Comparator, Role::Vote) => 158_074,
        }
    }

    /// The naked proof layout of `role` on this row (record section 6.6).
    pub fn proof_layout(self, role: Role) -> [ProofSegment; 11] {
        let vole = self.vole();
        let lambda_bytes = vole.lambda().bytes();
        let witness_bytes = role.witness_bits() / 8;
        let lengths = [
            (ProofField::Corrections, (vole.tau() - 1) * witness_bytes),
            (
                ProofField::MultCorrections,
                (vole.n_mask() * vole.n_mult()).div_ceil(8),
            ),
            (ProofField::UTilde, 4 * lambda_bytes),
            (ProofField::MaskedWitness, witness_bytes),
            (ProofField::Coefficients, (D_ZK - 1) * lambda_bytes),
            (
                ProofField::HiddenLeafCommitments,
                vole.tau() * (vole.leaf_commitment_bytes() + 16),
            ),
            (ProofField::NodeSeeds, vole.t_open() * lambda_bytes),
            (ProofField::Challenge, lambda_bytes),
            (ProofField::IvPre, 16),
            (ProofField::Salt, 32),
            (ProofField::Counter, 4),
        ];
        let mut offset = 0;
        lengths.map(|(field, len)| {
            let segment = ProofSegment { field, offset, len };
            offset += len;
            segment
        })
    }
}

/// `CRT_BYTES` of `row`: the backend's canonical word codec of the row's embedded
/// CRT tables, each word little-endian.
///
/// # Errors
/// [`ProfileError::Tables`] if the backend has no embedded tables for the row.
pub fn crt_bytes(row: Row) -> Result<Vec<u8>, ProfileError> {
    let words = encode_words(row.vole().crt_tables()?);
    Ok(words.iter().flat_map(|word| word.to_le_bytes()).collect())
}

/// `T_crt = SHAKE256(CRT_BYTES, 64 bytes)` of `row`.
///
/// # Errors
/// As [`crt_bytes`].
pub fn crt_table_digest(row: Row) -> Result<Digest64, ProfileError> {
    let bytes = crt_bytes(row)?;
    let mut xof = Xof::new(LEVEL);
    xof.update(&bytes);
    let mut digest = [0u8; DIGEST_BYTES];
    xof.finalize().squeeze(&mut digest);
    Ok(Digest64(digest))
}

/// `u16_le` of a descriptor parameter; every parameter of both rows fits.
fn u16_le(value: usize) -> [u8; 2] {
    u16::try_from(value).unwrap_or(u16::MAX).to_le_bytes()
}

/// `u32_le` of a relation dimension; every dimension fits.
fn u32_le(value: usize) -> [u8; 4] {
    u32::try_from(value).unwrap_or(u32::MAX).to_le_bytes()
}

/// `DESC` of `row` for the table digest `table_digest`.
fn descriptor_bytes(row: Row, table_digest: &Digest64) -> Result<Vec<u8>, ProfileError> {
    let vole = row.vole();
    let parameters = [
        vole.lambda().bits(),
        vole.tau(),
        vole.w_grind(),
        vole.t_open(),
        vole.d_zk(),
        vole.n_mult(),
    ]
    .map(u16_le)
    .concat();
    let dimensions = [
        REGISTRATION_WITNESS_BITS,
        REGISTRATION_CONSTRAINTS,
        VOTE_WITNESS_BITS,
        VOTE_CONSTRAINTS,
    ]
    .map(u32_le)
    .concat();
    Ok(frame_bytes(
        b"PARL/DESC/v1",
        &[
            &P16,
            BACKEND_LABEL,
            &parameters,
            table_digest.as_bytes(),
            &dimensions,
            SUITE,
        ],
    )?)
}

/// `NS_R = SHA3-512(Frame("PARL/NS/v1"; D, ASCII(role)))`.
///
/// # Errors
/// Only if the frame cannot be built, which no input causes.
pub fn namespace_digest(
    descriptor_digest: &Digest64,
    role: Role,
) -> Result<Digest64, ProfileError> {
    Ok(frame_digest(
        b"PARL/NS/v1",
        &[descriptor_digest.as_bytes(), role.label()],
    )?)
}

/// The compiled descriptor of one row. Public; see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    row: Row,
    table_digest: Digest64,
    descriptor: [u8; DESCRIPTOR_BYTES],
    descriptor_digest: Digest64,
    namespaces: [Digest64; 2],
    prefixes: [[u8; PREFIX_BYTES]; 2],
}

impl Profile {
    /// Compile the descriptor of `row` from the backend's embedded CRT tables.
    ///
    /// # Errors
    /// [`ProfileError`] if the backend lacks the tables; no caller input is
    /// involved.
    pub fn new(row: Row) -> Result<Self, ProfileError> {
        let table_digest = crt_table_digest(row)?;
        let bytes = descriptor_bytes(row, &table_digest)?;
        let descriptor = <[u8; DESCRIPTOR_BYTES]>::try_from(bytes.as_slice()).map_err(|_| {
            ProfileError::DescriptorLength {
                actual: bytes.len(),
            }
        })?;
        let descriptor_digest = Digest64(iroha_zkp_vole::hash::sha3_512(&[&descriptor]));
        let mut namespaces = [Digest64([0; DIGEST_BYTES]); 2];
        let mut prefixes = [[0u8; PREFIX_BYTES]; 2];
        for role in Role::ALL {
            let namespace = namespace_digest(&descriptor_digest, role)?;
            let (literal, digest) = prefixes[role.index()].split_at_mut(PREFIX_LITERAL.len());
            literal.copy_from_slice(PREFIX_LITERAL);
            digest.copy_from_slice(namespace.as_bytes());
            namespaces[role.index()] = namespace;
        }
        Ok(Self {
            row,
            table_digest,
            descriptor,
            descriptor_digest,
            namespaces,
            prefixes,
        })
    }

    /// The row.
    pub const fn row(&self) -> Row {
        self.row
    }

    /// `T_crt`.
    pub const fn table_digest(&self) -> &Digest64 {
        &self.table_digest
    }

    /// `DESC`.
    pub const fn descriptor(&self) -> &[u8; DESCRIPTOR_BYTES] {
        &self.descriptor
    }

    /// `D = SHA3-512(DESC)`.
    pub const fn descriptor_digest(&self) -> &Digest64 {
        &self.descriptor_digest
    }

    /// `NS_REG` or `NS_VOTE`.
    pub const fn namespace_digest(&self, role: Role) -> &Digest64 {
        &self.namespaces[role.index()]
    }

    /// `PREFIX_R = ASCII("PARL/FAEST/v1") || NS_R`, 77 bytes.
    pub const fn prefix(&self, role: Role) -> &[u8; PREFIX_BYTES] {
        &self.prefixes[role.index()]
    }

    /// The backend namespace of `role`: every oracle call absorbs `PREFIX_R`.
    ///
    /// # Errors
    /// Only if the backend refuses a 77-byte prefix, which it does not.
    pub fn namespace(&self, role: Role) -> Result<Namespace<'_>, ProfileError> {
        Ok(Namespace::new(self.prefix(role))?)
    }

    /// The backend proof context of `role` on this row.
    ///
    /// # Errors
    /// As [`Profile::namespace`].
    pub fn context(&self, role: Role) -> Result<ProofContext<'_>, ProfileError> {
        Ok(ProofContext::extended(
            self.namespace(role)?,
            self.row.vole(),
        )?)
    }

    /// The exact proof length of `role` on this row.
    pub const fn proof_bytes(&self, role: Role) -> usize {
        self.row.proof_bytes(role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digits"))
            .collect()
    }

    /// The four digests printed in section 6.1 of the record.
    const T_CRT_FAST: &str = "a9c572a7c8f2cc735218123c6456e1e016e78b06aa2d03192ef801bf7fdb93ae014a9e16555e6bad81382c630467e45e76c9b1c3948f9dfea41a7a1435bcffea";
    const T_CRT_SMALL: &str = "792f81bf102cac84b7c559595342b6b23ad27dab9065651feb928dd0a649a3f4bd1da3d350fbd4c62f1707d441d46ef084430b5f00b53a1af7088281d6a7386e";
    const D_FAST: &str = "01ed9f564981a07ab383d513c4e816f5a76542c7220eaaa36742f8eb0c51341da089e154a815f92fcd18353077cde18f435dfaa0834b65fdf3a658b0accdda28";
    const D_SMALL: &str = "4c38e45d70b5aa1295c107fe9035e82b179d8ec10ab7acf59b6955e0b22f9fdb09976788745a0fbb4ee1cabd840a12d9e746bf76b3998ab72c06e019bb889412";

    #[test]
    fn the_literals_are_the_frozen_ones() {
        assert_eq!(P16.to_vec(), hex("5041524c2d5348414b452d5631000000"));
        assert_eq!(SUITE.len(), 129);
        assert!(SUITE.ends_with(b"/LEAF-AFFINE-896"));
        assert_eq!(PREFIX_BYTES, 77);
        assert_eq!(Role::Registration.label(), b"REG");
        assert_eq!(Role::Vote.label(), b"VOTE");
        assert_eq!(
            (
                Role::Registration.witness_bits(),
                Role::Registration.constraints()
            ),
            (35_840, 72_576)
        );
        assert_eq!(
            (Role::Vote.witness_bits(), Role::Vote.constraints()),
            (53_504, 108_931)
        );
        assert_eq!((Role::Registration.index(), Role::Vote.index()), (0, 1));
    }

    #[test]
    fn unit_tests_compile_both_rows() {
        // Unit tests always see the comparator; production builds see only
        // `[Row::Candidate]`, which the dependent crates' tests exercise.
        assert_eq!(Row::ALL, [Row::Candidate, Row::Comparator]);
    }

    #[test]
    fn the_rows_are_the_two_of_the_record() {
        let fast = Row::Candidate.vole();
        assert_eq!(
            (
                fast.lambda().bits(),
                fast.tau(),
                fast.w_grind(),
                fast.t_open(),
                fast.d_zk(),
                fast.n_mult(),
                fast.n_leafcom()
            ),
            (256, 33, 8, 229, 7, 704, 3)
        );
        let small = Row::Comparator.vole();
        assert_eq!(
            (
                small.lambda().bits(),
                small.tau(),
                small.w_grind(),
                small.t_open(),
                small.d_zk(),
                small.n_mult(),
                small.n_leafcom()
            ),
            (256, 22, 6, 225, 7, 696, 3)
        );
        assert_eq!(fast.lambda(), LEVEL);
        assert_eq!(small.lambda(), LEVEL);
    }

    #[test]
    fn the_table_serialisation_has_the_lengths_and_digests_of_the_record() {
        let fast = crt_bytes(Row::Candidate).expect("embedded tables");
        let small = crt_bytes(Row::Comparator).expect("embedded tables");
        assert_eq!((fast.len(), small.len()), (84_304, 83_704));
        assert!(fast.starts_with(b"FAESTCRT"));
        assert_eq!(fast[8..16], 256u64.to_le_bytes());
        assert_eq!(small[16..24], 22u64.to_le_bytes());
        assert_eq!(
            crt_table_digest(Row::Candidate)
                .expect("embedded tables")
                .as_bytes()
                .to_vec(),
            hex(T_CRT_FAST)
        );
        assert_eq!(
            crt_table_digest(Row::Comparator)
                .expect("embedded tables")
                .as_bytes()
                .to_vec(),
            hex(T_CRT_SMALL)
        );
    }

    #[test]
    fn the_descriptor_digests_are_the_values_of_the_record() {
        for (row, table, digest) in [
            (Row::Candidate, T_CRT_FAST, D_FAST),
            (Row::Comparator, T_CRT_SMALL, D_SMALL),
        ] {
            let profile = Profile::new(row).expect("embedded tables");
            assert_eq!(profile.row(), row);
            assert_eq!(profile.table_digest().as_bytes().to_vec(), hex(table));
            assert_eq!(profile.descriptor_digest().as_bytes().to_vec(), hex(digest));
            let descriptor = profile.descriptor();
            assert_eq!(descriptor.len(), 286);
            // Tag, field count, P16, the backend label.
            assert!(
                descriptor
                    .starts_with(b"\x0c\x00PARL/DESC/v1\x06\x00\x10\x00\x00\x00PARL-SHAKE-V1")
            );
            assert!(descriptor.ends_with(SUITE));
            assert_eq!(
                descriptor_bytes(row, profile.table_digest()).expect("frame"),
                descriptor.to_vec()
            );
            assert_eq!(u16_le(704), [0xc0, 0x02]);
            assert_eq!(u32_le(108_931), [0x83, 0xa9, 0x01, 0x00]);
        }
    }

    #[test]
    fn namespaces_and_prefixes_separate_roles_and_rows() {
        use sha3::Digest;
        let fast = Profile::new(Row::Candidate).expect("embedded tables");
        let small = Profile::new(Row::Comparator).expect("embedded tables");
        let mut seen = Vec::new();
        for profile in [&fast, &small] {
            for role in Role::ALL {
                let mut frame = b"\x0a\x00PARL/NS/v1\x02\x00\x40\x00\x00\x00".to_vec();
                frame.extend_from_slice(profile.descriptor_digest().as_bytes());
                frame.extend_from_slice(
                    &u32::try_from(role.label().len())
                        .expect("small")
                        .to_le_bytes(),
                );
                frame.extend_from_slice(role.label());
                let expected: [u8; 64] = sha3::Sha3_512::digest(&frame).into();
                assert_eq!(profile.namespace_digest(role).as_bytes(), &expected);
                assert_eq!(
                    namespace_digest(profile.descriptor_digest(), role).expect("frame"),
                    Digest64(expected)
                );
                let prefix = profile.prefix(role);
                assert_eq!(prefix.len(), 77);
                assert_eq!(&prefix[..13], b"PARL/FAEST/v1");
                assert_eq!(prefix[13..], expected);
                assert_eq!(
                    profile.namespace(role).expect("namespace").as_bytes(),
                    prefix
                );
                let context = profile.context(role).expect("context");
                assert_eq!(context.namespace().as_bytes(), prefix);
                assert!(!context.namespace().is_reference());
                assert_eq!(*context.vole(), profile.row().vole());
                seen.push(*prefix);
            }
        }
        for (i, a) in seen.iter().enumerate() {
            for b in &seen[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // First bytes of the four namespaces as printed by the prototype.
        assert_eq!(
            fast.namespace_digest(Role::Registration).as_bytes()[..8],
            hex("fee2262f962d05a6")[..]
        );
        assert_eq!(
            fast.namespace_digest(Role::Vote).as_bytes()[..8],
            hex("c35e0a664654be33")[..]
        );
        assert_eq!(
            small.namespace_digest(Role::Registration).as_bytes()[..8],
            hex("119502053f76d040")[..]
        );
        assert_eq!(
            small.namespace_digest(Role::Vote).as_bytes()[..8],
            hex("d142d6ecdf7a6222")[..]
        );
    }

    #[test]
    fn the_proof_layout_is_the_ledger_of_the_record() {
        // Field lengths of section 6.6, in layout order.
        let ledger: [(Row, Role, [usize; 11], usize); 4] = [
            (
                Row::Candidate,
                Role::Registration,
                [143_360, 880, 128, 4480, 192, 3696, 7328, 32, 16, 32, 4],
                160_148,
            ),
            (
                Row::Candidate,
                Role::Vote,
                [214_016, 880, 128, 6688, 192, 3696, 7328, 32, 16, 32, 4],
                233_012,
            ),
            (
                Row::Comparator,
                Role::Registration,
                [94_080, 870, 128, 4480, 192, 2464, 7200, 32, 16, 32, 4],
                109_498,
            ),
            (
                Row::Comparator,
                Role::Vote,
                [140_448, 870, 128, 6688, 192, 2464, 7200, 32, 16, 32, 4],
                158_074,
            ),
        ];
        for (row, role, lengths, total) in ledger {
            let layout = row.proof_layout(role);
            let mut offset = 0;
            for (segment, len) in layout.iter().zip(lengths) {
                assert_eq!(
                    (segment.offset, segment.len),
                    (offset, len),
                    "{row:?} {role:?}"
                );
                offset += len;
            }
            assert_eq!(offset, total);
            assert_eq!(row.proof_bytes(role), total);
            assert_eq!(Profile::new(row).expect("tables").proof_bytes(role), total);
            assert_eq!(layout[0].field, ProofField::Corrections);
            assert_eq!(layout[10].field, ProofField::Counter);
        }
    }
}
