//! Parameter sets of FAEST v3.0 (specification Tables 3.1, 3.2, 3.3 and 5.1).
//!
//! The parameters are split along the seam between the proof system and the proven
//! relation:
//!
//! * [`VoleParams`] holds what the VOLE-in-the-head machinery fixes independently of
//!   the relation: `lambda`, `tau`, `w_grind`, `T_open`, `n_leafcom`, `d_zk` and
//!   `n_mult`, together with every value Table 5.1 derives from them.
//! * [`ProofParams`] adds the two sizes a relation contributes: the witness length
//!   `ell` and the constraint count `C`.
//! * [`OwfParams`] is the one-way-function row of Table 3.3 and [`FaestParams`] binds
//!   the three into one of the twelve standard parameter sets.
//!
//! A relation other than the FAEST one-way function builds its own row with
//! [`ProofParams::new`] from the [`VoleParams`] of a standard set; the standard rows
//! are constants and are never modified.

use thiserror::Error;

/// Bits of the initialisation vector `iv` and of `iv_pre`.
pub const IV_BITS: usize = 128;
/// Bytes of the initialisation vector `iv` and of `iv_pre`.
pub const IV_BYTES: usize = IV_BITS / 8;
/// Bits of the signature grinding counter `ctr`.
pub const COUNTER_BITS: usize = 32;
/// Maximum constraint degree `d_zk` of every FAEST v3.0 parameter set.
pub const D_ZK: usize = 7;
/// Largest witness length, in bits, a parameter row may declare.
///
/// This is a resource cap, not a security bound: it is far above
/// [`PROVEN_VOLE_HASH_LEN`], the range for which specification Lemma 4.6 proves the
/// `VOLEHash` bound. See [`ProofParams::new`].
pub const MAX_WITNESS_BITS: usize = 1 << 22;
/// Largest constraint count a parameter row may declare.
///
/// This is a resource cap, not a security bound: it is far above
/// [`PROVEN_ZK_HASH_LEN`], the range for which specification Lemma 4.7 proves the
/// `ZKHash` bound. See [`ProofParams::new`].
pub const MAX_CONSTRAINTS: usize = 1 << 28;
/// Largest `VOLEHash` input length `ell' = ell + d_zk - 1` covered by specification
/// Lemma 4.6 (`eps_v = 2^-4lambda * (1 + 2^-4)` for `ell' <= 2^12`).
pub const PROVEN_VOLE_HASH_LEN: usize = 1 << 12;
/// Largest `ZKHash` input length `C' = C + 1` covered by specification Lemma 4.7
/// (`eps_zk = 2^-lambda * (1 + 2^-38)` for `C' <= 2^13`).
pub const PROVEN_ZK_HASH_LEN: usize = 1 << 13;
/// Largest small-VOLE bit length `k` a parameter row may produce.
pub const MAX_VOLE_BITS: usize = 16;
/// Largest `T_open` and `n_mult` a parameter row may declare.
pub const MAX_COUNT: usize = 1 << 16;
/// Largest constraint degree `d_zk` a parameter row may declare: `H_5` returns the
/// `n_mask = d_zk + 3` gate-label bits in a 16-bit value
/// ([`crate::hash::MAX_H5_BITS`]).
pub const MAX_D_ZK: usize = 13;

/// Rejected parameter rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParamsError {
    /// `tau` is below 2 or above `lambda - w_grind`.
    #[error("tau = {tau} is outside [2, lambda - w_grind]")]
    Tau {
        /// Rejected value.
        tau: usize,
    },
    /// `w_grind` leaves no challenge bits.
    #[error("w_grind = {w_grind} is not below lambda")]
    Grinding {
        /// Rejected value.
        w_grind: usize,
    },
    /// The derived small-VOLE bit length is outside `[2, MAX_VOLE_BITS]`.
    #[error("small-VOLE bit length k = {k} is outside [2, {MAX_VOLE_BITS}]")]
    VoleBits {
        /// Derived value.
        k: usize,
    },
    /// `T_open` or `n_mult` is zero or above [`MAX_COUNT`], or `d_zk` is outside
    /// `[2, MAX_D_ZK]`.
    #[error("{name} = {value} is out of range")]
    Count {
        /// Name of the rejected parameter.
        name: &'static str,
        /// Rejected value.
        value: usize,
    },
    /// The leaf commitment is not two or three `lambda`-bit blocks.
    #[error("n_leafcom = {n_leafcom} is neither 2 nor 3")]
    LeafBlocks {
        /// Rejected value.
        n_leafcom: usize,
    },
    /// The witness length is not a multiple of 8, is below `lambda`, or is above
    /// [`MAX_WITNESS_BITS`].
    #[error(
        "witness length {witness_bits} must be a multiple of 8 in [lambda, {MAX_WITNESS_BITS}]"
    )]
    WitnessBits {
        /// Rejected value.
        witness_bits: usize,
    },
    /// The constraint count is below the witness length (the first `ell` constraints
    /// are the bit constraints) or above [`MAX_CONSTRAINTS`].
    #[error("constraint count {constraints} must be in [witness length, {MAX_CONSTRAINTS}]")]
    Constraints {
        /// Rejected value.
        constraints: usize,
    },
}

/// Security parameter `lambda`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// `lambda = 128`.
    L128,
    /// `lambda = 192`.
    L192,
    /// `lambda = 256`.
    L256,
}

impl SecurityLevel {
    /// All security levels in increasing order.
    pub const ALL: [Self; 3] = [Self::L128, Self::L192, Self::L256];

    /// `lambda` in bits.
    pub const fn bits(self) -> usize {
        match self {
            Self::L128 => 128,
            Self::L192 => 192,
            Self::L256 => 256,
        }
    }

    /// `lambda` in bytes.
    pub const fn bytes(self) -> usize {
        self.bits() / 8
    }

    /// The level whose `lambda` is `bytes * 8`, if any.
    pub const fn from_bytes(bytes: usize) -> Option<Self> {
        match bytes {
            16 => Some(Self::L128),
            24 => Some(Self::L192),
            32 => Some(Self::L256),
            _ => None,
        }
    }
}

/// Relation-independent parameters of the VOLE-in-the-head proof system
/// (`param` without `ell`, plus `n_mult` of `param_VOLE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VoleParams {
    lambda: SecurityLevel,
    tau: usize,
    w_grind: usize,
    t_open: usize,
    n_leafcom: usize,
    d_zk: usize,
    n_mult: usize,
}

impl VoleParams {
    /// Validate and build a row.
    ///
    /// # Errors
    /// Returns the [`ParamsError`] naming the first parameter that is out of range.
    pub const fn new(
        lambda: SecurityLevel,
        tau: usize,
        w_grind: usize,
        t_open: usize,
        n_leafcom: usize,
        d_zk: usize,
        n_mult: usize,
    ) -> Result<Self, ParamsError> {
        if w_grind >= lambda.bits() {
            return Err(ParamsError::Grinding { w_grind });
        }
        let n_delta = lambda.bits() - w_grind;
        if tau < 2 || tau > n_delta {
            return Err(ParamsError::Tau { tau });
        }
        let k = n_delta / tau + 1;
        if k < 2 || k > MAX_VOLE_BITS {
            return Err(ParamsError::VoleBits { k });
        }
        if t_open == 0 || t_open > MAX_COUNT {
            return Err(ParamsError::Count {
                name: "T_open",
                value: t_open,
            });
        }
        if n_leafcom != 2 && n_leafcom != 3 {
            return Err(ParamsError::LeafBlocks { n_leafcom });
        }
        if d_zk < 2 || d_zk > MAX_D_ZK {
            return Err(ParamsError::Count {
                name: "d_zk",
                value: d_zk,
            });
        }
        if n_mult == 0 || n_mult > MAX_COUNT {
            return Err(ParamsError::Count {
                name: "n_mult",
                value: n_mult,
            });
        }
        Ok(Self {
            lambda,
            tau,
            w_grind,
            t_open,
            n_leafcom,
            d_zk,
            n_mult,
        })
    }

    /// Security parameter `lambda`.
    pub const fn lambda(&self) -> SecurityLevel {
        self.lambda
    }

    /// Number of small-VOLE instances `tau`.
    pub const fn tau(&self) -> usize {
        self.tau
    }

    /// Grinding parameter `w_grind`: the top `w_grind` bits of `chall_3` are zero.
    pub const fn w_grind(&self) -> usize {
        self.w_grind
    }

    /// Threshold `T_open` on the number of GGM nodes in an opening.
    pub const fn t_open(&self) -> usize {
        self.t_open
    }

    /// Number `n_leafcom` of `lambda`-bit blocks per leaf commitment.
    pub const fn n_leafcom(&self) -> usize {
        self.n_leafcom
    }

    /// Maximum constraint degree `d_zk`.
    pub const fn d_zk(&self) -> usize {
        self.d_zk
    }

    /// Number `n_mult` of AND-gate corrections per mask.
    pub const fn n_mult(&self) -> usize {
        self.n_mult
    }

    /// `n_Delta = lambda - w_grind`, the challenge bits that select `Delta`.
    pub const fn n_delta(&self) -> usize {
        self.lambda.bits() - self.w_grind
    }

    /// `tau_1 = n_Delta mod tau`, the number of instances of bit length `k`.
    pub const fn tau1(&self) -> usize {
        self.n_delta() % self.tau
    }

    /// `tau_0 = tau - tau_1`, the number of instances of bit length `k - 1`.
    pub const fn tau0(&self) -> usize {
        self.tau - self.tau1()
    }

    /// `k = floor(n_Delta / tau) + 1`.
    pub const fn k(&self) -> usize {
        self.n_delta() / self.tau + 1
    }

    /// Bit length `d_i` of small-VOLE instance `i`, or `None` if `i >= tau`.
    pub const fn depth(&self, i: usize) -> Option<usize> {
        if i >= self.tau {
            None
        } else if i < self.tau1() {
            Some(self.k())
        } else {
            Some(self.k() - 1)
        }
    }

    /// `d_0 = max_i d_i`: `k` if `tau_1 > 0`, otherwise `k - 1`.
    pub const fn d0(&self) -> usize {
        if self.tau1() > 0 {
            self.k()
        } else {
            self.k() - 1
        }
    }

    /// Number `N_i = 2^{d_i}` of leaves of instance `i`, or `None` if `i >= tau`.
    pub const fn leaves_of(&self, i: usize) -> Option<usize> {
        match self.depth(i) {
            Some(depth) => Some(1 << depth),
            None => None,
        }
    }

    /// Total number `L = sum_i N_i` of GGM leaves.
    pub const fn leaves(&self) -> usize {
        self.tau1() * (1 << self.k()) + self.tau0() * (1 << (self.k() - 1))
    }

    /// Number `n_mask = d_zk + 3` of `lambda`-bit VOLE masks.
    pub const fn n_mask(&self) -> usize {
        self.d_zk + 3
    }

    /// Row length `8 * ceil(n_mult / 8)` of `c_mult` in bits.
    pub const fn n_mult_padded(&self) -> usize {
        self.n_mult.div_ceil(8) * 8
    }

    /// Bytes of a leaf commitment: `n_leafcom * lambda / 8`.
    pub const fn leaf_commitment_bytes(&self) -> usize {
        self.n_leafcom * self.lambda.bytes()
    }

    /// Bytes of `chall_1`, the `VOLEHash` seed: `(8 * lambda + 64) / 8`.
    pub const fn chall1_bytes(&self) -> usize {
        8 * self.lambda.bytes() + 8
    }

    /// Bytes of `chall_2`, the `ZKHash` seed: `(3 * lambda + 64) / 8`.
    pub const fn chall2_bytes(&self) -> usize {
        3 * self.lambda.bytes() + 8
    }

    /// Bytes of `chall_3`: `lambda / 8`.
    pub const fn chall3_bytes(&self) -> usize {
        self.lambda.bytes()
    }
}

/// A complete proof-system row: the relation-independent part plus the witness
/// length and constraint count of one relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProofParams {
    vole: VoleParams,
    witness_bits: usize,
    constraints: usize,
}

impl ProofParams {
    /// Build the row of a relation with `witness_bits` witness bits (`ell`) and
    /// `constraints` constraints (`C`, counting the `ell` bit constraints).
    ///
    /// # Errors
    /// Returns [`ParamsError::WitnessBits`] unless `witness_bits` is a multiple of 8
    /// in `[lambda, MAX_WITNESS_BITS]`, and [`ParamsError::Constraints`] unless
    /// `constraints` is in `[witness_bits, MAX_CONSTRAINTS]`.
    ///
    /// # Security
    /// The two caps only bound resources. The specification proves the
    /// universal-hash bounds for `ell + d_zk - 1 <= 2^12` (Lemma 4.6) and
    /// `C + 1 <= 2^13` (Lemma 4.7), which all twelve standard rows satisfy. A row
    /// beyond those ranges is accepted here but is **outside the lemmas as stated**:
    /// their proofs then give only the weaker bounds
    /// `eps_v <= 2^-4lambda + (ell' - 1)^5 / 2^(4lambda + 64)` with
    /// `ell' = ell + d_zk - 1` and
    /// `eps_zk <= 2^-lambda * (1 + (C + 1)^2 / 2^64)`. A relation that defines such a
    /// row must account for the larger terms in its own soundness analysis;
    /// [`Self::within_proven_hash_bounds`] reports which case a row is in.
    pub const fn new(
        vole: VoleParams,
        witness_bits: usize,
        constraints: usize,
    ) -> Result<Self, ParamsError> {
        if !witness_bits.is_multiple_of(8)
            || witness_bits < vole.lambda.bits()
            || witness_bits > MAX_WITNESS_BITS
        {
            return Err(ParamsError::WitnessBits { witness_bits });
        }
        if constraints < witness_bits || constraints > MAX_CONSTRAINTS {
            return Err(ParamsError::Constraints { constraints });
        }
        Ok(Self {
            vole,
            witness_bits,
            constraints,
        })
    }

    /// The relation-independent parameters.
    pub const fn vole(&self) -> &VoleParams {
        &self.vole
    }

    /// Witness length `ell` in bits.
    pub const fn witness_bits(&self) -> usize {
        self.witness_bits
    }

    /// Witness length in bytes.
    pub const fn witness_bytes(&self) -> usize {
        self.witness_bits / 8
    }

    /// Number `C` of constraints hashed by `ZKHash`.
    pub const fn constraints(&self) -> usize {
        self.constraints
    }

    /// Small-VOLE length `ell_hat = ell + n_mask * d_0` in bits.
    pub const fn ell_hat(&self) -> usize {
        self.witness_bits + self.vole.n_mask() * self.vole.d0()
    }

    /// Number `ell + d_zk - 1` of elements in the first `VOLEHash` input.
    pub const fn vole_hash_len(&self) -> usize {
        self.witness_bits + self.vole.d_zk - 1
    }

    /// Whether the row is inside the input-length ranges of specification Lemmas 4.6
    /// and 4.7: `ell + d_zk - 1 <= 2^12` and `C + 1 <= 2^13`. See the security note
    /// on [`Self::new`].
    pub const fn within_proven_hash_bounds(&self) -> bool {
        self.vole_hash_len() <= PROVEN_VOLE_HASH_LEN && self.constraints < PROVEN_ZK_HASH_LEN
    }

    /// Signature length in bits, by the formula of specification section 3.1.
    ///
    /// The validated ranges keep the result below `2^31`, so it cannot overflow.
    pub const fn signature_bits(&self) -> usize {
        let vole = &self.vole;
        let lambda = vole.lambda.bits();
        let (tau, ell) = (vole.tau, self.witness_bits);
        tau * ell
            + vole.n_mask() * vole.n_mult_padded()
            + 4 * lambda
            + (vole.d_zk - 1) * lambda
            + vole.t_open * lambda
            + vole.n_leafcom * lambda * tau
            + lambda
            + IV_BITS
            + COUNTER_BITS
    }

    /// Signature length in bytes. Every term of [`Self::signature_bits`] is a
    /// multiple of 8 because the witness length is.
    pub const fn signature_bytes(&self) -> usize {
        self.signature_bits() / 8
    }
}

/// The two one-way-function families of FAEST v3.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwfKind {
    /// FAEST: `AES_k(x)` (two blocks for `lambda` of 192 and 256).
    Aes,
    /// FAEST-EM: `Rijndael_x(k) XOR k` in Even-Mansour mode.
    EvenMansour,
}

/// One-way-function parameters `param_OWF` (specification Table 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwfParams {
    kind: OwfKind,
    lambda: SecurityLevel,
}

impl OwfParams {
    /// The Table 3.3 column of `kind` at `lambda`.
    pub const fn new(kind: OwfKind, lambda: SecurityLevel) -> Self {
        Self { kind, lambda }
    }

    /// The one-way-function family.
    pub const fn kind(self) -> OwfKind {
        self.kind
    }

    /// Security parameter `lambda`.
    pub const fn lambda(self) -> SecurityLevel {
        self.lambda
    }

    /// `N_k = lambda / 32`, the number of 32-bit words in the key.
    pub const fn n_k(self) -> usize {
        self.lambda.bits() / 32
    }

    /// `N_st`, the block size in 32-bit words: 4 for FAEST, `lambda / 32` for EM.
    pub const fn n_st(self) -> usize {
        match self.kind {
            OwfKind::Aes => 4,
            OwfKind::EvenMansour => self.lambda.bits() / 32,
        }
    }

    /// `N_st-bytes = 4 * N_st`.
    pub const fn n_st_bytes(self) -> usize {
        4 * self.n_st()
    }

    /// `N_st-bits = 32 * N_st`.
    pub const fn n_st_bits(self) -> usize {
        32 * self.n_st()
    }

    /// `beta = ceil(lambda / N_st-bits)`, the number of message blocks.
    pub const fn beta(self) -> usize {
        self.lambda.bits().div_ceil(self.n_st_bits())
    }

    /// `R = max(N_k, N_st) + 6`, the number of encryption rounds.
    pub const fn rounds(self) -> usize {
        let n_k = self.n_k();
        let n_st = self.n_st();
        (if n_k > n_st { n_k } else { n_st }) + 6
    }

    /// `S_ke`, the number of S-boxes in the key schedule: `-lambda / 8 + 56 +
    /// 28 * floor(lambda / 256)` for FAEST, 0 for EM.
    pub const fn s_ke(self) -> usize {
        match self.kind {
            OwfKind::Aes => 56 + 28 * (self.lambda.bits() / 256) - self.lambda.bits() / 8,
            OwfKind::EvenMansour => 0,
        }
    }

    /// `S_enc = 4 * N_st * R`, the number of S-boxes in one encryption.
    pub const fn s_enc(self) -> usize {
        4 * self.n_st() * self.rounds()
    }

    /// `ell_ke = lambda + 8 * S_ke`, the witness bits of the key schedule.
    pub const fn ell_ke(self) -> usize {
        self.lambda.bits() + 8 * self.s_ke()
    }

    /// `ell_enc = (R / 2 - 1) * N_st-bits`, the witness bits of one encryption.
    pub const fn ell_enc(self) -> usize {
        (self.rounds() / 2 - 1) * self.n_st_bits()
    }

    /// `ell = ell_ke + beta * ell_enc`, the witness length in bits.
    pub const fn ell(self) -> usize {
        self.ell_ke() + self.beta() * self.ell_enc()
    }

    /// `C = ell + 2 * S_ke + beta * S_enc / 2 + 1`, the number of constraints.
    pub const fn constraints(self) -> usize {
        self.ell() + 2 * self.s_ke() + self.beta() * self.s_enc() / 2 + 1
    }

    /// Bytes of the public one-way-function input `x`: `N_st-bits / 8`.
    pub const fn input_bytes(self) -> usize {
        self.n_st_bytes()
    }

    /// Bytes of the one-way-function output `y`: `beta * N_st-bits / 8`.
    pub const fn output_bytes(self) -> usize {
        self.beta() * self.n_st_bytes()
    }

    /// Bytes of the public key `pk = x || y`.
    pub const fn public_key_bytes(self) -> usize {
        self.input_bytes() + self.output_bytes()
    }

    /// Bytes of the secret key `sk = x || k`.
    pub const fn secret_key_bytes(self) -> usize {
        self.input_bytes() + self.lambda.bytes()
    }

    /// `n_leafcom` of the family: 3 for FAEST, 2 for FAEST-EM.
    pub const fn n_leafcom(self) -> usize {
        match self.kind {
            OwfKind::Aes => 3,
            OwfKind::EvenMansour => 2,
        }
    }
}

/// One of the twelve standard FAEST v3.0 parameter sets (specification Table 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FaestParams {
    name: &'static str,
    proof: ProofParams,
    owf: OwfParams,
    published_public_key_bytes: usize,
    published_signature_bytes: usize,
}

impl FaestParams {
    /// Name of the parameter set, for example `FAEST-128s`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Proof-system parameters with the witness length and constraint count of the
    /// one-way-function relation.
    pub const fn proof(&self) -> &ProofParams {
        &self.proof
    }

    /// Relation-independent parameters; the starting point of a custom relation row.
    pub const fn vole(&self) -> &VoleParams {
        self.proof.vole()
    }

    /// One-way-function parameters.
    pub const fn owf(&self) -> &OwfParams {
        &self.owf
    }

    /// Public-key size in bytes as published in Table 3.2.
    pub const fn public_key_bytes(&self) -> usize {
        self.published_public_key_bytes
    }

    /// Secret-key size in bytes (`sk = x || k`).
    pub const fn secret_key_bytes(&self) -> usize {
        self.owf.secret_key_bytes()
    }

    /// Signature size in bytes as published in Table 3.2.
    pub const fn signature_bytes(&self) -> usize {
        self.published_signature_bytes
    }
}

/// Build a standard row at compile time. A row that fails validation is a compile
/// error, never a run-time panic.
#[allow(clippy::too_many_arguments)]
const fn standard(
    name: &'static str,
    kind: OwfKind,
    lambda: SecurityLevel,
    tau: usize,
    w_grind: usize,
    t_open: usize,
    n_mult: usize,
    public_key_bytes: usize,
    signature_bytes: usize,
) -> FaestParams {
    let owf = OwfParams::new(kind, lambda);
    let Ok(vole) = VoleParams::new(lambda, tau, w_grind, t_open, owf.n_leafcom(), D_ZK, n_mult)
    else {
        panic!("invalid standard VOLE parameters");
    };
    let Ok(proof) = ProofParams::new(vole, owf.ell(), owf.constraints()) else {
        panic!("invalid standard relation parameters");
    };
    FaestParams {
        name,
        proof,
        owf,
        published_public_key_bytes: public_key_bytes,
        published_signature_bytes: signature_bytes,
    }
}

use OwfKind::{Aes, EvenMansour};
use SecurityLevel::{L128, L192, L256};

/// FAEST-128s.
pub const FAEST_128S: FaestParams = standard("FAEST-128s", Aes, L128, 11, 7, 102, 312, 32, 4066);
/// FAEST-128f.
pub const FAEST_128F: FaestParams = standard("FAEST-128f", Aes, L128, 17, 8, 108, 312, 32, 5170);
/// FAEST-192s.
pub const FAEST_192S: FaestParams = standard("FAEST-192s", Aes, L192, 16, 12, 162, 504, 48, 9410);
/// FAEST-192f.
pub const FAEST_192F: FaestParams = standard("FAEST-192f", Aes, L192, 24, 8, 163, 504, 48, 11738);
/// FAEST-256s.
pub const FAEST_256S: FaestParams = standard("FAEST-256s", Aes, L256, 22, 6, 225, 696, 48, 16626);
/// FAEST-256f.
pub const FAEST_256F: FaestParams = standard("FAEST-256f", Aes, L256, 33, 8, 229, 704, 48, 20856);
/// FAEST-EM-128s.
pub const FAEST_EM_128S: FaestParams = standard(
    "FAEST-EM-128s",
    EvenMansour,
    L128,
    11,
    7,
    103,
    312,
    32,
    3466,
);
/// FAEST-EM-128f.
pub const FAEST_EM_128F: FaestParams = standard(
    "FAEST-EM-128f",
    EvenMansour,
    L128,
    17,
    8,
    105,
    312,
    32,
    4170,
);
/// FAEST-EM-192s.
pub const FAEST_EM_192S: FaestParams = standard(
    "FAEST-EM-192s",
    EvenMansour,
    L192,
    16,
    8,
    162,
    504,
    48,
    7874,
);
/// FAEST-EM-192f.
pub const FAEST_EM_192F: FaestParams = standard(
    "FAEST-EM-192f",
    EvenMansour,
    L192,
    25,
    8,
    171,
    504,
    48,
    9818,
);
/// FAEST-EM-256s.
pub const FAEST_EM_256S: FaestParams = standard(
    "FAEST-EM-256s",
    EvenMansour,
    L256,
    22,
    6,
    218,
    696,
    64,
    14554,
);
/// FAEST-EM-256f.
pub const FAEST_EM_256F: FaestParams = standard(
    "FAEST-EM-256f",
    EvenMansour,
    L256,
    33,
    8,
    229,
    704,
    64,
    18084,
);

/// The twelve standard parameter sets in the order of Table 3.2.
pub const FAEST_PARAMETER_SETS: [FaestParams; 12] = [
    FAEST_128S,
    FAEST_128F,
    FAEST_192S,
    FAEST_192F,
    FAEST_256S,
    FAEST_256F,
    FAEST_EM_128S,
    FAEST_EM_128F,
    FAEST_EM_192S,
    FAEST_EM_192F,
    FAEST_EM_256S,
    FAEST_EM_256F,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_level_sizes_and_lookup() {
        assert_eq!(SecurityLevel::ALL.map(SecurityLevel::bits), [128, 192, 256]);
        assert_eq!(SecurityLevel::ALL.map(SecurityLevel::bytes), [16, 24, 32]);
        for level in SecurityLevel::ALL {
            assert_eq!(SecurityLevel::from_bytes(level.bytes()), Some(level));
        }
        assert_eq!(SecurityLevel::from_bytes(0), None);
        assert_eq!(SecurityLevel::from_bytes(20), None);
    }

    #[test]
    fn signature_size_formula_reproduces_all_twelve_published_sizes() {
        let published = [
            4066, 5170, 9410, 11738, 16626, 20856, 3466, 4170, 7874, 9818, 14554, 18084,
        ];
        for (set, size) in FAEST_PARAMETER_SETS.iter().zip(published) {
            assert_eq!(set.signature_bytes(), size, "{}", set.name());
            assert_eq!(set.proof().signature_bytes(), size, "{}", set.name());
            assert_eq!(set.proof().signature_bits(), size * 8, "{}", set.name());
        }
    }

    #[test]
    fn key_sizes_match_table_3_2() {
        let public = [32, 32, 48, 48, 48, 48, 32, 32, 48, 48, 64, 64];
        let secret = [32, 32, 40, 40, 48, 48, 32, 32, 48, 48, 64, 64];
        for ((set, pk), sk) in FAEST_PARAMETER_SETS.iter().zip(public).zip(secret) {
            assert_eq!(set.public_key_bytes(), pk, "{}", set.name());
            assert_eq!(set.owf().public_key_bytes(), pk, "{}", set.name());
            assert_eq!(set.secret_key_bytes(), sk, "{}", set.name());
        }
    }

    #[test]
    fn table_3_2_rows_are_exact() {
        // (name, ell, tau, w_grind, T_open, n_leafcom, n_mult)
        let rows = [
            ("FAEST-128s", 960, 11, 7, 102, 3, 312),
            ("FAEST-128f", 960, 17, 8, 108, 3, 312),
            ("FAEST-192s", 1728, 16, 12, 162, 3, 504),
            ("FAEST-192f", 1728, 24, 8, 163, 3, 504),
            ("FAEST-256s", 2208, 22, 6, 225, 3, 696),
            ("FAEST-256f", 2208, 33, 8, 229, 3, 704),
            ("FAEST-EM-128s", 640, 11, 7, 103, 2, 312),
            ("FAEST-EM-128f", 640, 17, 8, 105, 2, 312),
            ("FAEST-EM-192s", 1152, 16, 8, 162, 2, 504),
            ("FAEST-EM-192f", 1152, 25, 8, 171, 2, 504),
            ("FAEST-EM-256s", 1792, 22, 6, 218, 2, 696),
            ("FAEST-EM-256f", 1792, 33, 8, 229, 2, 704),
        ];
        for (set, row) in FAEST_PARAMETER_SETS.iter().zip(rows) {
            let vole = set.vole();
            assert_eq!(
                (
                    set.name(),
                    set.proof().witness_bits(),
                    vole.tau(),
                    vole.w_grind(),
                    vole.t_open(),
                    vole.n_leafcom(),
                    vole.n_mult(),
                ),
                row
            );
            assert_eq!(vole.d_zk(), 7);
            assert_eq!(vole.n_mask(), 10);
            assert_eq!(vole.lambda(), set.owf().lambda());
            assert_eq!(vole.n_leafcom(), set.owf().n_leafcom());
        }
    }

    #[test]
    fn table_5_1_derived_values_are_exact() {
        // (n_Delta, k, tau_1, tau_0, d_0, L, ell_hat, ell + d_zk - 1, nbar_mult, C)
        let rows = [
            (121, 12, 0, 11, 11, 22528, 1070, 966, 312, 1121),
            (120, 8, 1, 16, 8, 2304, 1040, 966, 312, 1121),
            (180, 12, 4, 12, 12, 40960, 1848, 1734, 504, 1985),
            (184, 8, 16, 8, 8, 5120, 1808, 1734, 504, 1985),
            (250, 12, 8, 14, 12, 61440, 2328, 2214, 696, 2537),
            (248, 8, 17, 16, 8, 6400, 2288, 2214, 704, 2537),
            (121, 12, 0, 11, 11, 22528, 750, 646, 312, 721),
            (120, 8, 1, 16, 8, 2304, 720, 646, 312, 721),
            (184, 12, 8, 8, 12, 49152, 1272, 1158, 504, 1297),
            (184, 8, 9, 16, 8, 4352, 1232, 1158, 504, 1297),
            (250, 12, 8, 14, 12, 61440, 1912, 1798, 696, 2017),
            (248, 8, 17, 16, 8, 6400, 1872, 1798, 704, 2017),
        ];
        for (set, row) in FAEST_PARAMETER_SETS.iter().zip(rows) {
            let vole = set.vole();
            let proof = set.proof();
            assert_eq!(
                (
                    vole.n_delta(),
                    vole.k(),
                    vole.tau1(),
                    vole.tau0(),
                    vole.d0(),
                    vole.leaves(),
                    proof.ell_hat(),
                    proof.vole_hash_len(),
                    vole.n_mult_padded(),
                    proof.constraints(),
                ),
                row,
                "{}",
                set.name()
            );
            // The instance lengths add up to n_Delta and the leaves to L.
            let depths: Vec<usize> = (0..vole.tau()).filter_map(|i| vole.depth(i)).collect();
            assert_eq!(depths.len(), vole.tau());
            assert_eq!(depths.iter().sum::<usize>(), vole.n_delta());
            assert_eq!(depths.iter().copied().max(), Some(vole.d0()));
            assert_eq!(depths.first().copied(), Some(vole.d0()));
            let leaves: usize = (0..vole.tau()).filter_map(|i| vole.leaves_of(i)).sum();
            assert_eq!(leaves, vole.leaves());
            assert_eq!(vole.depth(vole.tau()), None);
            assert_eq!(vole.leaves_of(vole.tau()), None);
            assert_eq!(proof.witness_bytes() * 8, proof.witness_bits());
            assert_eq!(vole.chall1_bytes(), 8 * vole.lambda().bytes() + 8);
            assert_eq!(vole.chall2_bytes(), 3 * vole.lambda().bytes() + 8);
            assert_eq!(vole.chall3_bytes(), vole.lambda().bytes());
            assert_eq!(
                vole.leaf_commitment_bytes(),
                vole.n_leafcom() * vole.lambda().bytes()
            );
        }
    }

    #[test]
    fn table_3_3_columns_are_exact() {
        // (N_k, N_st, N_st-bytes, N_st-bits, beta, R, S_ke, S_enc, ell_ke, ell_enc, ell, C)
        let columns = [
            (
                Aes,
                L128,
                (4, 4, 16, 128, 1, 10, 40, 160, 448, 512, 960, 1121),
            ),
            (
                Aes,
                L192,
                (6, 4, 16, 128, 2, 12, 32, 192, 448, 640, 1728, 1985),
            ),
            (
                Aes,
                L256,
                (8, 4, 16, 128, 2, 14, 52, 224, 672, 768, 2208, 2537),
            ),
            (
                EvenMansour,
                L128,
                (4, 4, 16, 128, 1, 10, 0, 160, 128, 512, 640, 721),
            ),
            (
                EvenMansour,
                L192,
                (6, 6, 24, 192, 1, 12, 0, 288, 192, 960, 1152, 1297),
            ),
            (
                EvenMansour,
                L256,
                (8, 8, 32, 256, 1, 14, 0, 448, 256, 1536, 1792, 2017),
            ),
        ];
        for (kind, lambda, column) in columns {
            let owf = OwfParams::new(kind, lambda);
            assert_eq!((owf.kind(), owf.lambda()), (kind, lambda));
            assert_eq!(
                (
                    owf.n_k(),
                    owf.n_st(),
                    owf.n_st_bytes(),
                    owf.n_st_bits(),
                    owf.beta(),
                    owf.rounds(),
                    owf.s_ke(),
                    owf.s_enc(),
                    owf.ell_ke(),
                    owf.ell_enc(),
                    owf.ell(),
                    owf.constraints(),
                ),
                column
            );
            assert_eq!(owf.input_bytes(), owf.n_st_bytes());
            assert_eq!(owf.output_bytes(), owf.beta() * owf.n_st_bytes());
            assert_eq!(owf.secret_key_bytes(), owf.n_st_bytes() + lambda.bytes());
        }
    }

    #[test]
    fn a_custom_relation_row_reuses_the_standard_vole_parameters() {
        let vole = *FAEST_256S.vole();
        let custom = ProofParams::new(vole, 4096, 6000).expect("valid custom row");
        assert_eq!(custom.vole(), FAEST_256S.vole());
        assert_eq!(custom.witness_bits(), 4096);
        assert_eq!(custom.constraints(), 6000);
        assert_eq!(custom.ell_hat(), 4096 + 10 * 12);
        assert_eq!(
            custom.signature_bytes(),
            FAEST_256S.signature_bytes() + 22 * (4096 - 2208) / 8
        );
        // The standard row is untouched.
        assert_eq!(FAEST_256S.proof().witness_bits(), 2208);
    }

    #[test]
    fn invalid_rows_are_rejected_with_typed_errors() {
        let vole = *FAEST_128S.vole();
        assert_eq!(
            ProofParams::new(vole, 961, 2000),
            Err(ParamsError::WitnessBits { witness_bits: 961 })
        );
        assert_eq!(
            ProofParams::new(vole, 120, 2000),
            Err(ParamsError::WitnessBits { witness_bits: 120 })
        );
        assert_eq!(
            ProofParams::new(vole, MAX_WITNESS_BITS + 8, MAX_WITNESS_BITS + 8),
            Err(ParamsError::WitnessBits {
                witness_bits: MAX_WITNESS_BITS + 8
            })
        );
        assert_eq!(
            ProofParams::new(vole, 960, 959),
            Err(ParamsError::Constraints { constraints: 959 })
        );
        assert_eq!(
            ProofParams::new(vole, 960, MAX_CONSTRAINTS + 1),
            Err(ParamsError::Constraints {
                constraints: MAX_CONSTRAINTS + 1
            })
        );

        let new = |tau, w_grind, t_open, n_leafcom, d_zk, n_mult| {
            VoleParams::new(L128, tau, w_grind, t_open, n_leafcom, d_zk, n_mult)
        };
        assert!(new(11, 7, 102, 3, 7, 312).is_ok());
        assert_eq!(new(1, 7, 102, 3, 7, 312), Err(ParamsError::Tau { tau: 1 }));
        assert_eq!(
            new(122, 7, 102, 3, 7, 312),
            Err(ParamsError::Tau { tau: 122 })
        );
        assert_eq!(
            new(11, 128, 102, 3, 7, 312),
            Err(ParamsError::Grinding { w_grind: 128 })
        );
        assert_eq!(
            new(2, 7, 102, 3, 7, 312),
            Err(ParamsError::VoleBits { k: 61 })
        );
        assert_eq!(
            new(11, 7, 0, 3, 7, 312),
            Err(ParamsError::Count {
                name: "T_open",
                value: 0
            })
        );
        assert_eq!(
            new(11, 7, 102, 4, 7, 312),
            Err(ParamsError::LeafBlocks { n_leafcom: 4 })
        );
        assert_eq!(
            new(11, 7, 102, 3, 1, 312),
            Err(ParamsError::Count {
                name: "d_zk",
                value: 1
            })
        );
        assert_eq!(
            new(11, 7, 102, 3, MAX_D_ZK + 1, 312),
            Err(ParamsError::Count {
                name: "d_zk",
                value: 14
            })
        );
        let widest = new(11, 7, 102, 3, MAX_D_ZK, 312).expect("d_zk = 13 is valid");
        assert_eq!(widest.n_mask(), crate::hash::MAX_H5_BITS);
        assert_eq!(
            new(11, 7, 102, 3, 7, MAX_COUNT + 1),
            Err(ParamsError::Count {
                name: "n_mult",
                value: MAX_COUNT + 1
            })
        );
        assert_eq!(
            new(11, 7, MAX_COUNT + 1, 3, 7, 312),
            Err(ParamsError::Count {
                name: "T_open",
                value: MAX_COUNT + 1
            })
        );
        assert_eq!(
            new(11, 7, 102, 3, 7, 0),
            Err(ParamsError::Count {
                name: "n_mult",
                value: 0
            })
        );
        // tau = n_Delta gives k = 2 and one-bit instances are excluded by k - 1 >= 1.
        assert!(new(121, 7, 102, 3, 7, 312).is_ok());
    }

    #[test]
    fn standard_rows_are_inside_the_universal_hash_lemma_ranges() {
        for set in FAEST_PARAMETER_SETS {
            let proof = set.proof();
            assert!(
                proof.vole_hash_len() <= PROVEN_VOLE_HASH_LEN,
                "{}",
                set.name()
            );
            assert!(proof.constraints() < PROVEN_ZK_HASH_LEN, "{}", set.name());
            assert!(proof.within_proven_hash_bounds(), "{}", set.name());
        }
        assert_eq!((PROVEN_VOLE_HASH_LEN, PROVEN_ZK_HASH_LEN), (4096, 8192));
        // The boundaries: ell' = 4096 and C + 1 = 8192 are inside, one more is not.
        let vole = *FAEST_256S.vole();
        let row = |ell, constraints| ProofParams::new(vole, ell, constraints).expect("valid");
        assert_eq!(row(4088, 8191).vole_hash_len(), 4094);
        assert!(row(4088, 8191).within_proven_hash_bounds());
        assert!(!row(4088, 8192).within_proven_hash_bounds());
        assert!(!row(4096, 8191).within_proven_hash_bounds());
        let exact = VoleParams::new(L256, 22, 6, 218, 3, 9, 696).expect("valid");
        let exact = ProofParams::new(exact, 4088, 4088).expect("valid");
        assert_eq!(exact.vole_hash_len(), PROVEN_VOLE_HASH_LEN);
        assert!(exact.within_proven_hash_bounds());
    }

    #[test]
    fn the_largest_valid_row_has_a_signature_below_two_to_the_31_bits() {
        // lambda = 256, w_grind = 0, tau = 256 (k = 2), every count at its cap.
        let vole = VoleParams::new(L256, 256, 0, MAX_COUNT, 3, MAX_D_ZK, MAX_COUNT)
            .expect("largest valid row");
        let proof =
            ProofParams::new(vole, MAX_WITNESS_BITS, MAX_CONSTRAINTS).expect("largest valid row");
        let wide = |value: usize| u64::try_from(value).expect("fits");
        let expected = wide(vole.tau()) * wide(MAX_WITNESS_BITS)
            + wide(vole.n_mask()) * wide(vole.n_mult_padded())
            + (4 + wide(MAX_D_ZK) - 1 + wide(MAX_COUNT) + 3 * wide(vole.tau()) + 1) * 256
            + 128
            + 32;
        assert!(expected < 1 << 31);
        assert_eq!(wide(proof.signature_bits()), expected);
        assert!(!proof.within_proven_hash_bounds());
    }

    #[test]
    fn standard_accessors_expose_the_same_row() {
        for set in FAEST_PARAMETER_SETS {
            assert_eq!(set.vole(), set.proof().vole());
            assert_eq!(set.proof().witness_bits(), set.owf().ell());
            assert_eq!(set.proof().constraints(), set.owf().constraints());
        }
        assert_eq!(IV_BYTES, 16);
        assert_eq!(COUNTER_BITS, 32);
    }
}
