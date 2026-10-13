//! The generic proof: [`prove`] and [`verify`] for any [`Relation`], on any row
//! with embedded CRT tables, inside any [`Namespace`].
//!
//! This is FAEST.Sign and FAEST.Verify (specification Figures 8.2 and 8.3) with
//! the relation-specific points lifted out. The caller supplies
//!
//! * the row ([`VoleParams`]) and the namespace, together a [`ProofContext`];
//! * the relation and its public input ([`crate::quicksilver`]);
//! * `mu` (`2 * lambda / 8` bytes), which must bind every byte of the public
//!   statement the constraints read, the relation and the row; reference mode
//!   computes `mu = H_2^0(pk || msg)`, another relation defines its own encoding
//!   (for example with [`transcript::message_digest`]);
//! * for the prover, the witness bits and a [`Tape`] with the root seed `r` and
//!   `iv_pre`.
//!
//! # Proving
//!
//! ```text
//!  0  refuse the witness unless it satisfies the relation      (plain evaluator)
//!  1  iv = H_4(iv_pre || mu)
//!  2  (com, c_1.., c_mult, u, V, ubar, vbar) = VOLECommit(r, iv)
//!  3  chall_1 = H_2^1(mu || com || c_1 || .. || c_mult || iv_pre)
//!  4  u~ = VOLEHash(chall_1, (u bits, ubar_0..ubar_{d-2}), (ubar_{d-1}..ubar_{d+2}))
//!     V~ = VOLEHash(chall_1, (V,      vbar_0..vbar_{d-2}), (vbar_{d-1}..vbar_{d+2}))
//!  5  d = w + u
//!  6  chall_2 = H_2^2(chall_1 || u~ || V~ || d)
//!  7  a~_0 .. a~_{d-1} = QuickSilver prover
//!  8  for ctr = 0, 1, .., 2^32 - 1:
//!         chall_3 = H_2^3(chall_2 || a~_0 || .. || a~_{d-1} || ctr)
//!         stop at the first ctr whose chall_3 has zero grinding bits and whose
//!         hidden indices can be opened within T_open node keys
//!  9  proof = c_1 .. || c_mult || u~ || d || a~_1 .. || decom_I || chall_3 || iv_pre || ctr
//! ```
//!
//! Steps 1 to 7 run once; only step 8 repeats. The counter is tried in increasing
//! order from zero and never wraps: if `2^32 - 1` fails, the result is
//! [`ProofError::GrindingExhausted`] and a later attempt needs a fresh tape.
//!
//! # Variants
//!
//! A [`ProofContext`] carries one of three [`Variant`]s ([`crate::variant`]) and
//! every layer below is driven from it; there is no other switch.
//!
//! * [`ProofContext::reference`]: the empty prefix and the FAEST construction.
//!   This is the FAEST-conformant variant and the one the listing above
//!   describes.
//! * [`ProofContext::new`]: the FAEST construction inside a non-empty prefix.
//! * [`ProofContext::extended`]: the extended construction inside a non-empty
//!   prefix, on a row with `lambda = 256` and `n_leafcom = 3`. It is
//!   FAEST-derived and has no official vectors. The listing changes as follows:
//!   the tape also holds a public 32-byte salt ([`Tape::extended`]; a tape
//!   without one, or a salted tape in another variant, is
//!   [`ProofError::TapeMismatch`]); step 2 commits with affine-checked leaves and
//!   hashes every gate label with the salt; step 3 appends the salt after
//!   `iv_pre`; step 8 stops after counter [`EXTENDED_LAST_COUNTER`] with
//!   [`ProofError::GrindingExhausted`] carrying that value; step 9 writes the
//!   salt between `iv_pre` and the counter. The verifier rejects a counter above
//!   the limit with [`CodecError::CounterOutOfRange`] as soon as the length of
//!   the proof is known to be right, before the opening is examined or anything
//!   is reconstructed, then proceeds as in the other variants.
//!
//! A proof of one variant does not verify in another: the layouts differ in
//! length between the constructions, and the prefix separates the oracles.
//!
//! [`prove`] performs step 0 and returns [`ProofError::WitnessRejected`] before
//! anything is derived from the tape. [`prove_without_witness_check`] skips step 0:
//! it exists so that tests can produce the proof a cheating prover would send and
//! check that [`verify`] rejects it. It must not be used otherwise.
//!
//! # Verifying
//!
//! [`verify`] parses the proof strictly ([`crate::codec`]), recomputes
//! `iv`, runs `VOLEReconstruct`, recomputes `chall_1`, `chall_2` (with
//! `D = Q~ + Delta * u~` in the place of `V~`) and `a~_0`, hashes the supplied
//! counter **once** and accepts iff the result is the `chall_3` of the proof.
//! Nothing else is compared: the commitment, `D` and `a~_0` are bound through the
//! hash chain. It never loops over counters and does not check that the counter
//! is minimal.
//!
//! # Supported rows
//!
//! Any row with `d_zk = 7` whose `(lambda, tau, w_grind, n_mult)` has an embedded
//! table set ([`VoleParams::crt_tables`]), at any witness length
//! [`ProofParams::new`] accepts. A relation on the FAEST-256f or FAEST-256s row is
//! therefore supported unchanged; another `d_zk` is
//! [`ProofError::UnsupportedDegree`].
//!
//! # Requirements on the relation that nothing here enforces
//!
//! Witness positions `[0, lambda)` feed the CRT gate labels
//! (`L_1 = L_0 + u[0, lambda)`) and `d = w + u` is published, so those positions
//! must hold a secret with about `lambda` bits of entropy that the verifier cannot
//! guess; otherwise the masks of the check are exposed. A row with
//! `ell + d_zk - 1 > 2^12` or `C + 1 > 2^13` is outside the ranges for which the
//! specification proves its universal-hash bounds
//! ([`ProofParams::within_proven_hash_bounds`]).
//!
//! # Secrets and erasure
//!
//! The witness is read in place and never copied. `u`, `V`, the mask values and
//! tags, the seed tree and every hash state that absorbed them are owned by
//! erasing types and are erased when [`prove`] returns, whether with a proof, an
//! error or exhaustion. The tape is the caller's and erases itself on drop.
//! Operations on secrets are those of the layers below: none selects a branch, an
//! index or an early exit. The retry loop, the challenge decoding and the opening
//! depend on public values only. Everything [`verify`] handles is public.
//!
//! # Memory
//!
//! The prover's peak is inside `VOLECommit` ([`crate::vole`], "Memory"): for 36,000
//! witness bits about 3.1 MB on the FAEST-256f row (`tau = 33`) and about 8.4 MB
//! on the FAEST-256s row, whose seed tree alone is 5.9 MB. After the commitment
//! the prover holds the tree (614,368 bytes on 256f), `V` (1,152,000 bytes), the
//! corrections (144,000 bytes) and `u`, and adds the proof (160,248 bytes for
//! that witness length on 256f), the challenges and, per counter that passes the
//! grinding test, one flag per tree node (12,799 bytes). The constraint check
//! itself allocates nothing ([`crate::quicksilver`], "Resources"). The verifier
//! peaks inside `VOLEReconstruct` at about 2.3 MB and then holds `Q`
//! (1,152,000 bytes); the proof is borrowed.
//!
//! The relation's own value scratch comes on top of these figures while the
//! constraint check runs, that is after the peak of `VOLECommit` and next to the
//! tree, `V` and the corrections. A relation that buffers three arrays of 1,600
//! values (a Keccak state at three points of a round) adds about 1.3 MB for the
//! prover at `lambda = 256` and about 0.2 MB for the verifier and for the witness
//! check that precedes proving. It must be erased by the relation
//! ([`crate::quicksilver`], "Secrets").

use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(doc)]
use crate::variant::EXTENDED_LAST_COUNTER;
use crate::{
    bavc,
    codec::{self, CodecError, ProofFields},
    crt::CrtError,
    field::{FieldError, LambdaField},
    hash::Namespace,
    params::{D_ZK, ParamsError, ProofParams, VoleParams},
    quicksilver::{self, ProverInputs, QuickSilverError, Relation, VerifierInputs},
    randomness::Tape,
    transcript::{self, Challenge1Input, Challenge3, TranscriptError},
    universal_hash::{UniversalHashError, VoleHasher},
    variant::{Construction, Variant, VariantError},
    vole::{self, Opening, VoleError},
};

/// Largest `lambda / 8`.
const MAX_LAMBDA_BYTES: usize = 32;

/// Which input had the wrong length in a [`ProofError::InvalidLength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    /// `mu`, `2 * lambda / 8` bytes.
    Mu,
    /// The witness, `ell / 8` bytes.
    Witness,
    /// The root seed of the tape, `lambda / 8` bytes.
    Root,
}

/// Errors of [`prove`] and rejections of [`verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProofError {
    /// The field type is not the field of the row.
    #[error("the row needs GF(2^{expected}) and the relation was given over GF(2^{actual})")]
    FieldMismatch {
        /// `lambda` of the row.
        expected: usize,
        /// Extension degree of the field type.
        actual: usize,
    },
    /// A context outside reference mode was requested with the empty prefix.
    #[error("the namespace prefix is empty: reference mode has its own constructor")]
    EmptyNamespace,
    /// The row's `d_zk` is not the supported degree.
    #[error("rows with d_zk = {d_zk} are not supported, only d_zk = {D_ZK}")]
    UnsupportedDegree {
        /// `d_zk` of the row.
        d_zk: usize,
    },
    /// The relation's witness length or constraint count is outside the range of
    /// the row.
    #[error(transparent)]
    Params(#[from] ParamsError),
    /// An input does not have the length the row fixes for it.
    #[error("{input:?} must be {expected} bytes long, got {actual}")]
    InvalidLength {
        /// The input concerned.
        input: Input,
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// The witness does not satisfy the relation. Nothing was derived from the
    /// tape.
    #[error("the witness does not satisfy the relation")]
    WitnessRejected,
    /// No counter in `0 ..= last` gave an acceptable third challenge. The tape
    /// must not be reused.
    #[error("no counter up to {last} gave an acceptable challenge")]
    GrindingExhausted {
        /// The last counter tried.
        last: u32,
    },
    /// The recomputed third challenge is not the one in the proof: the proof is
    /// not valid for this statement.
    #[error("the proof does not verify")]
    ChallengeMismatch,
    /// The proof is malformed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The constraint check failed on a malformed relation or input.
    #[error(transparent)]
    Relation(#[from] QuickSilverError),
    /// The VOLE layer failed or rejected the opening.
    #[error(transparent)]
    Vole(#[from] VoleError),
    /// The row has no embedded CRT tables.
    #[error(transparent)]
    Tables(#[from] CrtError),
    /// A transcript input was malformed.
    #[error(transparent)]
    Transcript(#[from] TranscriptError),
    /// The universal hash rejected a challenge.
    #[error(transparent)]
    Hash(#[from] UniversalHashError),
    /// A field element could not be decoded.
    #[error(transparent)]
    Field(#[from] FieldError),
    /// The extended variant was requested on a row where it is not defined.
    #[error(transparent)]
    Variant(#[from] VariantError),
    /// The tape was made for another construction than the context's: a tape
    /// without a salt in the extended variant, or a salted tape elsewhere.
    #[error("the context runs the {context:?} construction and the tape is for {tape:?}")]
    TapeMismatch {
        /// The construction of the context.
        context: Construction,
        /// The construction of the tape.
        tape: Construction,
    },
}

fn check_length(input: Input, expected: usize, actual: usize) -> Result<(), ProofError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ProofError::InvalidLength {
            input,
            expected,
            actual,
        })
    }
}

/// What every oracle call and every size of one proof depends on besides the
/// relation: the variant, the namespace and the relation-independent row. Public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofContext<'a> {
    variant: Variant,
    namespace: Namespace<'a>,
    vole: VoleParams,
}

impl<'a> ProofContext<'a> {
    /// The context of the non-empty `namespace` on the row `vole` in the
    /// prefixed variant ([`Variant::Prefixed`]): the FAEST construction with the
    /// prefix on every oracle call, no salt, counters up to `2^32 - 1`.
    ///
    /// The empty prefix is refused: it is reference mode, in which every oracle is
    /// the one of plain FAEST, and a relation of its own that ran there by
    /// accident (an unset or wrongly sliced prefix) would lose its domain
    /// separation silently on both sides. Reference mode is reachable through
    /// [`ProofContext::reference`] only.
    ///
    /// # Errors
    /// [`ProofError::EmptyNamespace`] if `namespace` is the empty prefix.
    pub const fn new(namespace: Namespace<'a>, vole: VoleParams) -> Result<Self, ProofError> {
        if namespace.is_reference() {
            return Err(ProofError::EmptyNamespace);
        }
        Ok(Self {
            variant: Variant::Prefixed,
            namespace,
            vole,
        })
    }

    /// The context of the non-empty `namespace` on the row `vole` in the extended
    /// variant ([`Variant::Extended`]): salted first challenge and `H_5`, counters
    /// up to [`EXTENDED_LAST_COUNTER`], affine-checked leaf commitments. Proving
    /// needs a [`Tape::extended`].
    ///
    /// # Errors
    /// [`ProofError::EmptyNamespace`] if `namespace` is the empty prefix, and
    /// [`ProofError::Variant`] unless the row has `lambda = 256` and
    /// `n_leafcom = 3`.
    pub const fn extended(namespace: Namespace<'a>, vole: VoleParams) -> Result<Self, ProofError> {
        if namespace.is_reference() {
            return Err(ProofError::EmptyNamespace);
        }
        if let Err(error) = Construction::Extended.check_row(&vole) {
            return Err(ProofError::Variant(error));
        }
        Ok(Self {
            variant: Variant::Extended,
            namespace,
            vole,
        })
    }

    /// The reference-mode context (the empty prefix) on the row `vole`: plain
    /// FAEST. The only way to build a context with the empty prefix.
    pub const fn reference(vole: VoleParams) -> ProofContext<'static> {
        ProofContext {
            variant: Variant::Reference,
            namespace: Namespace::REFERENCE,
            vole,
        }
    }

    /// The variant.
    pub const fn variant(&self) -> Variant {
        self.variant
    }

    /// The construction the layers below run: that of the variant.
    pub const fn construction(&self) -> Construction {
        self.variant.construction()
    }

    /// The namespace.
    pub const fn namespace(&self) -> Namespace<'a> {
        self.namespace
    }

    /// The relation-independent row.
    pub const fn vole(&self) -> &VoleParams {
        &self.vole
    }

    /// The complete row for `relation`: its witness length, and its constraints
    /// plus one Booleanity constraint per witness bit.
    ///
    /// # Errors
    /// * [`ProofError::FieldMismatch`] unless `F` is the field of the row;
    /// * [`ProofError::UnsupportedDegree`] unless the row has `d_zk = 7`;
    /// * [`ProofError::Relation`] or [`ProofError::Params`] if the relation's
    ///   witness length or constraint count is not acceptable on the row.
    pub fn params_for<F: LambdaField, R: Relation<F> + ?Sized>(
        &self,
        relation: &R,
    ) -> Result<ProofParams, ProofError> {
        if F::LEVEL != self.vole.lambda() {
            return Err(ProofError::FieldMismatch {
                expected: self.vole.lambda().bits(),
                actual: F::BITS,
            });
        }
        if self.vole.d_zk() != D_ZK {
            return Err(ProofError::UnsupportedDegree {
                d_zk: self.vole.d_zk(),
            });
        }
        let total = quicksilver::total_constraints(relation)?;
        Ok(ProofParams::new(self.vole, relation.witness_bits(), total)?)
    }

    /// Length in bytes of every proof of `relation` in this context.
    ///
    /// # Errors
    /// As [`Self::params_for`].
    pub fn proof_bytes<F: LambdaField, R: Relation<F> + ?Sized>(
        &self,
        relation: &R,
    ) -> Result<usize, ProofError> {
        self.params_for(relation)
            .map(|params| codec::proof_bytes_as(self.construction(), &params))
    }
}

/// Serialise field elements.
fn to_bytes<F: LambdaField>(elements: &[F]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(elements.len() * F::BYTES);
    for element in elements {
        bytes.extend_from_slice(element.to_bytes().as_ref());
    }
    bytes
}

/// `VOLEHash(chall_1, (rows, masks[..d_zk - 1]), masks[d_zk - 1..])` where `rows`
/// feeds the `ell` leading elements of the first input.
fn vole_hash<F: LambdaField>(
    challenge_1: &[u8],
    rows: impl FnOnce(&mut VoleHasher<F>) -> Result<(), ProofError>,
    masks: &[F],
) -> Result<[F; 4], ProofError> {
    let mut hasher = VoleHasher::<F>::new(challenge_1)?;
    rows(&mut hasher)?;
    let (head, tail) = masks.split_at_checked(D_ZK - 1).unwrap_or((masks, &[]));
    for mask in head {
        hasher.update(*mask);
    }
    let mut last = Zeroizing::new([F::ZERO; 4]);
    for (slot, mask) in last.iter_mut().zip(tail) {
        *slot = *mask;
    }
    Ok(hasher.finalize(&last))
}

/// Feed the field elements serialised in `bytes` to `hasher`.
fn feed_elements<F: LambdaField>(
    hasher: &mut VoleHasher<F>,
    bytes: &[u8],
) -> Result<(), ProofError> {
    for chunk in bytes.chunks_exact(F::BYTES) {
        hasher.update(F::from_bytes(chunk)?);
    }
    Ok(())
}

/// Prove that `witness` satisfies `relation` for `public`.
///
/// `mu` is `2 * lambda / 8` bytes and `witness` is `ell / 8` bytes with bit `i` at
/// bit `i mod 8` of byte `i / 8`. The proof is deterministic in its inputs: the
/// same context, relation, public input, `mu`, witness and tape give the same
/// bytes. Its length is [`ProofContext::proof_bytes`].
///
/// # Errors
/// * [`ProofError::WitnessRejected`] if the witness violates a constraint; this
///   is decided before the tape is used;
/// * [`ProofError::GrindingExhausted`] if no counter up to
///   [`Construction::last_counter`] is acceptable;
/// * [`ProofError::InvalidLength`] for `mu`, the witness or a tape of another
///   security level;
/// * [`ProofError::TapeMismatch`] unless the tape was made for the construction
///   of the context; this too is decided before the tape is used;
/// * the errors of [`ProofContext::params_for`], [`ProofError::Tables`] for a row
///   without embedded tables, and [`ProofError::Relation`] for a malformed
///   relation.
pub fn prove<F: LambdaField, R: Relation<F> + ?Sized>(
    context: &ProofContext<'_>,
    relation: &R,
    public: &R::PublicInput,
    mu: &[u8],
    witness: &[u8],
    tape: &Tape,
) -> Result<Vec<u8>, ProofError> {
    prove_bounded::<F, R>(
        context,
        relation,
        public,
        &Secrets {
            mu,
            witness,
            tape,
            check: true,
        },
        context.construction().last_counter(),
    )
}

/// [`prove`] without the check that the witness satisfies the relation.
///
/// **Test support only.** For a violating witness this returns the bytes a
/// cheating prover would send, which [`verify`] rejects; it exists so that tests
/// of soundness have such bytes. A caller with a real witness gains nothing from
/// it and loses the guarantee that no proof is produced for a false statement.
///
/// # Errors
/// As [`prove`], without [`ProofError::WitnessRejected`].
pub fn prove_without_witness_check<F: LambdaField, R: Relation<F> + ?Sized>(
    context: &ProofContext<'_>,
    relation: &R,
    public: &R::PublicInput,
    mu: &[u8],
    witness: &[u8],
    tape: &Tape,
) -> Result<Vec<u8>, ProofError> {
    prove_bounded::<F, R>(
        context,
        relation,
        public,
        &Secrets {
            mu,
            witness,
            tape,
            check: false,
        },
        context.construction().last_counter(),
    )
}

/// The last counter the prover tries: `requested`, or the last counter of the
/// construction if that is smaller.
const fn counter_bound(construction: Construction, requested: u32) -> u32 {
    let limit = construction.last_counter();
    if requested < limit { requested } else { limit }
}

/// The prover's per-proof inputs.
struct Secrets<'a> {
    mu: &'a [u8],
    witness: &'a [u8],
    tape: &'a Tape,
    /// Whether to refuse a witness that violates the relation.
    check: bool,
}

/// [`prove`] with the counters `0 ..= last_counter`, or up to the last counter
/// of the construction if that is smaller.
fn prove_bounded<F: LambdaField, R: Relation<F> + ?Sized>(
    context: &ProofContext<'_>,
    relation: &R,
    public: &R::PublicInput,
    secrets: &Secrets<'_>,
    last_counter: u32,
) -> Result<Vec<u8>, ProofError> {
    let Secrets {
        mu,
        witness,
        tape,
        check,
    } = *secrets;
    let namespace = context.namespace;
    let construction = context.construction();
    let last_counter = counter_bound(construction, last_counter);
    let params = context.params_for::<F, R>(relation)?;
    let vole = params.vole();
    let level = vole.lambda();
    let lb = level.bytes();
    check_length(Input::Mu, 2 * lb, mu.len())?;
    check_length(Input::Witness, params.witness_bytes(), witness.len())?;
    check_length(Input::Root, lb, tape.level().bytes())?;
    let binding = tape.binding();
    if binding.construction() != construction {
        return Err(ProofError::TapeMismatch {
            context: construction,
            tape: binding.construction(),
        });
    }
    let tables = vole.crt_tables()?;
    if check && !quicksilver::is_satisfied::<F, R>(relation, public, witness)? {
        return Err(ProofError::WitnessRejected);
    }

    let iv = transcript::derive_iv(namespace, level, tape.iv_pre(), mu)?;
    let commitment = vole::commit_as(namespace, binding, &params, tables, tape.root(), &iv)?;
    let challenge_1 = transcript::challenge_1_as(
        namespace,
        binding,
        &params,
        &Challenge1Input {
            mu,
            commitment: commitment.commitment(),
            corrections: commitment.corrections(),
            mult_corrections: commitment.mult_corrections(),
            iv_pre: tape.iv_pre(),
        },
    )?;

    let u = commitment.u();
    let u_tilde = {
        let masks = vole::elements::<F>(vole, commitment.u_masks())?;
        vole_hash::<F>(
            &challenge_1,
            |hasher| {
                for position in 0..params.witness_bits() {
                    hasher.update_bit(u[position / 8] >> (position % 8));
                }
                Ok(())
            },
            &masks,
        )?
    };
    let v_tilde = {
        let masks = vole::elements::<F>(vole, commitment.v_masks())?;
        vole_hash::<F>(
            &challenge_1,
            |hasher| feed_elements(hasher, commitment.v()),
            &masks,
        )?
    };
    let u_tilde = to_bytes(&u_tilde);
    let v_tilde = to_bytes(&v_tilde);

    // d = w + u is public.
    let mut masked_witness = u.to_vec();
    for (masked, bits) in masked_witness.iter_mut().zip(witness) {
        *masked ^= *bits;
    }
    let challenge_2 = transcript::challenge_2(
        namespace,
        &params,
        &challenge_1,
        &u_tilde,
        &v_tilde,
        &masked_witness,
    )?;

    let coefficients = quicksilver::prove::<F, R>(
        relation,
        public,
        &ProverInputs {
            witness,
            tags: commitment.v(),
            mask_values: commitment.u_masks(),
            mask_tags: commitment.v_masks(),
        },
        &challenge_2,
    )?;
    let coefficients = to_bytes(&coefficients);

    let grinder = Challenge3::new(namespace, vole, &challenge_2, &coefficients)?;
    let mut challenge_3 = [0u8; MAX_LAMBDA_BYTES];
    let challenge_3 = &mut challenge_3[..lb];
    let mut counter = 0u32;
    let decommitment = loop {
        grinder.at(counter, challenge_3)?;
        let opened = bavc::decode_challenge(vole, challenge_3)
            .map_err(VoleError::from)
            .and_then(|hidden| commitment.open(&hidden));
        match opened {
            Ok(decommitment) => break decommitment,
            Err(error) if error.is_retry() => {}
            Err(error) => return Err(error.into()),
        }
        if counter == last_counter {
            return Err(ProofError::GrindingExhausted { last: last_counter });
        }
        counter += 1;
    };

    Ok(codec::encode_as(
        construction,
        &params,
        &ProofFields {
            corrections: commitment.corrections(),
            mult_corrections: commitment.mult_corrections(),
            u_tilde: &u_tilde,
            masked_witness: &masked_witness,
            coefficients: coefficients.get(lb..).unwrap_or(&[]),
            decommitment: &decommitment,
            challenge: challenge_3,
            iv_pre: tape.iv_pre(),
            salt: binding.salt(),
            counter,
        },
    )?)
}

/// Verify `proof` for `relation`, `public` and `mu` in `context`.
///
/// This is a verifier entry point: `proof` is untrusted. The supplied counter is
/// hashed once; no grinding is repeated.
///
/// # Errors
/// Every error is a rejection:
/// * [`ProofError::Codec`] for a proof of the wrong length, with a counter above
///   the limit of the variant ([`CodecError::CounterOutOfRange`], decided before
///   anything is reconstructed) or with non-canonical padding or challenge;
/// * [`ProofError::ChallengeMismatch`] if the proof does not verify;
/// * [`ProofError::Vole`] if the opening is rejected;
/// * [`ProofError::InvalidLength`] for `mu`, the errors of
///   [`ProofContext::params_for`], [`ProofError::Tables`] and
///   [`ProofError::Relation`] for a misuse on the verifier's own side.
pub fn verify<F: LambdaField, R: Relation<F> + ?Sized>(
    context: &ProofContext<'_>,
    relation: &R,
    public: &R::PublicInput,
    mu: &[u8],
    proof: &[u8],
) -> Result<(), ProofError> {
    let params = context.params_for::<F, R>(relation)?;
    let lb = params.vole().lambda().bytes();
    check_length(Input::Mu, 2 * lb, mu.len())?;
    let fields = codec::decode_as(context.construction(), &params, proof)?;
    let mut challenge_3 = [0u8; MAX_LAMBDA_BYTES];
    let challenge_3 = &mut challenge_3[..lb];
    grinder_of::<F, R>(context, &params, relation, public, mu, &fields)?
        .at(fields.counter, challenge_3)?;
    if challenge_3 == fields.challenge {
        Ok(())
    } else {
        Err(ProofError::ChallengeMismatch)
    }
}

/// The verifier's `chall_3` oracle for the decoded proof `fields`: everything
/// `chall_3` absorbs before the counter, recomputed from the opening.
fn grinder_of<F: LambdaField, R: Relation<F> + ?Sized>(
    context: &ProofContext<'_>,
    params: &ProofParams,
    relation: &R,
    public: &R::PublicInput,
    mu: &[u8],
    fields: &ProofFields<'_>,
) -> Result<Challenge3, ProofError> {
    let namespace = context.namespace;
    // The salt, if any, comes from the proof; `decode_as` yields one exactly in
    // the extended layout.
    let binding = fields.binding();
    let vole = params.vole();
    let level = vole.lambda();
    let lb = level.bytes();
    let tables = vole.crt_tables()?;

    let iv = transcript::derive_iv(namespace, level, fields.iv_pre, mu)?;
    let opened = vole::reconstruct_as(
        namespace,
        binding,
        params,
        tables,
        &Opening {
            challenge: fields.challenge,
            decommitment: fields.decommitment,
            corrections: fields.corrections,
            mult_corrections: fields.mult_corrections,
        },
        &iv,
    )?;
    let challenge_1 = transcript::challenge_1_as(
        namespace,
        binding,
        params,
        &Challenge1Input {
            mu,
            commitment: opened.commitment(),
            corrections: fields.corrections,
            mult_corrections: fields.mult_corrections,
            iv_pre: fields.iv_pre,
        },
    )?;

    // D = Q~ + Delta * u~ stands in for the prover's V~.
    let delta = F::from_bytes(opened.delta())?;
    let masks = vole::elements::<F>(vole, opened.q_masks())?;
    let mut d_tilde = vole_hash::<F>(
        &challenge_1,
        |hasher| feed_elements(hasher, opened.q()),
        &masks,
    )?;
    for (slot, bytes) in d_tilde.iter_mut().zip(fields.u_tilde.chunks_exact(lb)) {
        *slot += delta * F::from_bytes(bytes)?;
    }
    let challenge_2 = transcript::challenge_2(
        namespace,
        params,
        &challenge_1,
        fields.u_tilde,
        &to_bytes(&d_tilde),
        fields.masked_witness,
    )?;

    let first = quicksilver::verify::<F, R>(
        relation,
        public,
        &VerifierInputs {
            masked_witness: fields.masked_witness,
            keys: opened.q(),
            mask_keys: opened.q_masks(),
            delta: opened.delta(),
        },
        &challenge_2,
        fields.coefficients,
    )?;
    let mut coefficients = to_bytes(&[first]);
    coefficients.extend_from_slice(fields.coefficients);

    Ok(Challenge3::new(
        namespace,
        vole,
        &challenge_2,
        &coefficients,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bavc::BavcError,
        field::{Gf128, Gf192, Gf256},
        params::{FAEST_128F, FAEST_192F, FAEST_256F, SecurityLevel},
        quicksilver::ConstraintSystem,
    };

    /// `w_{2i} * w_{2i+1} + w_{128+i} + p_i = 0` for `i < 8`, on 256 witness bits.
    struct Pairs;

    impl<F: LambdaField> Relation<F> for Pairs {
        type PublicInput = [bool; 8];

        fn witness_bits(&self) -> usize {
            256
        }

        fn constraints(&self) -> usize {
            8
        }

        fn emit<C: ConstraintSystem<Field = F>>(&self, public: &[bool; 8], cs: &mut C) {
            for (i, bit) in public.iter().enumerate() {
                let product = cs.mul(cs.witness(2 * i), cs.witness(2 * i + 1));
                cs.constrain(cs.add_bit(cs.add(product, cs.witness(128 + i)), *bit));
            }
        }
    }

    const PUBLIC: [bool; 8] = [true, false, false, true, true, true, false, true];

    fn witness(salt: u8) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0u8..32)
            .map(|at| at.wrapping_mul(73).wrapping_add(salt) ^ 0x5c)
            .collect();
        bytes[16] = 0;
        for (i, bit) in PUBLIC.iter().enumerate() {
            let product = (bytes[i / 4] >> (2 * i % 8)) & (bytes[i / 4] >> ((2 * i + 1) % 8)) & 1;
            bytes[16] |= (product ^ u8::from(*bit)) << i;
        }
        bytes
    }

    fn tape(level: SecurityLevel, salt: u8) -> Tape {
        let root: Vec<u8> = (0u8..32)
            .map(|at| at.wrapping_mul(salt | 1) ^ salt)
            .take(level.bytes())
            .collect();
        Tape::explicit(level, &root, &[salt; 16]).expect("valid tape")
    }

    fn secrets<'a>(mu: &'a [u8], witness: &'a [u8], tape: &'a Tape) -> Secrets<'a> {
        Secrets {
            mu,
            witness,
            tape,
            check: true,
        }
    }

    #[test]
    fn honest_proofs_verify_at_every_level() {
        fn check<F: LambdaField>(vole: &VoleParams) {
            let namespace = Namespace::new(b"proof unit tests").expect("bounded");
            for context in [
                ProofContext::reference(*vole),
                ProofContext::new(namespace, *vole).expect("non-empty prefix"),
            ] {
                let level = vole.lambda();
                let mu = vec![0x6du8; 2 * level.bytes()];
                let witness = witness(1);
                let proof =
                    prove::<F, _>(&context, &Pairs, &PUBLIC, &mu, &witness, &tape(level, 3))
                        .expect("valid witness");
                assert_eq!(Ok(proof.len()), context.proof_bytes::<F, _>(&Pairs));
                assert_eq!(
                    verify::<F, _>(&context, &Pairs, &PUBLIC, &mu, &proof),
                    Ok(())
                );
                let mut other = PUBLIC;
                other[7] ^= true;
                assert_eq!(
                    verify::<F, _>(&context, &Pairs, &other, &mu, &proof),
                    Err(ProofError::ChallengeMismatch)
                );
            }
        }
        check::<Gf128>(FAEST_128F.vole());
        check::<Gf192>(FAEST_192F.vole());
        check::<Gf256>(FAEST_256F.vole());
    }

    #[test]
    fn the_counter_loop_stops_at_the_first_acceptable_counter_and_never_wraps() {
        let context = ProofContext::reference(*FAEST_128F.vole());
        let mu = [0x21u8; 32];
        let witness = witness(2);
        let tape = tape(SecurityLevel::L128, 9);
        let inputs = secrets(&mu, &witness, &tape);
        let proof = prove_bounded::<Gf128, _>(&context, &Pairs, &PUBLIC, &inputs, u32::MAX)
            .expect("valid witness");
        let counter = u32::from_le_bytes(proof[proof.len() - 4..].try_into().expect("4 bytes"));
        assert!(counter > 0, "pick a tape whose first counter fails");

        // The same bytes with any bound at or above the counter.
        let bounded = prove_bounded::<Gf128, _>(&context, &Pairs, &PUBLIC, &inputs, counter)
            .expect("the counter is within the bound");
        assert_eq!(bounded, proof);
        // Exhaustion at every smaller bound, zero included.
        for last in [0, counter / 2, counter - 1] {
            assert_eq!(
                prove_bounded::<Gf128, _>(&context, &Pairs, &PUBLIC, &inputs, last),
                Err(ProofError::GrindingExhausted { last })
            );
        }

        // No earlier counter is acceptable: the proof's counter is the first one.
        let params = context.params_for::<Gf128, _>(&Pairs).expect("valid row");
        let fields = codec::decode(&params, &proof).expect("canonical");
        for earlier in [0, counter - 1] {
            let mut forged = proof.clone();
            let at = forged.len() - 4;
            forged[at..].copy_from_slice(&earlier.to_le_bytes());
            assert_eq!(
                verify::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu, &forged),
                Err(ProofError::ChallengeMismatch)
            );
        }
        assert_eq!(fields.counter, counter);
    }

    /// Why the prover must skip a counter, recomputed from `chall_3` alone.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Skipped {
        /// A grinding bit is set.
        Grinding,
        /// The grinding bits are zero and the opening has more than `T_open` keys.
        Opening,
    }

    /// The fate of every counter up to the one in `proof`, recomputed on the
    /// verifier's side: the reasons the earlier ones are skipped, in order.
    fn skipped_counters<F: LambdaField>(
        context: &ProofContext<'_>,
        mu: &[u8],
        proof: &[u8],
    ) -> Vec<Skipped> {
        let params = context.params_for::<F, _>(&Pairs).expect("valid row");
        let vole = params.vole();
        let fields = codec::decode(&params, proof).expect("canonical");
        let grinder = grinder_of::<F, _>(context, &params, &Pairs, &PUBLIC, mu, &fields)
            .expect("the opening reconstructs");
        let mut challenge = vec![0u8; vole.lambda().bytes()];
        let mut fate = |counter: u32| {
            grinder.at(counter, &mut challenge).expect("valid length");
            match bavc::decode_challenge(vole, &challenge) {
                Err(BavcError::GrindingBitsSet) => Some(Skipped::Grinding),
                Err(other) => panic!("unexpected {other:?}"),
                Ok(hidden) => {
                    let nodes = bavc::opening_nodes(vole, &hidden).expect("valid pattern");
                    (nodes > vole.t_open()).then_some(Skipped::Opening)
                }
            }
        };
        let skipped = (0..fields.counter)
            .map(|counter| fate(counter).expect("an earlier counter was acceptable"))
            .collect();
        assert_eq!(
            fate(fields.counter),
            None,
            "the proof's counter is acceptable"
        );
        skipped
    }

    /// The counter rule: a counter is skipped when a grinding bit of its
    /// challenge is set **or** when the opening it selects has more than `T_open`
    /// node keys, and the proof carries the first counter with neither failure.
    #[test]
    fn a_counter_whose_opening_is_too_large_is_skipped_like_a_grinding_failure() {
        // The standard FAEST-128f row, on which about a third of the challenges
        // with zero grinding bits select an opening above T_open = 108.
        let standard = *FAEST_128F.vole();
        // The same geometry with a tight T_open: nearly every such challenge
        // aborts, so the accepted counter comes after several aborts.
        let tight = VoleParams::new(
            standard.lambda(),
            standard.tau(),
            standard.w_grind(),
            96,
            standard.n_leafcom(),
            D_ZK,
            standard.n_mult(),
        )
        .expect("valid row");
        let mu = [0x21u8; 32];
        let witness = witness(2);
        for (vole, at_least) in [(standard, 1), (tight, 2)] {
            let context = ProofContext::reference(vole);
            let mut aborting_runs = 0;
            for salt in 0..12 {
                let tape = tape(SecurityLevel::L128, salt);
                let proof = prove::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu, &witness, &tape)
                    .expect("valid witness");
                assert_eq!(
                    verify::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu, &proof),
                    Ok(())
                );
                let skipped = skipped_counters::<Gf128>(&context, &mu, &proof);
                let aborts = skipped
                    .iter()
                    .filter(|reason| **reason == Skipped::Opening)
                    .count();
                if aborts >= at_least {
                    aborting_runs += 1;
                    // The bound just below the counter exhausts: the aborting
                    // counters were not accepted with a truncated opening.
                    let last = u32::try_from(skipped.len()).expect("small") - 1;
                    assert_eq!(
                        prove_bounded::<Gf128, _>(
                            &context,
                            &Pairs,
                            &PUBLIC,
                            &secrets(&mu, &witness, &tape),
                            last
                        ),
                        Err(ProofError::GrindingExhausted { last })
                    );
                }
            }
            assert!(
                aborting_runs > 0,
                "no tape with {at_least} opening aborts before the accepted counter"
            );
        }
    }

    #[test]
    fn a_violating_witness_is_refused_before_the_tape_is_used() {
        let context = ProofContext::reference(*FAEST_128F.vole());
        let mu = [0x21u8; 32];
        let mut broken = witness(4);
        broken[16] ^= 1;
        // A tape of the wrong level would be an error if it were looked at after
        // the witness; the length checks come first, so use a valid one and a
        // bound of zero: the refusal comes before any grinding.
        let tape = tape(SecurityLevel::L128, 9);
        assert_eq!(
            prove_bounded::<Gf128, _>(&context, &Pairs, &PUBLIC, &secrets(&mu, &broken, &tape), 0),
            Err(ProofError::WitnessRejected)
        );
        assert_eq!(
            prove::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu, &broken, &tape),
            Err(ProofError::WitnessRejected)
        );
        let forged =
            prove_without_witness_check::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu, &broken, &tape)
                .expect("no check");
        assert_eq!(
            verify::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu, &forged),
            Err(ProofError::ChallengeMismatch)
        );
    }

    #[test]
    fn the_empty_prefix_is_reachable_through_the_reference_constructor_only() {
        let vole = *FAEST_128F.vole();
        let empty = Namespace::new(b"").expect("bounded");
        assert_eq!(
            ProofContext::new(empty, vole),
            Err(ProofError::EmptyNamespace)
        );
        assert_eq!(
            ProofContext::new(Namespace::REFERENCE, vole),
            Err(ProofError::EmptyNamespace)
        );
        let one = Namespace::new(b"x").expect("bounded");
        let context = ProofContext::new(one, vole).expect("non-empty prefix");
        assert_eq!(context.namespace(), one);
        assert_eq!(context.vole(), &vole);
        assert!(!context.namespace().is_reference());
        assert!(ProofContext::reference(vole).namespace().is_reference());
    }

    #[test]
    fn misuse_is_a_typed_error() {
        let vole = *FAEST_128F.vole();
        let context = ProofContext::reference(vole);
        assert_eq!(context.vole(), &vole);
        assert!(context.namespace().is_reference());
        let mu = [0u8; 32];
        let witness = witness(5);
        let good = tape(SecurityLevel::L128, 1);
        assert_eq!(
            prove::<Gf256, _>(&context, &Pairs, &PUBLIC, &mu, &witness, &good),
            Err(ProofError::FieldMismatch {
                expected: 128,
                actual: 256
            })
        );
        assert_eq!(
            verify::<Gf192, _>(&context, &Pairs, &PUBLIC, &mu, &[]),
            Err(ProofError::FieldMismatch {
                expected: 128,
                actual: 192
            })
        );
        assert_eq!(
            prove::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu[1..], &witness, &good),
            Err(ProofError::InvalidLength {
                input: Input::Mu,
                expected: 32,
                actual: 31
            })
        );
        assert_eq!(
            prove::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu, &witness[1..], &good),
            Err(ProofError::InvalidLength {
                input: Input::Witness,
                expected: 32,
                actual: 31
            })
        );
        assert_eq!(
            prove::<Gf128, _>(
                &context,
                &Pairs,
                &PUBLIC,
                &mu,
                &witness,
                &tape(SecurityLevel::L256, 1)
            ),
            Err(ProofError::InvalidLength {
                input: Input::Root,
                expected: 16,
                actual: 32
            })
        );
        assert_eq!(
            verify::<Gf128, _>(&context, &Pairs, &PUBLIC, &mu[1..], &[]),
            Err(ProofError::InvalidLength {
                input: Input::Mu,
                expected: 32,
                actual: 31
            })
        );

        // Another d_zk, a row without tables, a witness shorter than lambda.
        let degree = VoleParams::new(SecurityLevel::L128, 17, 8, 108, 3, 5, 312).expect("valid");
        assert_eq!(
            ProofContext::reference(degree).params_for::<Gf128, _>(&Pairs),
            Err(ProofError::UnsupportedDegree { d_zk: 5 })
        );
        let foreign = VoleParams::new(SecurityLevel::L128, 16, 8, 108, 3, 7, 312).expect("valid");
        assert!(matches!(
            prove::<Gf128, _>(
                &ProofContext::reference(foreign),
                &Pairs,
                &PUBLIC,
                &mu,
                &witness,
                &good
            ),
            Err(ProofError::Tables(_))
        ));
        assert!(matches!(
            ProofContext::reference(*FAEST_256F.vole()).params_for::<Gf256, _>(&Short),
            Err(ProofError::Params(_))
        ));
        assert_eq!(check_length(Input::Mu, 2, 2), Ok(()));
    }

    /// A relation whose witness is shorter than `lambda = 256`.
    struct Short;

    impl Relation<Gf256> for Short {
        type PublicInput = ();

        fn witness_bits(&self) -> usize {
            128
        }

        fn constraints(&self) -> usize {
            0
        }

        fn emit<C: ConstraintSystem<Field = Gf256>>(&self, (): &(), _: &mut C) {}
    }

    #[test]
    fn the_hash_helpers_split_the_masks_and_serialise_elements() {
        type F = Gf128;
        let challenge = [0x35u8; 136];
        let masks: Vec<F> = (1..=10).map(F::from_u64).collect();
        let rows = [F::from_u64(100), F::from_u64(101)];
        let bytes = to_bytes(&rows);
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 100);
        assert_eq!(bytes[16], 101);
        let hashed = vole_hash::<F>(&challenge, |hasher| feed_elements(hasher, &bytes), &masks)
            .expect("valid challenge");
        let mut x0 = rows.to_vec();
        x0.extend_from_slice(&masks[..6]);
        let x1: [F; 4] = masks[6..].try_into().expect("four elements");
        assert_eq!(
            hashed,
            crate::universal_hash::vole_hash(&challenge, &x0, &x1).expect("valid challenge")
        );
        assert!(matches!(
            vole_hash::<F>(&challenge[1..], |_| Ok(()), &masks),
            Err(ProofError::Hash(_))
        ));
    }

    const SALT: [u8; 32] = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e,
        0x0f, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff,
    ];

    fn extended_tape(salt: u8) -> Tape {
        let root: Vec<u8> = (0u8..32)
            .map(|at| at.wrapping_mul(salt | 1) ^ salt)
            .collect();
        Tape::extended(SecurityLevel::L256, &root, &[salt; 16], &SALT).expect("valid tape")
    }

    #[test]
    fn contexts_carry_their_variant() {
        use crate::params::{FAEST_256S, FAEST_EM_256F};
        let namespace = Namespace::new(b"variants").expect("bounded");
        let fast = *FAEST_256F.vole();
        let reference = ProofContext::reference(fast);
        assert_eq!(reference.variant(), Variant::Reference);
        assert_eq!(reference.construction(), Construction::Faest);
        let prefixed = ProofContext::new(namespace, fast).expect("non-empty prefix");
        assert_eq!(prefixed.variant(), Variant::Prefixed);
        assert_eq!(prefixed.construction(), Construction::Faest);
        for set in [FAEST_256F, FAEST_256S] {
            let vole = *set.vole();
            let extended = ProofContext::extended(namespace, vole).expect("supported row");
            assert_eq!(extended.variant(), Variant::Extended);
            assert_eq!(extended.construction(), Construction::Extended);
            assert_eq!(extended.namespace(), namespace);
            assert_eq!(extended.vole(), &vole);
            // 32 bytes of salt and 16 more per hidden leaf commitment.
            let plain = ProofContext::new(namespace, vole).expect("non-empty prefix");
            assert_eq!(
                extended.proof_bytes::<Gf256, _>(&Pairs),
                plain
                    .proof_bytes::<Gf256, _>(&Pairs)
                    .map(|bytes| bytes + 32 + 16 * vole.tau())
            );
        }
        assert_eq!(
            ProofContext::extended(Namespace::REFERENCE, fast),
            Err(ProofError::EmptyNamespace)
        );
        assert_eq!(
            ProofContext::extended(namespace, *FAEST_128F.vole()),
            Err(ProofError::Variant(VariantError::UnsupportedLevel {
                lambda: 128
            }))
        );
        assert_eq!(
            ProofContext::extended(namespace, *FAEST_192F.vole()),
            Err(ProofError::Variant(VariantError::UnsupportedLevel {
                lambda: 192
            }))
        );
        assert_eq!(
            ProofContext::extended(namespace, *FAEST_EM_256F.vole()),
            Err(ProofError::Variant(VariantError::UnsupportedLeafBlocks {
                n_leafcom: 2
            }))
        );
    }

    #[test]
    fn extended_proofs_need_extended_tapes_and_verify() {
        let namespace = Namespace::new(b"proof unit tests").expect("bounded");
        let vole = *FAEST_256F.vole();
        let extended = ProofContext::extended(namespace, vole).expect("supported row");
        let prefixed = ProofContext::new(namespace, vole).expect("non-empty prefix");
        let mu = [0x6du8; 64];
        let witness = witness(1);
        let proof = prove::<Gf256, _>(&extended, &Pairs, &PUBLIC, &mu, &witness, &extended_tape(3))
            .expect("valid witness");
        assert_eq!(Ok(proof.len()), extended.proof_bytes::<Gf256, _>(&Pairs));
        assert_eq!(
            verify::<Gf256, _>(&extended, &Pairs, &PUBLIC, &mu, &proof),
            Ok(())
        );
        // The salt sits between iv_pre and the counter.
        let at = proof.len() - 4 - 32;
        assert_eq!(proof[at..at + 32], SALT);
        assert_eq!(proof[at - 16..at], [3u8; 16]);

        let mismatch = |context: Construction, tape: Construction| {
            Err(ProofError::TapeMismatch { context, tape })
        };
        let plain = tape(SecurityLevel::L256, 3);
        assert_eq!(
            prove::<Gf256, _>(&extended, &Pairs, &PUBLIC, &mu, &witness, &plain),
            mismatch(Construction::Extended, Construction::Faest)
        );
        for context in [prefixed, ProofContext::reference(vole)] {
            assert_eq!(
                prove::<Gf256, _>(&context, &Pairs, &PUBLIC, &mu, &witness, &extended_tape(3)),
                mismatch(Construction::Faest, Construction::Extended)
            );
        }
        assert_eq!(
            prove_without_witness_check::<Gf256, _>(
                &extended, &Pairs, &PUBLIC, &mu, &witness, &plain
            ),
            mismatch(Construction::Extended, Construction::Faest)
        );
    }

    #[test]
    fn the_counter_bound_is_the_smaller_of_the_request_and_the_limit() {
        use crate::variant::EXTENDED_LAST_COUNTER;
        assert_eq!(EXTENDED_LAST_COUNTER, 0x000f_ffff);
        assert_eq!(
            counter_bound(Construction::Extended, u32::MAX),
            EXTENDED_LAST_COUNTER
        );
        assert_eq!(
            counter_bound(Construction::Extended, EXTENDED_LAST_COUNTER + 1),
            EXTENDED_LAST_COUNTER
        );
        assert_eq!(counter_bound(Construction::Extended, 7), 7);
        assert_eq!(counter_bound(Construction::Faest, u32::MAX), u32::MAX);
        assert_eq!(counter_bound(Construction::Faest, 0), 0);
    }

    #[test]
    fn extended_exhaustion_reports_the_last_counter_tried() {
        let namespace = Namespace::new(b"proof unit tests").expect("bounded");
        let context = ProofContext::extended(namespace, *FAEST_256F.vole()).expect("supported");
        let mu = [0x21u8; 64];
        let witness = witness(2);
        let tape = extended_tape(9);
        let inputs = secrets(&mu, &witness, &tape);
        let proof = prove_bounded::<Gf256, _>(&context, &Pairs, &PUBLIC, &inputs, u32::MAX)
            .expect("valid witness");
        assert_eq!(
            prove::<Gf256, _>(&context, &Pairs, &PUBLIC, &mu, &witness, &tape).as_ref(),
            Ok(&proof)
        );
        let counter = u32::from_le_bytes(proof[proof.len() - 4..].try_into().expect("4 bytes"));
        assert!(counter > 0, "pick a tape whose first counter fails");
        assert!(counter <= context.construction().last_counter());
        // The limit is a parameter of the same loop: with a tiny limit below the
        // accepted counter the prover stops there and reports it, without wrapping.
        for last in [0, counter - 1] {
            assert_eq!(
                prove_bounded::<Gf256, _>(&context, &Pairs, &PUBLIC, &inputs, last),
                Err(ProofError::GrindingExhausted { last })
            );
        }
        assert_eq!(
            prove_bounded::<Gf256, _>(&context, &Pairs, &PUBLIC, &inputs, counter).as_ref(),
            Ok(&proof)
        );
    }
}
