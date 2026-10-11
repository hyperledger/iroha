//! SHA-256 compression and the KAGEMUSHA digest codec (M3 gadget
//! `iroha_plonk_gadgets::sha256`, `specs/kagemusha_lambda_omega_v1.md`
//! section 9).
//!
//! Every protocol P-256 signature is `SHA256withECDSA` over the 32-byte
//! canonical (little-endian) encoding of a Poseidon digest `m`, so each
//! in-circuit ECDSA needs exactly one SHA-256 block: the 32 message bytes as
//! eight big-endian words, then the constant padding `0x80000000`, six zero
//! words and the bit length 256. [`Sha256Chip::hash_digest`] is that path:
//! [`Sha256Chip::digest_block`] (the codec, with the `m < |D|` canonicity
//! check) and one [`Sha256Chip::compress`] from the initial hash value. The
//! digest leaves as eight range-checked 32-bit words `H_0 .. H_7`; the ECDSA
//! scalar `e` is their big-endian concatenation reduced mod `n`.
//!
//! The chip is generic over the Pasta field; the KAGEMUSHA placement is the
//! `Fq` Q leaf, where `m` (a canonical `Fp` value, `|Fp| < |Fq|`) is one
//! cell holding the integer `m`. This replaces the degree-9 Table8 chip of
//! `iroha_core_zk` (`pasta_sha256_table8.rs`) with a degree-5 design that
//! uses one lookup argument instead of two.
//!
//! # Spread arithmetic
//!
//! `spread(x)` interleaves zeros between the bits of `x` (bit `i` moves to
//! bit `2 i`). The sum of up to three spread words has base-4 digits at most
//! 3, and the digit of position `i` is the number of inputs with bit `i`
//! set. So `S = spread(x) + 2 spread(y)` with spread-valid `x` and `y`
//! (both below `2^32`) has exactly one solution: `x` is the bitwise XOR of
//! the inputs and `y` their bitwise majority. Every Boolean function of a
//! round is such a *split*:
//!
//! | function | spread sum `S` | used half |
//! | --- | --- | --- |
//! | `Σ0(a)` | `spread(ROTR2 a) + spread(ROTR13 a) + spread(ROTR22 a)` | even |
//! | `Σ1(e)` | rotations 6, 11, 25 of `e` | even |
//! | `σ0(w)` | `ROTR7, ROTR18, SHR3` | even |
//! | `σ1(w)` | `ROTR17, ROTR19, SHR10` | even |
//! | `Maj(a, b, c)` | `spread(a) + spread(b) + spread(c)` | odd |
//! | `e ∧ f` | `spread(e) + spread(f)` | odd |
//! | `¬e ∧ g` | `spread(2^32 - 1) - spread(e) + spread(g)` | odd |
//!
//! `Ch(e, f, g) = (e ∧ f) + (¬e ∧ g)` because the two terms are bitwise
//! disjoint. A rotated word's spread form is a linear combination of the
//! spread forms of its pieces when every rotation amount is a piece
//! boundary, so the rotation sums are linear in the cells.
//!
//! # Layout
//!
//! Thirteen advice columns ([`SHA256_ADVICE_COLUMNS`]): the lookup pair
//! `dense, spread`, seven bit columns and four equality-enabled word
//! columns. Everything is laid out in two-row *units*, and every gate
//! queries rotations 0 and 1 only. Each unit row carries one lookup
//! `(tag, q spread, q dense)` into one table of `(2^33 + w, spread(x), x)`
//! for the widths `w` in 7, 8 and 11 and every `x < 2^w`, plus the zero row
//! of inactive rows ([`TABLE_ROWS`] = 2,433 rows, so `k >= 12`); the tags
//! sit in the SHA namespace of the shared table ([`table_tag`],
//! [`crate::table`]). The table is the chip's own three fixed columns
//! ([`Sha256Config::configure`]), or `T`, `x_0` and `V` of the Q leaf's
//! shared table, where the lookup is the guest of a foreign-field range
//! argument ([`Sha256Config::configure_shared`]; every dense value is below
//! `2^11`, inside that table's 15-bit `V` bound). The other pieces are
//! boolean cells; every decomposition unit fills all fourteen bit cells, so
//! one row-wide booleanity gate covers them.
//!
//! | unit | pieces, low to high (L = looked up) | outputs |
//! | --- | --- | --- |
//! | half | L11, 14 bits, L7 | `x`, `spread(x)` |
//! | `A_t` | 2 bits, L11, 9 bits, L7, 3 bits | `A`, `spread(A)`, `Σ0` sum |
//! | `E_t` | 6, 5, 3 bits, L11, L7 | `E`, `spread(E)`, `Σ1` sum |
//! | `W_t` | 3, 4, 3 bits, L7, 1, 1, 2 bits, L11 | `W`, `σ0` sum, `σ1` sum |
//! | bytes | L8, L8 | big- and little-endian 16-bit pairs |
//!
//! A split is two half units; the odd unit hosts the split gate
//! `even' + 2 odd = S` with the even spread and the inputs of `S` copied
//! into its free word slots. The word-level relations sit in the free word
//! slots of units of the same round; carries are word cells with a range
//! polynomial (`c (c-1) (c-2) (c-3)`, degree 4, so the gate has degree 5):
//!
//! | gate (host unit) | relation | carry |
//! | --- | --- | --- |
//! | `T1` (`e ∧ f` even) | `T1 = h + Σ1 + (e ∧ f) + W_t + K_t` | none (an integer `< 5 · 2^32`) |
//! | `E` add (`¬e ∧ g` even) | `E_t + 2^32 (c + 4 c') = d + T1 + (¬e ∧ g)` | `c < 4`, `c'` boolean |
//! | `A` add (`A_t`) | `A_t + 2^32 c = E_t - d + Σ0 + Maj + 2^32` | `c < 4` |
//! | `W` add (`σ1` even) | `W_t + 2^32 c = σ1 + W_{t-7} + σ0 + W_{t-16}` | `c < 4` |
//! | feed-forward (half) | `H_i + 2^32 c = V_i + X_i` | `c` boolean |
//! | bytes join (bytes) | `W = 2^16 hi_be + lo_be`, `L = hi_le + 2^16 lo_le` | none |
//! | borrow (half) | `C_j + L_j + β_j = P_j + 2^32 β_{j+1}`, `acc_j = 2^32 acc_{j+1} + L_j` | `β` boolean |
//!
//! `A_t = T1 + T2 mod 2^32` is checked through `E_t - d ≡ T1 (mod 2^32)`,
//! which saves a `T1` copy and keeps that carry below 4. `K_t` and the
//! borrow chain's modulus limbs `P_j` sit in one fixed column.
//!
//! # Soundness
//!
//! - Every looked-up piece is an integer below `2^w` with its true spread
//!   form and every bit is boolean, so a unit's dense value is an integer
//!   below `2^32` with a unique piece decomposition, and its spread form and
//!   rotation sums are the exact integers.
//! - In every gate both sides are integers below `2^67`, far below the
//!   field moduli, so field equality is integer equality: an addition with
//!   range-checked operands, a range-checked result and a bounded carry has
//!   the unique solution `sum mod 2^32`; a split has the unique base-4
//!   solution above.
//! - `A_t`, `E_t`, `W_t`, the feed-forward words and the split halves are
//!   unit outputs; constants enter through the constants column; every
//!   other operand is a copy. So the output is the SHA-256 compression of
//!   the inputs, which must be [`Sha256Word`]s (range-checked or constant).
//! - The codec decomposes the digest cell into 32 looked-up bytes,
//!   recomposes it (`acc_0 = digest`) and proves
//!   `(|D| - 1) - m = sum_j C_j 2^(32 j)` with range-checked `C_j` and
//!   boolean borrows (`β_0 = β_8 = 0`), so the bytes are the canonical
//!   encoding of `m < |D| <= |F|`; the alias `m + |F|` is unsatisfiable.
//!
//! # Costs (one block, measured in `tests/sha256.rs`)
//!
//! Twelve units per round, five per schedule step and eight for the
//! feed-forward: `64 · 24 + 48 · 10 + 16 = 2,032` rows, plus two rows for
//! every assigned message word `W_1 .. W_15` and state word `a, b, c, e, f,
//! g` ([`Sha256Chip::compress_rows`]), plus 48 rows for the codec
//! ([`DIGEST_CODEC_ROWS`]). A compression of sixteen assigned words uses
//! 2,062 rows and 23,251 advice cells; [`Sha256Chip::hash_digest`] 2,094
//! rows ([`HASH_DIGEST_ROWS`]) and 23,347 cells (gate G3.3: at most 2,800
//! rows and 50,000 cells). The circuit degree is 5 (the lookup, and the
//! carry range gates); with its own table there is one lookup argument, two
//! fixed columns, three table columns, one complex and seventeen simple
//! selectors, and five equality-enabled columns (the word columns and the
//! shared constants column); on the shared table, no argument and no table
//! column of its own.
//!
//! # Interface
//!
//! [`Sha256Config::configure`] takes the thirteen advice columns and a
//! constants column; [`Sha256Chip::load_table`] loads the table once per
//! circuit. Inputs are [`Sha256Word`]s: constants, or cells range-checked by
//! [`Sha256Chip::assign_u32`] / [`Sha256Chip::range_check_u32`] or produced
//! by the chip. [`Sha256Chip::compress`] returns a [`Sha256Digest`] whose
//! [`Sha256Digest::state`] chains the next block.

mod chip;
pub mod native;
mod spec;
#[cfg(test)]
mod tests;

pub use chip::{
    DIGEST_CODEC_ROWS, FEED_FORWARD_ROWS, HASH_DIGEST_ROWS, ROUND_ROWS, SCHEDULE_ROWS,
    SHA256_ADVICE_COLUMNS, Sha256Chip, Sha256Config, Sha256Digest, Sha256State, Sha256Word,
    table_tag,
};
pub use spec::{BIT_COLUMNS, TABLE_ROWS, TABLE_TAGS, UNIT_ROWS, WORD_COLUMNS};
