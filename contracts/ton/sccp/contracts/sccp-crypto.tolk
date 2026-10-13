// Cryptographic and chain-identity primitives of the SCCP v1 TON contracts.
//
// Tolk 1.4.2 has no BLS, keccak, SHA-256-over-builders or GLOBALID builtins,
// so they are declared here as asm wrappers (specs/sccp.md §5.3.7). The
// Acton emulator suite pins `GLOBALID` and the keccak wrappers in
// `tests/unit/sccp-vectors.test.tolk`, and the SHA-256, BLS and `SDLEXCMP`
// wrappers in `tests/unit/sccp-bls.test.tolk` against
// `fixtures/sccp/finality_v1.json` (stack shape and opcode gas at n = 4, 7
// and 31, §11.4).

/// `GLOBALID` (0xF835): the `global_id` of config parameter 19
/// (TON mainnet = -239).
// SAFETY: `GLOBALID` pops nothing and pushes one integer.
@pure
fun sccpGlobalId(): int
    asm "GLOBALID"

/// Current destination time in milliseconds (`now() × 1000`, §0).
@pure
fun sccpNowMs(): int {
    return blockchain.now() * 1000;
}

/// Keccak-256 (`HASHEXT` hash id 3) of the concatenation of the byte-aligned
/// slices and builders in `parts` (at most 255 entries).
// SAFETY: `EXPLODEVAR` leaves the entries in order and their count, the
// operands of `HASHEXT`. An entry that is no byte-aligned slice or builder
// makes the opcode throw.
@pure
fun keccak256Parts(parts: tuple): uint256
    asm "255 PUSHINT" "EXPLODEVAR" "3 HASHEXT"

/// Keccak-256 of the data bits of one byte-aligned builder.
// SAFETY: the argument and the count 1 are the operands of `HASHEXT`.
@pure
fun keccak256Builder(b: builder): uint256
    asm "1 PUSHINT" "3 HASHEXT"

/// Keccak-256 of two byte-aligned builders.
// SAFETY: the arguments in order and the count 2 are the operands of `HASHEXT`.
@pure
fun keccak256Builders2(a: builder, b: builder): uint256
    asm "2 PUSHINT" "3 HASHEXT"

/// Keccak-256 of two byte-aligned slices (`2 PUSHINT 3 HASHEXT`; the
/// checkpoint id over `XHead.bytes` and `XTail.bytes`, §5.3.4 item 3).
// SAFETY: the arguments in order and the count 2 are the operands of `HASHEXT`.
@pure
fun keccak256Slices2(a: slice, b: slice): uint256
    asm "2 PUSHINT" "3 HASHEXT"

/// SHA-256 (`HASHEXT` hash id 0) of the concatenation of the byte-aligned
/// slices and builders in `parts` (at most 255 entries).
// SAFETY: as `keccak256Parts`, with hash id 0.
@pure
fun sha256Parts(parts: tuple): uint256
    asm "255 PUSHINT" "EXPLODEVAR" "0 HASHEXT"

/// SHA-256 of the byte-aligned `parts` as a slice of exactly 256 bits and
/// no references (§5.3.4 item 2): `HASHEXTA` id 0 into an empty builder,
/// then `ENDC`, `CTOS`.
// SAFETY: `NEWC SWAP` puts the empty builder under the tuple, so `HASHEXTA`
// finds the builder, the entries and their count, and appends the 256-bit
// hash to the builder.
@pure
fun sha256PartsToSlice(parts: tuple): slice
    asm "NEWC" "SWAP" "255 PUSHINT" "EXPLODEVAR" "0 HASHEXTA" "ENDC" "CTOS"

/// `BLS_FASTAGGREGATEVERIFY` over the tuple `t = [k_1 … k_q, q, m, σ]`
/// (§5.3.4 item 5): `DUP TLEN UNTUPLEVAR` leaves `k_1 … k_q q m σ` with `σ`
/// on top, exactly the opcode's pop order. The opcode hashes `m` to G2 under
/// `DST_SIG`, aggregates the keys and checks the pairing; it costs
/// 58 000 + 3 000·q gas. It returns false for a key or signature that is no
/// canonical point of its subgroup, the identity key included, and it hashes
/// the whole message slice. It reads only the first 48 bytes of a key slice
/// and the first 96 of `σ`, so the caller passes slices of exactly 384 and
/// 768 bits. The caller also rejects the identity signature itself (§5.1.3
/// step 6): §3.8 requires `σ ≠ O`, and the cheap path never reaches the
/// opcode.
// SAFETY: `t` must have the shape above. `UNTUPLEVAR` then leaves exactly the
// operands of the opcode, and a tuple of another shape makes it throw, never
// verify.
@pure
fun sccpBlsFastAggregateVerify(t: tuple): bool
    asm "DUP" "TLEN" "UNTUPLEVAR" "BLS_FASTAGGREGATEVERIFY"

/// `SDLEXCMP`: −1, 0 or 1 as `a` is lexicographically below, equal to or
/// above `b` (data bits only).
// SAFETY: `SDLEXCMP` pops two slices and pushes one integer.
@pure
fun sccpLexCompare(a: slice, b: slice): int
    asm "SDLEXCMP"
