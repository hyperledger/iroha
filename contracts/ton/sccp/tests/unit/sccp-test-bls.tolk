// Test-side BLS12-381 min-pk signing for the SCCP v1 TON emulator suite.
//
// The minter verifies Taira's `CommitQC` with `BLS_FASTAGGREGATEVERIFY`
// (specs/sccp.md §3.8, §5.3.4). The committed fixtures hold a fixed set of
// certificates; scenario tests also need a certificate over any `X` at any
// time, so this file signs in the test VM with the fixture test keys:
//
//     σ = (Σ sk_i mod r) · hash_to_G2(m)
//
// `hash_to_G2` is RFC 9380 `BLS12381G2_XMD:SHA-256_SSWU_RO_` under `DST_SIG`:
// `expand_message_xmd` runs on `HASHEXT` SHA-256, the four field elements are
// reduced modulo `p` over two 256-bit limbs, and the map, the cofactor
// clearing and the group operations are the native `BLS_MAP_TO_G2`,
// `BLS_G2_ADD` and `BLS_G2_MUL` opcodes. `BLS_MAP_TO_G2` maps one field
// element and clears the cofactor, and both steps are homomorphisms, so the
// sum of the two mapped points is the RFC's `hash_to_curve`.
//
// This is test-only code: it never runs in a contract, and the secret keys it
// uses are the published test keys of `fixtures/sccp/finality_v1.json`. It is
// pinned by reproducing fixture values byte for byte: the hash-to-field
// elements and the hashed point of the §11.2 message
// (`fixtures/sccp/bls_consensus_v1.json`) and the signatures of the fixture
// certificates.

import "@contracts/sccp-crypto"

/// Order `r` of the BLS12-381 groups G1 and G2.
const BLS_SCALAR_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

/// The base field prime `p = BLS_P_HI · 2^256 + BLS_P_LO` (381 bits).
const BLS_P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7
const BLS_P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

/// `2^256 − 1`, the largest value of one limb.
const BLS_LIMB_MAX = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

/// A 512-bit hash-to-field input is below `p · 2^BLS_REDUCE_STEPS`.
const BLS_REDUCE_STEPS = 132

/// `DST_prime = DST_SIG ‖ I2OSP(43, 1)` with `DST_SIG =
/// "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"` (§3.8), 44 bytes.
fun blsDstPrime(): slice {
    return "424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f2b".hexToSlice();
}

/// `BLS_MAP_TO_G2`: maps one `Fp2` element (96 bytes) to a point of G2 with
/// the cofactor cleared (96-byte compressed form).
// SAFETY: the opcode pops one slice and pushes one slice.
@pure
fun blsMapToG2(fieldElement: slice): slice
    asm "BLS_MAP_TO_G2"

/// Generic compressed G1 decoding and subgroup check; infinity is a group point.
// SAFETY: the opcode pops one slice and pushes one boolean.
@pure
fun blsG1InGroup(point: slice): bool
    asm "BLS_G1_INGROUP"

/// Generic compressed G2 decoding and subgroup check; infinity is a group point.
// SAFETY: the opcode pops one slice and pushes one boolean.
@pure
fun blsG2InGroup(point: slice): bool
    asm "BLS_G2_INGROUP"

/// `BLS_G2_ADD`: the sum of two G2 points in compressed form.
// SAFETY: the opcode pops two slices and pushes one slice.
@pure
fun blsG2Add(a: slice, b: slice): slice
    asm "BLS_G2_ADD"

/// `BLS_G2_MUL`: the G2 point `point` multiplied by `scalar`.
// SAFETY: the opcode pops a slice and an integer and pushes one slice.
@pure
fun blsG2Mul(point: slice, scalar: int): slice
    asm "BLS_G2_MUL"

/// The eight SHA-256 blocks `b_1 … b_8` of `expand_message_xmd(m, DST_SIG,
/// 256)` (RFC 9380 §5.3.1) for a 32-byte message, as 256-bit integers.
fun blsExpandMessage(m: slice): array<int> {
    return blsExpandMessageWithDst([m], blsDstPrime());
}

/// Test-only XMD with explicit `DST_prime` and message pieces, including the
/// upstream RFC QUUX text messages that do not use the consensus POP domain.
fun blsExpandMessageWithDst(pieces: array<slice>, dst: slice): array<int> {
    // b_0 = H(Z_pad(64) ‖ m ‖ I2OSP(256, 2) ‖ I2OSP(0, 1) ‖ DST_prime)
    var parts: array<builder> = [beginCell().storeUint(0, 256).storeUint(0, 256)];
    var piece = 0;
    repeat (pieces.size()) {
        parts.push(beginCell().storeSlice(pieces.get(piece)));
        piece += 1;
    }
    parts.push(beginCell().storeUint(256, 16).storeUint(0, 8).storeSlice(dst));
    val b0 = sha256Parts(parts);
    var blocks: array<int> = [];
    var previous = 0;
    var i = 1;
    while (i <= 8) {
        // b_i = H(strxor(b_0, b_{i−1}) ‖ I2OSP(i, 1) ‖ DST_prime), b_0 alone for i = 1
        previous = sha256Parts(
            [beginCell().storeUint(b0 ^ previous, 256).storeUint(i, 8).storeSlice(dst)],
        );
        blocks.push(previous);
        i += 1;
    }
    return blocks;
}

/// `(hi · 2^256 + lo) mod p` as the limbs `(hi', lo')` of the reduced value,
/// by shift and subtract. `hi` and `lo` are 256-bit limbs.
fun blsReduceModP(hi: int, lo: int): (int, int) {
    var vh = hi;
    var vl = lo;
    // s = p · 2^(BLS_REDUCE_STEPS − 1), halved on every step
    val shift = BLS_REDUCE_STEPS - 1;
    var sh = (BLS_P_HI << shift) | (BLS_P_LO >> (256 - shift));
    var sl = (BLS_P_LO & ((1 << (256 - shift)) - 1)) << shift;
    repeat (BLS_REDUCE_STEPS) {
        if ((vh > sh) | ((vh == sh) & (vl >= sl))) {
            var low = vl - sl;
            var borrow = 0;
            if (low < 0) {
                low = low + BLS_LIMB_MAX + 1;
                borrow = 1;
            }
            vl = low;
            vh = vh - sh - borrow;
        }
        sl = (sl >> 1) | ((sh & 1) << 255);
        sh = sh >> 1;
    }
    return (vh, vl);
}

/// One `Fp` element of `hash_to_field`: `OS2IP(b_a ‖ b_b) mod p` as 48
/// big-endian bytes in a builder.
fun blsFieldElement(high: int, low: int): builder {
    val (rh, rl) = blsReduceModP(high, low);
    return beginCell().storeUint(rh, 128).storeUint(rl, 256);
}

/// The two `Fp2` elements `u_0, u_1` of `hash_to_field(m, 2)` under `DST_SIG`,
/// each as the 96 bytes `c_0 ‖ c_1` that `BLS_MAP_TO_G2` reads: `u_0 = (e_0,
/// e_1)` and `u_1 = (e_2, e_3)` with `e_j = OS2IP(b_{2j+1} ‖ b_{2j+2}) mod p`.
fun blsHashToField(m: slice): (slice, slice) {
    return blsBlocksToField(blsExpandMessage(m));
}

/// Reduce the eight XMD blocks into two `Fp2` inputs for either test domain.
fun blsBlocksToField(b: array<int>): (slice, slice) {
    val u0 = beginCell()
        .storeBuilder(blsFieldElement(b.get(0), b.get(1)))
        .storeBuilder(blsFieldElement(b.get(2), b.get(3)))
        .endCell()
        .beginParse();
    val u1 = beginCell()
        .storeBuilder(blsFieldElement(b.get(4), b.get(5)))
        .storeBuilder(blsFieldElement(b.get(6), b.get(7)))
        .endCell()
        .beginParse();
    return (u0, u1);
}

/// `hash_to_G2(m)` under `DST_SIG` for a 32-byte message: a compressed G2
/// point of 96 bytes.
fun blsHashToG2(m: slice): slice {
    val (u0, u1) = blsHashToField(m);
    return blsG2Add(blsMapToG2(u0), blsMapToG2(u1));
}

/// `Σ secrets mod r`: the secret key of the aggregate of the given signers.
fun blsAggregateSecret(secrets: array<int>): int {
    var sum = 0;
    var i = 0;
    val count = secrets.size();
    while (i < count) {
        val (_, reduced) = divMod(sum + secrets.get(i), BLS_SCALAR_ORDER);
        sum = reduced;
        i += 1;
    }
    return sum;
}

/// The min-pk signature `sk · hash_to_G2(m)` over the 32-byte message `m`: a
/// compressed G2 point of exactly 768 bits.
fun blsSign(secret: int, m: slice): slice {
    return blsG2Mul(blsHashToG2(m), secret);
}

/// The aggregate signature of the signers with the given secret keys over
/// one message. It equals the sum of their signatures, because every signer
/// signs the same point.
fun blsAggregateSign(secrets: array<int>, m: slice): slice {
    return blsSign(blsAggregateSecret(secrets), m);
}
