// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.31;

/// @title BLS12_381
/// @notice BLS12-381 operations of the SCCP v1 destination over the EIP-2537
/// precompiles (`specs/sccp.md` §3.8 and §5.2.4): RFC 9380 hash-to-G2 under
/// the Sumeragi consensus signature domain `DST_SIG`, G1 addition, the
/// two-pair pairing check, and the field constants that the encoding checks
/// of §5.1.3 step 6 compare against.
/// @dev Written for this repository from RFC 9380 (§5.2 `hash_to_field`,
/// §5.3.1 `expand_message_xmd` with SHA-256, §8.8.2 suite
/// `BLS12381G2_XMD:SHA-256_SSWU_RO_`) and EIP-2537. Three rules hold for
/// every function:
/// - a precompile is called with `gas()`, never a literal stipend, and its
///   success and exact return length are checked;
/// - every byte that is hashed or handed to a precompile is written by the
///   function that uses it, `Z_pad` and the 16-byte padding of every field
///   element included, so no result depends on earlier memory contents;
/// - a field element has the EIP-2537 form, 64 bytes big-endian whose top 16
///   bytes are zero, which is the word pair `(hi, lo)` of the constants below.
/// All functions are internal: the library is inlined, never linked or
/// deployed. BSC's precompile `0x66` is not used.
library BLS12_381 {
    // ---------------------------------------------------------------------
    // Constants (§0)
    // ---------------------------------------------------------------------

    /// @notice Field modulus `p`: the upper 16 bytes of the 48-byte value.
    uint256 internal constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    /// @notice Field modulus `p`: the lower 32 bytes.
    uint256 internal constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    /// @notice `HALF_P = (p − 1) / 2`: the upper 16 bytes.
    uint256 internal constant HALF_P_HI = 0x0d0088f51cbff34d258dd3db21a5d66b;
    /// @notice `HALF_P = (p − 1) / 2`: the lower 32 bytes.
    uint256 internal constant HALF_P_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;
    /// @notice `g1.x`, the `x` of the G1 generator and of `−g1`: the upper 16 bytes.
    uint256 internal constant G1_X_HI = 0x17f1d3a73197d7942695638c4fa9ac0f;
    /// @notice `g1.x`: the lower 32 bytes.
    uint256 internal constant G1_X_LO = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    /// @notice `−g1.y = p − g1.y`: the upper 16 bytes. The four words `G1_X_HI`,
    /// `G1_X_LO`, `NEG_G1_Y_HI`, `NEG_G1_Y_LO` are the 128-byte point `−g1`.
    uint256 internal constant NEG_G1_Y_HI = 0x114d1d6855d545a8aa7d76c8cf2e21f2;
    /// @notice `−g1.y`: the lower 32 bytes.
    uint256 internal constant NEG_G1_Y_LO = 0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca;

    /// @notice Length of an EIP-2537 G1 point, `x ‖ y`.
    uint256 internal constant G1_POINT_LENGTH = 128;
    /// @notice Length of two EIP-2537 G1 points, the `G1ADD` input.
    uint256 internal constant G1_PAIR_LENGTH = 256;
    /// @notice Length of an EIP-2537 G2 point, `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`.
    uint256 internal constant G2_POINT_LENGTH = 256;
    /// @notice Length of the pairing input of §5.2.4, two (G1, G2) pairs.
    uint256 internal constant PAIRING_INPUT_LENGTH = 768;

    uint256 private constant PRECOMPILE_SHA256 = 0x02;
    uint256 private constant PRECOMPILE_MODEXP = 0x05;
    uint256 private constant PRECOMPILE_G1ADD = 0x0b;
    uint256 private constant PRECOMPILE_G2ADD = 0x0d;
    uint256 private constant PRECOMPILE_PAIRING_CHECK = 0x0f;
    uint256 private constant PRECOMPILE_MAP_FP2_TO_G2 = 0x11;

    /// @dev `DST_prime = DST_SIG ‖ I2OSP(43, 1)`, 44 bytes: its first 32 bytes.
    bytes32 private constant DST_PRIME_HEAD = "BLS_SIG_BLS12381G2_XMD:SHA-256_S";
    /// @dev The last 12 bytes of `DST_prime`, `"SWU_RO_POP_" ‖ 0x2b`, left-aligned.
    bytes32 private constant DST_PRIME_TAIL = 0x5357555f524f5f504f505f2b0000000000000000000000000000000000000000;

    // ---------------------------------------------------------------------
    // Field comparisons (§5.1.3 step 6)
    // ---------------------------------------------------------------------

    /// @notice True iff the 48-byte value `hi ‖ lo` is a canonical field
    /// element, that is below `p`. `hi` holds the upper 16 bytes; a `hi` of
    /// `2^128` or more is not below `p`.
    function isFieldElement(uint256 hi, uint256 lo) internal pure returns (bool) {
        return hi < P_HI || (hi == P_HI && lo < P_LO);
    }

    /// @notice True iff the 48-byte value `hi ‖ lo` is above `HALF_P`, which is
    /// the ZCash sign bit of a `y` coordinate (§0).
    function isAboveHalfP(uint256 hi, uint256 lo) internal pure returns (bool) {
        return hi > HALF_P_HI || (hi == HALF_P_HI && lo > HALF_P_LO);
    }

    // ---------------------------------------------------------------------
    // Hash to G2 (§3.8 step 8)
    // ---------------------------------------------------------------------

    /// @notice RFC 9380 `hash_to_field(m, 2)` over Fp2 with
    /// `expand_message_xmd(m, DST_SIG, 256)` and SHA-256. Returns 256 bytes,
    /// `u0.c0 ‖ u0.c1 ‖ u1.c0 ‖ u1.c1`: each half is one `MAP_FP2_TO_G2` input.
    /// @dev Reverts with empty data when a precompile call fails or returns
    /// another length. Every input is well formed, so that happens only when
    /// gas runs out or on a chain that lacks the precompile.
    function hashToField(bytes32 m) internal view returns (bytes memory u) {
        assembly ("memory-safe") {
            // `u` is allocated; everything else is temporary memory above the
            // free memory pointer, at these offsets from `s`:
            //   0x000  msg_prime, 143 bytes:
            //          Z_pad(64) ‖ m(32) ‖ l_i_b_str(2) ‖ I2OSP(0, 1) ‖ DST_prime(44)
            //   0x0c0  block input, 77 bytes:
            //          b_0 or (b_0 xor b_(i−1)) (32) ‖ I2OSP(i, 1) ‖ DST_prime(44)
            //   0x140  uniform_bytes, 256 bytes: b_1 ‖ … ‖ b_8
            //   0x240  MODEXP input, 225 bytes:
            //          lengths(96) ‖ base(64) ‖ exponent(1) ‖ modulus(64)
            u := mload(0x40)
            mstore(u, 0x100)
            let s := add(u, 0x120)
            mstore(0x40, s)

            // b_0 = SHA-256(msg_prime), written where the first block input reads it.
            mstore(s, 0) // Z_pad: one SHA-256 block of zero bytes
            mstore(add(s, 0x20), 0)
            mstore(add(s, 0x40), m)
            mstore(add(s, 0x60), shl(240, 0x0100)) // l_i_b_str = I2OSP(256, 2), then I2OSP(0, 1)
            mstore(add(s, 0x63), DST_PRIME_HEAD)
            mstore(add(s, 0x83), DST_PRIME_TAIL)
            let blockInput := add(s, 0xc0)
            let ok := staticcall(gas(), PRECOMPILE_SHA256, s, 143, blockInput, 0x20)
            if iszero(and(ok, eq(returndatasize(), 0x20))) { revert(0, 0) }
            let b0 := mload(blockInput)
            mstore(add(blockInput, 0x21), DST_PRIME_HEAD)
            mstore(add(blockInput, 0x41), DST_PRIME_TAIL)

            // b_1 = SHA-256(b_0 ‖ I2OSP(1, 1) ‖ DST_prime) and, for i = 2..8,
            // b_i = SHA-256((b_0 xor b_(i−1)) ‖ I2OSP(i, 1) ‖ DST_prime).
            let uniform := add(s, 0x140)
            for { let i := 1 } lt(i, 9) { i := add(i, 1) } {
                mstore8(add(blockInput, 0x20), i)
                let b := add(uniform, shl(5, sub(i, 1)))
                ok := staticcall(gas(), PRECOMPILE_SHA256, blockInput, 77, b, 0x20)
                if iszero(and(ok, eq(returndatasize(), 0x20))) { revert(0, 0) }
                mstore(blockInput, xor(b0, mload(b)))
            }

            // The k-th element is OS2IP(uniform_bytes[64k .. 64k + 64]) mod p,
            // computed by MODEXP with exponent 1. Its 64-byte result is below
            // `p`, so the top 16 bytes of every element are zero.
            let modexp := add(s, 0x240)
            mstore(modexp, 0x40) // length of the base
            mstore(add(modexp, 0x20), 1) // length of the exponent
            mstore(add(modexp, 0x40), 0x40) // length of the modulus
            mstore8(add(modexp, 0xa0), 1) // exponent
            mstore(add(modexp, 0xa1), P_HI) // modulus: 16 zero bytes, then `p`
            mstore(add(modexp, 0xc1), P_LO)
            let elements := add(u, 0x20)
            for { let k := 0 } lt(k, 0x100) { k := add(k, 0x40) } {
                mcopy(add(modexp, 0x60), add(uniform, k), 0x40)
                ok := staticcall(gas(), PRECOMPILE_MODEXP, modexp, 225, add(elements, k), 0x40)
                if iszero(and(ok, eq(returndatasize(), 0x40))) { revert(0, 0) }
            }
        }
    }

    /// @notice RFC 9380 `hash_to_curve` of the 32-byte message `m` to G2 under
    /// `DST_SIG` (§3.8 step 8): `MAP_FP2_TO_G2(u0) + MAP_FP2_TO_G2(u1)`, where
    /// the precompile includes the isogeny and the cofactor clearing. Returns
    /// the 256-byte EIP-2537 point, which is in the G2 subgroup.
    /// @dev Reverts with empty data in the same cases as `hashToField`.
    function hashToG2(bytes32 m) internal view returns (bytes memory q) {
        bytes memory u = hashToField(m);
        assembly ("memory-safe") {
            // The first mapped point and then the sum occupy the result; the
            // second mapped point sits in temporary memory right after it, so
            // that both are the contiguous 512-byte `G2ADD` input.
            q := mload(0x40)
            mstore(q, 0x100)
            let point := add(q, 0x20)
            mstore(0x40, add(point, 0x100))
            let ok := staticcall(gas(), PRECOMPILE_MAP_FP2_TO_G2, add(u, 0x20), 0x80, point, 0x100)
            if iszero(and(ok, eq(returndatasize(), 0x100))) { revert(0, 0) }
            ok := staticcall(gas(), PRECOMPILE_MAP_FP2_TO_G2, add(u, 0xa0), 0x80, add(point, 0x100), 0x100)
            if iszero(and(ok, eq(returndatasize(), 0x100))) { revert(0, 0) }
            ok := staticcall(gas(), PRECOMPILE_G2ADD, point, 0x200, point, 0x100)
            if iszero(and(ok, eq(returndatasize(), 0x100))) { revert(0, 0) }
        }
    }

    // ---------------------------------------------------------------------
    // G1 addition and the pairing check (§3.8 steps 7 and 9)
    // ---------------------------------------------------------------------

    /// @notice `G1ADD` over `pair`, the two points `A ‖ B` (256 bytes). On
    /// success `A + B` replaces `A` and `B` is kept. Returns false, with `pair`
    /// unchanged, when the call fails or returns another length. The
    /// precompile refuses a coordinate that is not below `p` and a point off
    /// the curve, and a refusal consumes all gas forwarded to it, so callers
    /// check the coordinates first (§5.2.4). `G1ADD` makes no subgroup check,
    /// and it reads 128 zero bytes as the point at infinity.
    function g1Add(bytes memory pair) internal view returns (bool ok) {
        assert(pair.length == G1_PAIR_LENGTH);
        assembly ("memory-safe") {
            let points := add(pair, 0x20)
            ok := staticcall(gas(), PRECOMPILE_G1ADD, points, 0x100, points, 0x80)
            ok := and(ok, eq(returndatasize(), 0x80))
        }
    }

    /// @notice True iff the first G1 point of `points` is the EIP-2537 point at
    /// infinity, 128 zero bytes.
    function g1IsInfinity(bytes memory points) internal pure returns (bool infinity) {
        assert(points.length >= G1_POINT_LENGTH);
        assembly ("memory-safe") {
            infinity := iszero(
                or(
                    or(mload(add(points, 0x20)), mload(add(points, 0x40))),
                    or(mload(add(points, 0x60)), mload(add(points, 0x80)))
                )
            )
        }
    }

    /// @notice `PAIRING_CHECK` over exactly two pairs, `input = P1 ‖ Q1 ‖ P2 ‖
    /// Q2` (768 bytes; §5.2.4 lays it out as `apk ‖ Q ‖ (−g1) ‖ σ`). True iff
    /// the call succeeds and returns exactly the 32-byte value 1, that is
    /// `e(P1, Q1) · e(P2, Q2) = 1`. False when the pairing product differs,
    /// when the call returns another length, and when the precompile refuses
    /// the input: a coordinate that is not below `p`, a point off its curve or
    /// outside its subgroup. A refusal consumes all gas forwarded to it.
    /// @dev The precompile accepts the point at infinity in either group, so
    /// `e(O, Q) · e(−g1, O) = 1` holds for every `Q`: callers reject `apk = O`
    /// and `σ = O` themselves (§5.1.3 steps 6 and 10).
    function pairingCheck(bytes memory input) internal view returns (bool ok) {
        assert(input.length == PAIRING_INPUT_LENGTH);
        assembly ("memory-safe") {
            // The result word is written to the scratch space. Its value counts
            // only when the call succeeded and returned exactly 32 bytes, so
            // nothing that the scratch space held before can pass.
            ok := staticcall(gas(), PRECOMPILE_PAIRING_CHECK, add(input, 0x20), 0x300, 0x00, 0x20)
            ok := and(ok, and(eq(returndatasize(), 0x20), eq(mload(0x00), 1)))
        }
    }
}
