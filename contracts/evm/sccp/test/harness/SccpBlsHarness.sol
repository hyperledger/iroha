// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.31;

import {BLS12_381} from "../../lib/BLS12_381.sol";

/// @title SccpBlsHarness
/// @notice Test-only entry points over the internal library `BLS12_381`, used
/// by `contracts/evm/sccp/test/sccp_bls.test.js` on EDR. It is not part of the
/// locked build and is never deployed on a real chain.
/// @dev The functions that take `dirtyWords` first fill that many words from
/// the free memory pointer on, and the scratch space, with `fill`, without
/// allocating them. Whatever the library allocates or uses as temporary memory
/// afterwards therefore starts from those bytes instead of zeros. `gasUsed` is
/// the gas of the library call alone, measured with `gasleft()` around it.
contract SccpBlsHarness {
    /// @notice The library constants: `p`, `HALF_P` (64-byte field elements),
    /// the 128-byte point `−g1` and the three input lengths.
    function constants()
        external
        pure
        returns (
            bytes memory p,
            bytes memory halfP,
            bytes memory negG1,
            uint256 g1PointLength,
            uint256 g1PairLength,
            uint256 g2PointLength,
            uint256 pairingInputLength
        )
    {
        p = abi.encodePacked(BLS12_381.P_HI, BLS12_381.P_LO);
        halfP = abi.encodePacked(BLS12_381.HALF_P_HI, BLS12_381.HALF_P_LO);
        negG1 = abi.encodePacked(
            BLS12_381.G1_X_HI, BLS12_381.G1_X_LO, BLS12_381.NEG_G1_Y_HI, BLS12_381.NEG_G1_Y_LO
        );
        g1PointLength = BLS12_381.G1_POINT_LENGTH;
        g1PairLength = BLS12_381.G1_PAIR_LENGTH;
        g2PointLength = BLS12_381.G2_POINT_LENGTH;
        pairingInputLength = BLS12_381.PAIRING_INPUT_LENGTH;
    }

    /// @notice `BLS12_381.isFieldElement`.
    function isFieldElement(uint256 hi, uint256 lo) external pure returns (bool) {
        return BLS12_381.isFieldElement(hi, lo);
    }

    /// @notice `BLS12_381.isAboveHalfP`.
    function isAboveHalfP(uint256 hi, uint256 lo) external pure returns (bool) {
        return BLS12_381.isAboveHalfP(hi, lo);
    }

    /// @notice `BLS12_381.hashToField` after the memory fill.
    function hashToField(bytes32 m, uint256 dirtyWords, bytes32 fill)
        external
        view
        returns (bytes memory u, uint256 gasUsed)
    {
        _dirty(dirtyWords, fill);
        uint256 gasBefore = gasleft();
        u = BLS12_381.hashToField(m);
        gasUsed = gasBefore - gasleft();
    }

    /// @notice `BLS12_381.hashToG2` after the memory fill.
    function hashToG2(bytes32 m, uint256 dirtyWords, bytes32 fill)
        external
        view
        returns (bytes memory q, uint256 gasUsed)
    {
        _dirty(dirtyWords, fill);
        uint256 gasBefore = gasleft();
        q = BLS12_381.hashToG2(m);
        gasUsed = gasBefore - gasleft();
    }

    /// @notice `BLS12_381.g1Add` on a memory copy of `pair`, which is returned
    /// as the call left it.
    function g1Add(bytes calldata pair) external view returns (bool ok, bytes memory result, uint256 gasUsed) {
        result = pair;
        uint256 gasBefore = gasleft();
        ok = BLS12_381.g1Add(result);
        gasUsed = gasBefore - gasleft();
    }

    /// @notice Folds `points`, one or more 128-byte G1 points, with
    /// `BLS12_381.g1Add` in one 256-byte buffer, as a certificate verifier
    /// aggregates signer keys. Returns the buffer (the sum is its first half),
    /// whether the sum is the point at infinity, and false as soon as one
    /// addition is refused.
    function g1Sum(bytes calldata points, uint256 dirtyWords, bytes32 fill)
        external
        view
        returns (bool ok, bytes memory pair, bool infinity, uint256 gasUsed)
    {
        uint256 pointLength = BLS12_381.G1_POINT_LENGTH;
        require(points.length != 0 && points.length % pointLength == 0);
        _dirty(dirtyWords, fill);
        pair = new bytes(BLS12_381.G1_PAIR_LENGTH);
        uint256 gasBefore = gasleft();
        assembly ("memory-safe") {
            calldatacopy(add(pair, 0x20), points.offset, pointLength)
        }
        ok = true;
        for (uint256 offset = pointLength; offset < points.length; offset += pointLength) {
            assembly ("memory-safe") {
                calldatacopy(add(pair, 0xa0), add(points.offset, offset), pointLength)
            }
            if (!BLS12_381.g1Add(pair)) {
                ok = false;
                break;
            }
        }
        gasUsed = gasBefore - gasleft();
        infinity = BLS12_381.g1IsInfinity(pair);
    }

    /// @notice `BLS12_381.g1IsInfinity` on a memory copy of `points`.
    function g1IsInfinity(bytes calldata points) external pure returns (bool) {
        return BLS12_381.g1IsInfinity(points);
    }

    /// @notice `BLS12_381.pairingCheck` on a memory copy of `input`, after the
    /// memory fill.
    function pairingCheck(bytes calldata input, uint256 dirtyWords, bytes32 fill)
        external
        view
        returns (bool ok, uint256 gasUsed)
    {
        _dirty(dirtyWords, fill);
        bytes memory copy = input;
        uint256 gasBefore = gasleft();
        ok = BLS12_381.pairingCheck(copy);
        gasUsed = gasBefore - gasleft();
    }

    /// @dev Writes `fill` over `words` words starting at the free memory
    /// pointer, which stays where it is, and over the scratch space.
    function _dirty(uint256 words, bytes32 fill) private pure {
        if (words == 0) return;
        assembly ("memory-safe") {
            let start := mload(0x40)
            for { let i := 0 } lt(i, words) { i := add(i, 1) } { mstore(add(start, shl(5, i)), fill) }
            mstore(0x00, fill)
            mstore(0x20, fill)
        }
    }
}
