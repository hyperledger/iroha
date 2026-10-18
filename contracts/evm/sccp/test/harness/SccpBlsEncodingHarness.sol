// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.31;

import {SccpTairaXor} from "../../SccpTairaXor.sol";

/// @title SccpBlsEncodingHarness
/// @notice Test-only entry point to the production step-6 encoding checks.
/// @dev The BLS suite changes only `_checkEncodings` visibility to internal
/// in its compiler input. The deployed production artifact is unchanged.
contract SccpBlsEncodingHarness is SccpTairaXor {
    /// @notice Forwards the production constructor arguments unchanged.
    constructor(
        bytes32 networkId, bytes32 instance, uint8 tag, uint32 revision, uint256 cap,
        uint64 generation, bytes32 committeeRoot, uint64 startHeight, uint64 untilMs
    ) SccpTairaXor(networkId, instance, tag, revision, cap, generation, committeeRoot, startHeight, untilMs) {}

    /// @notice Checks one signer's encoding and the affine signature limbs.
    /// @dev Sizes normally established before step 6 are fixed here. This
    /// entry point does not claim to validate a complete commit certificate.
    function checkEncodings(TairaCertificateV1 calldata certificate) external pure {
        require(certificate.committee.length == 48 && certificate.signerYs.length == 48);
        require(certificate.signature.length == 192);
        _checkEncodings(certificate, 1);
    }
}
