// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.31;

import {SccpTairaXor} from "../../SccpTairaXor.sol";

/// @title SccpDirtyMemoryHarness
/// @notice Test-only `SccpTairaXor` whose `dirty*` entry points run the four
/// entry-point bodies that verify a certificate on memory that is not zero
/// (`specs/sccp.md` §11.4 item 3), used on EDR by
/// `contracts/evm/sccp/test/sccp_v1_fixtures.test.js` for the shared fixtures
/// and by `contracts/evm/sccp/test/sccp_taira_xor.test.js` for committees of 4,
/// 7 and 31 keys with batches of 16 certificates. It is not part of the locked
/// build and is never deployed on a real chain.
/// @dev Each `dirty*` function first writes `fill` over the scratch space and
/// over `dirtyWords` words from the free memory pointer on, without allocating
/// them, and then enters the internal body of the production entry point.
/// Whatever verification allocates or uses as temporary memory therefore
/// starts from those bytes instead of zeros, so an outcome that depended on
/// fresh memory would differ from the production entry point's. Every other
/// function, the storage layout and the nine immutables are inherited
/// unchanged.
contract SccpDirtyMemoryHarness is SccpTairaXor {
    /// @notice Forwards the nine §5.2.1 constructor arguments unchanged.
    constructor(
        bytes32 tairaNetworkId_,
        bytes32 consensusInstance_,
        uint8 networkTag_,
        uint32 routeRevision_,
        uint256 maxWrappedSupply_,
        uint64 initialGeneration_,
        bytes32 initialCommitteeRoot_,
        uint64 initialStartHeight_,
        uint64 initialUntilMs_
    )
        SccpTairaXor(
            tairaNetworkId_,
            consensusInstance_,
            networkTag_,
            routeRevision_,
            maxWrappedSupply_,
            initialGeneration_,
            initialCommitteeRoot_,
            initialStartHeight_,
            initialUntilMs_
        )
    {}

    /// @notice `submitCheckpoints` after the memory fill.
    function dirtySubmitCheckpoints(TairaCertificateV1[] calldata certificates, uint256 dirtyWords, bytes32 fill)
        external
    {
        _dirty(dirtyWords, fill);
        _submitCheckpoints(certificates);
    }

    /// @notice `finalizeFromTaira` after the memory fill.
    function dirtyFinalizeFromTaira(
        TairaCertificateV1 calldata certificate,
        MessageProofV1 calldata proof,
        uint256 dirtyWords,
        bytes32 fill
    ) external returns (bytes32) {
        _dirty(dirtyWords, fill);
        return _finalizeFromTaira(certificate, proof);
    }

    /// @notice `applyControl` after the memory fill.
    function dirtyApplyControl(
        TairaCertificateV1 calldata certificate,
        ControlProofV1 calldata control,
        uint256 dirtyWords,
        bytes32 fill
    ) external {
        _dirty(dirtyWords, fill);
        _applyControl(certificate, control);
    }

    /// @notice `voidExpired` after the memory fill.
    function dirtyVoidExpired(
        uint64 nonce,
        TairaCertificateV1 calldata certificate,
        MessageProofV1 calldata proof,
        uint256 dirtyWords,
        bytes32 fill
    ) external {
        _dirty(dirtyWords, fill);
        _voidExpired(nonce, certificate, proof);
    }

    /// @dev Writes `fill` over `words` words starting at the free memory
    /// pointer, which stays where it is, and over the scratch space.
    function _dirty(uint256 words, bytes32 fill) private pure {
        assembly ("memory-safe") {
            let start := mload(0x40)
            for { let i := 0 } lt(i, words) { i := add(i, 1) } { mstore(add(start, shl(5, i)), fill) }
            mstore(0x00, fill)
            mstore(0x20, fill)
        }
    }
}
