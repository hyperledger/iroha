// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.31;

import {SccpTairaXor} from "../../SccpTairaXor.sol";

/// @title SccpFixtureHarness
/// @notice Test-only access to the production payload, tree and history routines.
/// @dev The fixture suite compiles this against a visibility-only source override:
/// selected private helpers become internal, with their bodies unchanged. Neither
/// this harness nor that override is part of the locked deployable artifact.
contract SccpFixtureHarness is SccpTairaXor {
    /// @notice Forwards the production constructor arguments unchanged.
    constructor(
        bytes32 networkId, bytes32 instance, uint8 tag, uint32 revision, uint256 cap,
        uint64 generation, bytes32 committeeRoot, uint64 startHeight, uint64 untilMs
    ) SccpTairaXor(networkId, instance, tag, revision, cap, generation, committeeRoot, startHeight, untilMs) {}

    /// @notice Decodes the destination's outbound payload and computes its message id.
    function fixtureOutbound(bytes calldata payload)
        external view returns (uint64 nonce, uint256 deadlineMs, uint256 amount, address recipient, bytes32 messageId)
    {
        (nonce, deadlineMs, amount, recipient) = _parseOutboundPayload(payload);
        messageId = _outboundMessageId(payload);
    }

    /// @notice Builds the caller's inbound payload and computes its message id.
    function fixtureInbound(uint64 nonce, uint256 amount, bytes calldata recipient)
        external view returns (bytes memory payload, bytes32 messageId)
    {
        payload = _inboundPayload(nonce, amount, recipient);
        messageId = _inboundMessageId(payload);
    }

    /// @notice Computes the production positional promote-odd root.
    function fixtureRoot(bytes32 leaf, uint256 index, uint256 count, bytes32[] calldata path)
        external pure returns (bytes32)
    {
        return _merkleRoot(leaf, index, count, path);
    }

    /// @notice Checks inclusion, including the exact count, position and sibling bounds.
    function fixtureCheckLeaf(bytes32 leaf, uint256 index, uint256 count, bytes32[] calldata path, bytes32 root)
        external pure
    {
        _checkLeaf(leaf, index, count, path, root);
    }

    /// @notice Checks a recorded older block against a supplied history commitment.
    function fixtureHistory(uint64 size, bytes32 root, BlockRefV1 calldata blockRef)
        external pure returns (bytes32, uint256)
    {
        FinalityHeader memory x;
        x.height = type(uint64).max;
        x.historySize = size;
        x.historyRoot = root;
        return _checkBlockRef(x, blockRef);
    }

    /// @notice Computes the three domain-separated production leaf/node forms.
    function fixtureLeaves(bytes32 messageId, ControlProofV1 calldata control, bytes32 left, bytes32 right)
        external view returns (bytes32, bytes32, bytes32)
    {
        return (_transferLeaf(messageId), _controlLeaf(control, control.parliamentPaused), _node(left, right));
    }

    /// @notice Emits the inherited event for an encoding-only arbitrary-id golden.
    /// @dev The fixture's expired id has no payload preimage. The suite separately
    /// exercises public voidExpired with a real certified payload on both networks.
    function fixtureVoidEvent(bytes32 messageId, uint64 nonce) external {
        emit SccpVoided(messageId, nonce);
    }

    /// @notice Derives the exact message whose signature a destination checks.
    /// @dev Evidence classification and its Blake2b id belong to Taira. The test
    /// runner binds each evidence id to this production-computed Commit digest.
    function fixtureCommitMessage(bytes calldata qc, bytes calldata header) external view returns (bytes32) {
        require(qc.length == 116 && header.length == 221);
        return _commitMessage(qc, header);
    }
}
