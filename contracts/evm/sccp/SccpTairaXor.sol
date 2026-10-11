// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.31;

import {BLS12_381} from "./lib/BLS12_381.sol";

/// @title SccpTairaXor
/// @notice SCCP v1 destination for Taira XOR on Ethereum and BSC
/// (`specs/sccp.md` §5.1 and §5.2). The contract is the ERC-20/BEP-20 token
/// itself with the bridge built in. It has no owner, guardian, admin key,
/// setter or upgrade path, and it calls nothing but precompiles.
/// Taira-to-destination messages are authorized by Taira's Sumeragi commit
/// certificates: one BLS12-381 aggregate signature of exactly `q = n − f`
/// validators of the current committee generation over the finality header
/// `X` of a Taira block, verified through the EIP-2537 precompiles. The pause
/// state changes only through control leaves of certified Taira blocks.
/// @dev Compiled by solc 0.8.31 with the legacy pipeline and
/// `evmVersion: cancun` (§5.5). The source avoids the 0.8.31 legacy-pipeline
/// bug patterns: it never deletes memory `bytes` elements and declares no
/// custom storage layout.
contract SccpTairaXor {
    // ---------------------------------------------------------------------
    // ABI structures (§5.2.2)
    // ---------------------------------------------------------------------

    /// @notice A Taira commit certificate in its EVM form (§3.7): `qc` is the 116-byte
    /// `QC_FIXED`, `header` the 221-byte finality header `X`, `signature` the aggregate signature
    /// as the four 48-byte limbs `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`, `committee` the `n` compressed
    /// 48-byte keys of the current generation in canonical order, and `signerYs` the 48-byte `y`
    /// of every signer in ascending signer index.
    struct TairaCertificateV1 {
        bytes qc;
        bytes header;
        bytes signature;
        bytes committee;
        bytes signerYs;
    }

    /// @notice A stored checkpoint, named by its finality header `X` (§5.1.3).
    struct CheckpointRefV1 {
        bytes header;
    }

    /// @notice The Taira block that carries a leaf: the certified block itself, or an older
    /// SCCP-bearing block proven against the certified history root (§5.1.5).
    struct BlockRefV1 {
        uint64 height;
        bytes32 sccpRoot;
        uint32 messageCount;
        uint64 historyIndex;
        bytes32[] historyPath;
    }

    /// @notice Transfer payload with its position in the block commitment tree (§3.4).
    struct MessageProofV1 {
        bytes payload;
        uint32 leafIndex;
        bytes32[] path;
        BlockRefV1 block;
    }

    /// @notice Control leaf fields with the leaf's position in the block commitment tree (§5.1.6).
    struct ControlProofV1 {
        uint64 controlNonce;
        uint8 track;
        bool parliamentPaused;
        uint64 fastPauseUntilMs;
        bytes32 certificateId;
        bytes32 effectHash;
        uint32 leafIndex;
        bytes32[] path;
        BlockRefV1 block;
    }

    /// @dev A finality header `X` (§3.6) that passed X1–X7 with `ACTIVE` set. `id` is
    /// `keccak256(X)`, filled in by the caller of `_parseHeader`.
    struct FinalityHeader {
        bytes32 networkId;
        uint64 height;
        uint64 timestampMs;
        bool rotation;
        uint32 messageCount;
        bytes32 sccpRoot;
        uint64 historySize;
        bytes32 historyRoot;
        uint64 generation;
        bytes32 committeeRoot;
        uint64 validityMs;
        bytes32 nextCommitteeRoot;
        bytes32 id;
    }

    // ---------------------------------------------------------------------
    // Events and errors (§5.2.2)
    // ---------------------------------------------------------------------

    /// @notice ERC-20 transfer; mints come from and burns go to the zero address.
    event Transfer(address indexed from, address indexed to, uint256 value);
    /// @notice ERC-20 allowance change.
    event Approval(address indexed owner, address indexed spender, uint256 value);
    /// @notice Inbound source event consumed by Taira (§4.12.2).
    event SccpTransferToTaira(bytes32 indexed messageId, address indexed sender, uint64 nonce, bytes payload);
    /// @notice A Taira transfer minted on this destination.
    event SccpFinalized(bytes32 indexed messageId, uint64 indexed nonce, address indexed recipient, uint256 tokenAmount);
    /// @notice A Taira transfer nonce voided without minting; `messageId` is zero for `voidFrozen`.
    event SccpVoided(bytes32 indexed messageId, uint64 indexed nonce);
    /// @notice A rotation installed committee generation `generation`.
    event SccpCommitteeRotated(uint64 indexed generation, bytes32 root, uint64 untilMs, uint64 startHeight);
    /// @notice A checkpoint was stored for `height`; `header` is `keccak256(X)`.
    event SccpCheckpointed(uint64 indexed height, bytes32 header);
    /// @notice The current generation signed a conflict and the destination latched (§5.1.2).
    /// `reason` 1: two headers at one height (`a` the stored id, `b` the new one); 2: a height
    /// below the generation's start; 3: a rotation below a certified height (for 2 and 3, `a` is
    /// `X.committee_root` and `b` is `keccak256(X)`).
    event SccpLatched(uint8 indexed reason, uint64 generation, uint64 height, bytes32 a, bytes32 b);
    /// @notice A control leaf was applied; `fastPauseUntilMs` is the stored, clamped expiry.
    event SccpControlApplied(
        uint64 indexed controlNonce, uint8 track, bool parliamentPaused, uint64 fastPauseUntilMs, bytes32 certificateId
    );
    /// @notice A certificate whose signature this call verified (§5.1.3 step 12); `signature` is
    /// the 192-byte calldata form.
    event SccpCertificate(uint64 indexed height, uint64 indexed generation, bytes qc, bytes header, bytes signature);

    /// @notice The chain is not this deployment's, or the constructor's network tag is unknown.
    error WrongChain();
    /// @notice Finalization is refused while the effective pause holds.
    error MintingIsPaused();
    /// @notice The certificate is not of the current generation, the destination has expired, or
    /// a stored checkpoint is neither of the current generation nor the handoff that installed it.
    error CommitteeNotAccepted();
    /// @notice The committee length or root, a signer key's encoding or the aggregate key is invalid.
    error BadCommittee();
    /// @notice `QC_FIXED`, the signature length, `signerYs` or the signer set is malformed.
    error BadCertificate();
    /// @notice The aggregate signature is the identity, is not a point of the G2 subgroup, or
    /// does not verify.
    error BadSignature();
    /// @notice `X` is not 221 bytes, violates X1–X7, is inactive or names another network.
    error BadHeader();
    /// @notice A block reference, a Merkle path or a history path does not verify.
    error BadProof();
    /// @notice The transfer payload violates §3.2 for this destination.
    error BadPayload();
    /// @notice The outbound nonce is already consumed by a mint or a void.
    error AlreadyConsumed(uint64 nonce);
    /// @notice The mint would exceed the immutable supply cap.
    error SupplyCapExceeded();
    /// @notice No stored checkpoint is `keccak256(X)` at `X.height`.
    error UnknownCheckpoint();
    /// @notice The payload recipient is the zero address or this contract.
    error BadRecipient();
    /// @notice An amount or a `voidFrozen` range is outside its admitted range.
    error BadAmount();
    /// @notice The supplied nonce differs from the expected one, or the sender's source nonces
    /// are exhausted (`expected` is then 2^64 − 1, which no burn uses).
    error BadNonce(uint64 expected);
    /// @notice The calldata of `transferToTaira` or `voidFrozen` is not the canonical ABI
    /// encoding that Taira decodes (§5.1.7, §5.1.8, §5.2.2).
    error NonCanonicalCalldata();
    /// @notice The mint deadline of the message has passed.
    error DeadlinePassed();
    /// @notice The mint deadline of the message has not passed yet.
    error DeadlineNotReached();
    /// @notice The destination is `Live`: neither expired nor latched.
    error NotFrozen();
    /// @notice The control nonce is not above the last applied control nonce.
    error StaleControl();
    /// @notice The control fields violate the §3.4 constraints.
    error BadControl();
    /// @notice `submitCheckpoints` got no certificate or changed no state.
    error NothingToDo();
    /// @notice A constructor argument is outside its §5.2.1 bound.
    error BadConfig();
    /// @notice The destination is latched.
    error Equivocated();
    /// @notice An inline certificate shows a conflict; only `submitCheckpoints` latches.
    error LatchRequired();
    /// @notice More than 16 certificates in one `submitCheckpoints` call.
    error TooManyCertificates();
    /// @notice ERC-6093: the sender balance is below the requested amount.
    error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);
    /// @notice ERC-6093: the allowance is below the requested amount.
    error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);
    /// @notice ERC-6093: the token sender is the zero address.
    error ERC20InvalidSender(address sender);
    /// @notice ERC-6093: the token receiver is the zero address or this contract.
    error ERC20InvalidReceiver(address receiver);
    /// @notice ERC-6093: the approved spender is the zero address.
    error ERC20InvalidSpender(address spender);

    // ---------------------------------------------------------------------
    // Constants (§2, §3.2 - §3.9, §5.1.1)
    // ---------------------------------------------------------------------

    uint64 private constant MAX_VALIDITY_MS = 2_592_000_000;
    uint64 private constant MAX_FAST_PAUSE_MS = 2_592_000_000;
    uint64 private constant MAX_INIT_SLACK_MS = 3_600_000;
    /// @dev The last `block.timestamp` whose milliseconds fit `u64`.
    uint256 private constant MAX_CLOCK_SECONDS = type(uint64).max / 1000;

    uint8 private constant TAG_TAIRA = 0x40;
    uint8 private constant TAG_ETHEREUM = 0x41;
    uint8 private constant TAG_BSC = 0x42;

    uint256 private constant X_BYTES = 221;
    uint256 private constant X_MAGIC = 0x534343502f46494e414c4954592f5631; // "SCCP/FINALITY/V1"
    uint256 private constant X_FLAG_ACTIVE = 0x01;
    uint256 private constant X_FLAG_ROTATION = 0x02;
    uint256 private constant X_FLAGS_RESERVED = 0xfc;
    uint256 private constant QC_FIXED_BYTES = 116;
    uint256 private constant SIGNATURE_BYTES = 192;
    /// @dev A field element, a compressed G1 key and a signature limb are 48 bytes each.
    uint256 private constant FIELD_BYTES = 48;
    uint256 private constant MIN_COMMITTEE = 4;
    uint256 private constant MAX_COMMITTEE = 31;
    uint256 private constant MAX_CERTIFICATES_PER_CALL = 16;
    /// @dev The upper 16 bytes of a compressed key without its three flag bits: `byte0 & 0x1f`.
    uint256 private constant KEY_X_HI_MASK = 0x1fffffffffffffffffffffffffffffff;
    uint256 private constant PRECOMPILE_SHA256 = 0x02;

    uint8 private constant LATCH_TWO_HEADERS = 1;
    uint8 private constant LATCH_BELOW_START = 2;
    uint8 private constant LATCH_ROTATION_BELOW_HIGH = 3;

    uint256 private constant MAX_BLOCK_LEAVES = 512;
    uint256 private constant MAX_BLOCK_PATH = 9;
    uint256 private constant MAX_HISTORY_PATH = 32;
    uint256 private constant MAX_HISTORY_SIZE = 1 << 32;
    uint256 private constant TRACK_PARLIAMENT = 1;
    uint256 private constant TRACK_FAST_PAUSE = 2;
    uint256 private constant MAX_VOID_FROZEN_RANGE = 256;
    uint256 private constant VOID_FROZEN_CALLDATA_BYTES = 0x44; // 4 + 2 * 0x20
    uint256 private constant MAX_TAIRA_ACCOUNT_BYTES = 1024;
    uint256 private constant MAX_PAYLOAD_BYTES = 4096;
    uint256 private constant MIN_PAYLOAD_BYTES = 59;
    uint256 private constant PAYLOAD_KIND_TRANSFER = 0x02;
    uint256 private constant PAYLOAD_VERSION = 0x01;
    uint256 private constant CODEC_CANONICAL_TEXT = 1;
    uint256 private constant CODEC_EVM_ADDRESS20 = 2;
    uint256 private constant CODEC_TAIRA_ACCOUNT = 3;
    uint256 private constant EVM_ADDRESS_BYTES = 20;
    uint256 private constant ASSET_ID_XOR = 0x786f72; // "xor"
    uint256 private constant CANONICAL_TRANSFER_HEAD = 0x84; // 4 + 0x80

    // ---------------------------------------------------------------------
    // Storage (§5.2.3). Declaration order fixes the slots, and within a packed
    // slot the first-declared field is the low-order one.
    // ---------------------------------------------------------------------

    // Slot A: the committee root of the current generation `cur`.
    bytes32 private curRoot;
    // Slot B: `cur.untilMs`, `cur.start`, `cur.high`, `cur.generation`.
    uint64 private curUntilMs;
    uint64 private curStart;
    uint64 private curHigh;
    uint64 private curGeneration;
    // Slot C: the pause state, the operation counter and the latch.
    /// @notice Nonce of the last applied control, 0 initially.
    uint64 public controlNonce;
    /// @notice Monotone count of finalizations, voids, burns and applied controls (not
    /// checkpoints or rotations). It saturates at 2^64 − 1.
    uint64 public opCount;
    uint64 private appliedFastPauseUntilMs;
    bool private appliedParliamentPaused;
    /// @notice The latch: the current generation signed a conflict. It never clears.
    bool public equivocated;
    /// @notice `keccak256(X)` of the checkpoint stored for a Taira height, or zero.
    mapping(uint64 => bytes32) public checkpointHeader;
    mapping(uint256 => uint256) private consumedBitmap; // word = nonce >> 8, bit = nonce & 255
    /// @notice Next outbound source nonce per burning sender, in 0 ..= 2^64 − 2. The value
    /// 2^64 − 1 means the sender's nonces are exhausted (§5.1.7).
    mapping(address => uint64) public transferNonces;
    /// @notice ERC-20 total supply in Taira units (9 decimals).
    uint256 public totalSupply;
    /// @notice ERC-20 balances.
    mapping(address => uint256) public balanceOf;
    /// @notice ERC-20 allowances.
    mapping(address => mapping(address => uint256)) public allowance;

    bytes32 private immutable TAIRA_NETWORK_ID;
    bytes32 private immutable CONSENSUS_INSTANCE;
    uint8 private immutable NETWORK_TAG;
    uint32 private immutable ROUTE_REVISION;
    uint256 private immutable MAX_WRAPPED_SUPPLY;
    uint64 private immutable INITIAL_GENERATION;
    bytes32 private immutable INITIAL_COMMITTEE_ROOT;
    uint64 private immutable INITIAL_START_HEIGHT;
    uint64 private immutable INITIAL_UNTIL_MS;

    // ---------------------------------------------------------------------
    // Constructor (§5.2.1)
    // ---------------------------------------------------------------------

    /// @param tairaNetworkId_ Taira `NetworkId` (nonzero), the `network_id` of every accepted `X`.
    /// @param consensusInstance_ Taira's Sumeragi instance id `I` (nonzero), bound into every
    /// signed commit preimage.
    /// @param networkTag_ Own profile tag: 0x41 Ethereum, 0x42 BSC.
    /// @param routeRevision_ Registered route revision bound into every payload (nonzero).
    /// @param maxWrappedSupply_ Immutable supply cap in Taira units (nonzero, below 2^128).
    /// @param initialGeneration_ Pinned committee generation (at least 1).
    /// @param initialCommitteeRoot_ Committee root of the pinned generation (nonzero).
    /// @param initialStartHeight_ First Taira height of the pinned generation (at least 1).
    /// @param initialUntilMs_ Trust deadline of the pinned generation: after the deployment time
    /// and at most `MAX_VALIDITY_MS + MAX_INIT_SLACK_MS` after it.
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
    ) {
        if (networkTag_ != TAG_ETHEREUM && networkTag_ != TAG_BSC) revert WrongChain();
        if (block.chainid != _identityWordOf(networkTag_)) revert WrongChain();
        uint256 nowMs = _nowMs();
        // The upper bound on `initialUntilMs_` is compared as a difference, after the lower
        // bound, so that its sum is never formed (§5.1.2 "Arithmetic").
        if (
            tairaNetworkId_ == bytes32(0) || consensusInstance_ == bytes32(0) || routeRevision_ == 0
                || maxWrappedSupply_ == 0 || maxWrappedSupply_ >> 128 != 0 || initialGeneration_ == 0
                || initialCommitteeRoot_ == bytes32(0) || initialStartHeight_ == 0 || initialUntilMs_ <= nowMs
                || initialUntilMs_ - nowMs > MAX_VALIDITY_MS + MAX_INIT_SLACK_MS
        ) revert BadConfig();

        TAIRA_NETWORK_ID = tairaNetworkId_;
        CONSENSUS_INSTANCE = consensusInstance_;
        NETWORK_TAG = networkTag_;
        ROUTE_REVISION = routeRevision_;
        MAX_WRAPPED_SUPPLY = maxWrappedSupply_;
        INITIAL_GENERATION = initialGeneration_;
        INITIAL_COMMITTEE_ROOT = initialCommitteeRoot_;
        INITIAL_START_HEIGHT = initialStartHeight_;
        INITIAL_UNTIL_MS = initialUntilMs_;

        curRoot = initialCommitteeRoot_;
        curUntilMs = initialUntilMs_;
        curStart = initialStartHeight_;
        curHigh = initialStartHeight_ - 1;
        curGeneration = initialGeneration_;
    }

    // ---------------------------------------------------------------------
    // Checkpoints and rotations (§5.1.2, §5.1.3)
    // ---------------------------------------------------------------------

    /// @notice Verifies up to 16 certificates of the current committee generation in order. Each
    /// stores its checkpoint and raises `high`, and a rotation installs the successor generation;
    /// a conflict signed by the current generation latches the destination instead.
    /// @dev Permissionless, open while paused and not counted in `opCount`. A latch, and a
    /// rotation that leaves the destination not `Live`, persist and end the batch without
    /// reverting. Any other failure reverts the whole batch, and so does a call that changes no
    /// state (`NothingToDo`).
    function submitCheckpoints(TairaCertificateV1[] calldata certificates) external {
        _submitCheckpoints(certificates);
    }

    // ---------------------------------------------------------------------
    // Taira -> destination (§5.1.5)
    // ---------------------------------------------------------------------

    /// @notice Mints a Taira transfer proven under a certificate of the current generation, which
    /// also stores the certificate's checkpoint and raises `high`.
    function finalizeFromTaira(TairaCertificateV1 calldata certificate, MessageProofV1 calldata proof)
        external
        returns (bytes32)
    {
        return _finalizeFromTaira(certificate, proof);
    }

    /// @notice Mints a Taira transfer proven under a stored checkpoint.
    function finalizeFromCheckpoint(CheckpointRefV1 calldata checkpoint, MessageProofV1 calldata proof)
        external
        returns (bytes32)
    {
        _requireChain();
        return _finalize(_checkpointedHeader(checkpoint.header), proof);
    }

    // ---------------------------------------------------------------------
    // Parliament and fast-pause controls (§5.1.6)
    // ---------------------------------------------------------------------

    /// @notice Applies a control leaf proven under a certificate of the current generation. It is
    /// permissionless and not blocked by the pause.
    function applyControl(TairaCertificateV1 calldata certificate, ControlProofV1 calldata control) external {
        _applyControl(certificate, control);
    }

    /// @notice Applies a control leaf proven under a stored checkpoint.
    function applyControlFromCheckpoint(CheckpointRefV1 calldata checkpoint, ControlProofV1 calldata control)
        external
    {
        bool parliamentPaused = _decodedParliamentPaused(control);
        _requireChain();
        _control(_checkpointedHeader(checkpoint.header), control, parliamentPaused);
    }

    // ---------------------------------------------------------------------
    // Destination -> Taira (§5.1.7)
    // ---------------------------------------------------------------------

    /// @notice Burns `tokenAmount` from the caller and emits the inbound source event for Taira.
    /// It stays open while paused, after expiry and after a latch.
    /// @dev Only the canonical ABI encoding succeeds, so that the contract and Taira's decoder
    /// accept exactly the same calls.
    function transferToTaira(bytes calldata tairaRecipient, uint256 tokenAmount, uint64 expectedNonce)
        external
        returns (bytes32 messageId)
    {
        _requireChain();
        _requireCanonicalTransferCalldata();
        if (tokenAmount == 0 || tokenAmount >> 128 != 0) revert BadAmount();
        address sender = msg.sender;
        uint64 nonce = transferNonces[sender];
        // Source nonces are 0 ..= 2^64 − 2. A stored next nonce of 2^64 − 1 is exhausted: no
        // `expectedNonce` is accepted, so that nonce is never used and the counter never wraps.
        if (expectedNonce != nonce || nonce == type(uint64).max) revert BadNonce(nonce);
        unchecked {
            transferNonces[sender] = nonce + 1;
        }
        _burn(sender, tokenAmount);
        bytes memory payload = _inboundPayload(nonce, tokenAmount, tairaRecipient);
        messageId = _inboundMessageId(payload);
        _bumpOpCount();
        emit SccpTransferToTaira(messageId, sender, nonce, payload);
    }

    // ---------------------------------------------------------------------
    // Voids (§5.1.8)
    // ---------------------------------------------------------------------

    /// @notice Voids a Taira transfer after its deadline, proven under a certificate of the
    /// current generation, so that Taira refunds it.
    function voidExpired(uint64 nonce, TairaCertificateV1 calldata certificate, MessageProofV1 calldata proof)
        external
    {
        _voidExpired(nonce, certificate, proof);
    }

    /// @notice Voids a Taira transfer after its deadline, proven under a stored checkpoint.
    function voidExpiredFromCheckpoint(uint64 nonce, CheckpointRefV1 calldata checkpoint, MessageProofV1 calldata proof)
        external
    {
        _requireChain();
        _void(_checkpointedHeader(checkpoint.header), nonce, proof);
    }

    /// @notice Voids up to 256 unconsumed nonces once the destination is frozen: expired or
    /// latched. A frozen destination never mints again, so voiding any nonce is safe.
    /// @dev Only the exact 68-byte encoding succeeds (the ABI decoder already rejects dirty words).
    function voidFrozen(uint64 firstNonce, uint64 count) external {
        _requireChain();
        if (msg.data.length != VOID_FROZEN_CALLDATA_BYTES) revert NonCanonicalCalldata();
        // The range check comes before `Frozen`. `firstNonce + count ≤ 2^64` is compared as
        // `count − 1 ≤ 2^64 − 1 − firstNonce`, so that no value above `u64` is formed; the last
        // nonce of a range that ends at 2^64 is 2^64 − 1.
        uint256 first = firstNonce;
        if (count == 0 || count > MAX_VOID_FROZEN_RANGE || count - 1 > type(uint64).max - first) revert BadAmount();
        if (_isLive(_nowMs())) revert NotFrozen();
        uint256 last = first + (count - 1);
        _consumeRange(first, last);
        _bumpOpCount();
        // One `SccpVoided(0, nonce)` per nonce, emitted directly as LOG3 without data.
        bytes32 topic = SccpVoided.selector;
        assembly ("memory-safe") {
            for { let nonce := first } iszero(gt(nonce, last)) { nonce := add(nonce, 1) } {
                log3(0, 0, topic, 0, nonce)
            }
        }
    }

    // ---------------------------------------------------------------------
    // Views (§5.2.2)
    // ---------------------------------------------------------------------

    /// @notice The current committee generation `cur`.
    function committeeState()
        external
        view
        returns (bytes32 root, uint64 untilMs, uint64 start, uint64 high, uint64 generation)
    {
        return (curRoot, curUntilMs, curStart, curHigh, curGeneration);
    }

    /// @notice The stored pause state and the effective pause at `block.timestamp`.
    function pauseState()
        external
        view
        returns (bool parliamentPaused, uint64 fastPauseUntilMs, uint64 controlNonce_, bool effective)
    {
        return (appliedParliamentPaused, appliedFastPauseUntilMs, controlNonce, _effectivePause(_nowMs()));
    }

    /// @notice The effective pause at `block.timestamp`: it blocks minting only.
    function mintingPaused() external view returns (bool) {
        return _effectivePause(_nowMs());
    }

    /// @notice Taira's Sumeragi instance id `I` pinned by this deployment.
    function consensusInstance() external view returns (bytes32) {
        return CONSENSUS_INSTANCE;
    }

    /// @notice The committee generation pinned at deployment.
    function initialCommittee()
        external
        view
        returns (uint64 generation, bytes32 root, uint64 start, uint64 untilMs)
    {
        return (INITIAL_GENERATION, INITIAL_COMMITTEE_ROOT, INITIAL_START_HEIGHT, INITIAL_UNTIL_MS);
    }

    /// @notice Upper bound on the validity a rotation can grant its successor generation.
    function maxValidityMs() external pure returns (uint64) {
        return MAX_VALIDITY_MS;
    }

    /// @notice Whether an outbound nonce is consumed by a mint or a void.
    function isConsumed(uint64 nonce) external view returns (bool) {
        return consumedBitmap[uint256(nonce) >> 8] & (uint256(1) << (uint256(nonce) & 0xff)) != 0;
    }

    /// @notice Taira `NetworkId` pinned by this deployment.
    function tairaNetworkId() external view returns (bytes32) {
        return TAIRA_NETWORK_ID;
    }

    /// @notice Route revision bound into every payload.
    function routeRevision() external view returns (uint32) {
        return ROUTE_REVISION;
    }

    /// @notice Immutable supply cap in Taira units.
    function maxWrappedSupply() external view returns (uint256) {
        return MAX_WRAPPED_SUPPLY;
    }

    // ---------------------------------------------------------------------
    // ERC-20 surface
    // ---------------------------------------------------------------------

    /// @notice Token name.
    function name() external pure returns (string memory) {
        return "Taira XOR";
    }

    /// @notice Token symbol.
    function symbol() external pure returns (string memory) {
        return "tXOR";
    }

    /// @notice Token decimals; one token unit equals one Taira unit.
    function decimals() external pure returns (uint8) {
        return 9;
    }

    /// @notice ERC-20 transfer.
    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    /// @notice ERC-20 transferFrom; an unlimited allowance is not decremented.
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 current = allowance[from][msg.sender];
        if (current != type(uint256).max) {
            if (current < value) revert ERC20InsufficientAllowance(msg.sender, current, value);
            unchecked {
                allowance[from][msg.sender] = current - value;
            }
        }
        _transfer(from, to, value);
        return true;
    }

    /// @notice ERC-20 approve.
    function approve(address spender, uint256 value) external returns (bool) {
        if (spender == address(0)) revert ERC20InvalidSpender(address(0));
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    // ---------------------------------------------------------------------
    // Entry-point bodies. The bodies that verify a certificate are internal,
    // not private, so that a test harness can enter them with prepared memory.
    // ---------------------------------------------------------------------

    /// @dev §5.1.3 `submitCheckpoints`: chain identity, `TooManyCertificates`, an empty batch,
    /// `Live`, then every certificate in order.
    function _submitCheckpoints(TairaCertificateV1[] calldata certificates) internal {
        _requireChain();
        uint256 count = certificates.length;
        if (count > MAX_CERTIFICATES_PER_CALL) revert TooManyCertificates();
        if (count == 0) revert NothingToDo();
        uint64 nowMs = _nowMs();
        _requireLive(nowMs);
        bool changed;
        for (uint256 i = 0; i < count; ++i) {
            (bool progressed, bool stopped) = _applyCheckpoint(certificates[i], nowMs);
            if (progressed) changed = true;
            if (stopped) break;
        }
        if (!changed) revert NothingToDo();
    }

    /// @dev §5.1.5 with an inline certificate.
    function _finalizeFromTaira(TairaCertificateV1 calldata certificate, MessageProofV1 calldata proof)
        internal
        returns (bytes32)
    {
        _requireChain();
        return _finalize(_inlineHeader(certificate), proof);
    }

    /// @dev §5.1.6 with an inline certificate.
    function _applyControl(TairaCertificateV1 calldata certificate, ControlProofV1 calldata control) internal {
        bool parliamentPaused = _decodedParliamentPaused(control);
        _requireChain();
        _control(_inlineHeader(certificate), control, parliamentPaused);
    }

    /// @dev §5.1.8 `voidExpired` with an inline certificate.
    function _voidExpired(uint64 nonce, TairaCertificateV1 calldata certificate, MessageProofV1 calldata proof)
        internal
    {
        _requireChain();
        _void(_inlineHeader(certificate), nonce, proof);
    }

    // ---------------------------------------------------------------------
    // Committee state machine (§5.1.2)
    // ---------------------------------------------------------------------

    /// @dev One certificate of `submitCheckpoints`: `changed` tells whether it changed state, and
    /// `stopped` whether it latched or rotated into a generation that is already expired, which
    /// ends the batch with the state kept.
    function _applyCheckpoint(TairaCertificateV1 calldata certificate, uint64 nowMs)
        private
        returns (bool changed, bool stopped)
    {
        FinalityHeader memory x = _verifyCertificate(certificate);
        bytes32 stored = checkpointHeader[x.height];
        uint8 reason = _violation(x, stored);
        if (reason != 0) {
            // Latching never reverts: the signature verified, so nothing below can fail.
            equivocated = true;
            curUntilMs = 0;
            emit SccpLatched(
                reason, x.generation, x.height, reason == LATCH_TWO_HEADERS ? stored : x.committeeRoot, x.id
            );
            return (true, true);
        }
        changed = _recordCheckpoint(x, stored);
        if (x.rotation) {
            stopped = _rotate(x, nowMs);
            changed = true;
        }
    }

    /// @dev Obtains `X` from an inline certificate: `VerifyCertificate`, V1–V3 answering
    /// `LatchRequired`, the checkpoint and `high`, and only then `Live`. No successor is installed.
    function _inlineHeader(TairaCertificateV1 calldata certificate) private returns (FinalityHeader memory x) {
        x = _verifyCertificate(certificate);
        bytes32 stored = checkpointHeader[x.height];
        if (_violation(x, stored) != 0) revert LatchRequired();
        _recordCheckpoint(x, stored);
        _requireLive(_nowMs());
    }

    /// @dev The violation predicates of a verified CUR certificate, as the latch reason:
    /// V1 a different header already stored at the height, V2 a height before the generation's
    /// start, V3 a rotation below a height the generation already certified; 0 if none holds.
    function _violation(FinalityHeader memory x, bytes32 stored) private view returns (uint8) {
        if (stored != bytes32(0) && stored != x.id) return LATCH_TWO_HEADERS;
        if (x.height < curStart) return LATCH_BELOW_START;
        if (x.rotation && x.height < curHigh) return LATCH_ROTATION_BELOW_HIGH;
        return 0;
    }

    /// @dev Stores the checkpoint if its height has none and raises `high`; true if either changed.
    function _recordCheckpoint(FinalityHeader memory x, bytes32 stored) private returns (bool changed) {
        if (stored == bytes32(0)) {
            checkpointHeader[x.height] = x.id;
            emit SccpCheckpointed(x.height, x.id);
            changed = true;
        }
        if (x.height > curHigh) {
            curHigh = x.height;
            changed = true;
        }
    }

    /// @dev Installs the successor of a rotation: `{next root, generation + 1, height + 1,
    /// height, min(t_eff(X) + validity, 2^64 − 1)}` with `t_eff(X) = min(X.timestamp_ms, now_ms)`.
    /// Returns true if the successor is already expired at `nowMs`.
    function _rotate(FinalityHeader memory x, uint64 nowMs) private returns (bool expired) {
        uint64 untilMs;
        uint64 generation;
        uint64 start;
        unchecked {
            // Two `u64` values added in 256 bits: the sum saturates instead of wrapping.
            uint256 sum = uint256(x.timestampMs < nowMs ? x.timestampMs : nowMs) + x.validityMs;
            untilMs = sum > type(uint64).max ? type(uint64).max : uint64(sum);
            // X6 bounds a rotation's generation and height by 2^64 − 2, so neither sum wraps.
            generation = x.generation + 1;
            start = x.height + 1;
        }
        curRoot = x.nextCommitteeRoot;
        curUntilMs = untilMs;
        curStart = start;
        curHigh = x.height;
        curGeneration = generation;
        emit SccpCommitteeRotated(generation, x.nextCommitteeRoot, untilMs, start);
        // The latch is clear here, so the destination is `Live` iff the new deadline holds.
        return nowMs > untilMs;
    }

    /// @dev Checkpoint use (§5.1.3): the length of `X`, the stored id, X1–X7 with `ACTIVE`,
    /// `Live`, and then eligibility: U1, `X` is of the current generation, or U2, `X` is the
    /// handoff that installed it.
    function _checkpointedHeader(bytes calldata header) private view returns (FinalityHeader memory x) {
        if (header.length != X_BYTES) revert BadHeader();
        bytes32 id = keccak256(header);
        bytes32 stored = checkpointHeader[uint64(_be(_offset(header) + 48, 8))];
        if (stored == bytes32(0) || stored != id) revert UnknownCheckpoint();
        x = _parseHeader(header);
        x.id = id;
        _requireLive(_nowMs());
        bytes32 root = curRoot;
        uint256 generation = curGeneration;
        if (x.generation == generation && x.committeeRoot == root) return x;
        bool handoff;
        unchecked {
            // `u64` values widened to 256 bits, so neither sum wraps.
            handoff = x.rotation && uint256(x.generation) + 1 == generation
                && uint256(x.height) + 1 == curStart && x.nextCommitteeRoot == root;
        }
        if (!handoff) revert CommitteeNotAccepted();
    }

    /// @dev `Live ⇔ ¬equivocated ∧ now_ms ≤ cur.untilMs`.
    function _isLive(uint64 nowMs) private view returns (bool) {
        return !equivocated && nowMs <= curUntilMs;
    }

    /// @dev A destination that is not `Live` answers `Equivocated` when latched and
    /// `CommitteeNotAccepted` when only its deadline has passed.
    function _requireLive(uint64 nowMs) private view {
        if (equivocated) revert Equivocated();
        if (nowMs > curUntilMs) revert CommitteeNotAccepted();
    }

    /// @dev The effective pause: `parliamentPaused ∨ now_ms < fastPauseUntilMs`.
    function _effectivePause(uint64 nowMs) private view returns (bool) {
        return appliedParliamentPaused || nowMs < appliedFastPauseUntilMs;
    }

    /// @dev The destination clock `now_ms = min(block.timestamp × 1000, 2^64 − 1)`: it saturates
    /// instead of reverting or truncating.
    function _nowMs() private view returns (uint64) {
        uint256 timestamp = block.timestamp;
        if (timestamp > MAX_CLOCK_SECONDS) return type(uint64).max;
        unchecked {
            return uint64(timestamp * 1000);
        }
    }

    // ---------------------------------------------------------------------
    // Certificate verification (§3.6 - §3.8, §5.1.3, §5.2.4)
    // ---------------------------------------------------------------------

    /// @dev `VerifyCertificate` steps 1–12; the first failure is the call's error. Returns the
    /// parsed `X` with its id. A certificate whose `X` is already stored takes the cheap path
    /// after step 6: its signature is not checked and it is not published again.
    function _verifyCertificate(TairaCertificateV1 calldata certificate)
        internal
        returns (FinalityHeader memory x)
    {
        // 1. Exact lengths.
        uint256 n = _committeeSize(certificate);
        // 2. X1–X7 with `ACTIVE`, and the pinned Taira network. There is no skew check.
        x = _parseHeader(certificate.header);
        if (x.networkId != TAIRA_NETWORK_ID) revert BadHeader();
        // 3. CUR, before any signature work.
        bytes32 root = curRoot;
        if (x.generation != curGeneration || x.committeeRoot != root) revert CommitteeNotAccepted();
        // 4. The supplied keys are the current committee.
        if (keccak256(abi.encodePacked(bytes17("SCCP/COMMITTEE/V1"), uint8(n), certificate.committee)) != root) {
            revert BadCommittee();
        }
        // 5. No signer bit beyond the committee, and exactly `q` signers.
        uint256 signers = _be(_offset(certificate.qc) + 112, 4);
        if (signers >> n != 0 || _popcount(signers) != _quorum(n)) revert BadCertificate();
        // 6. Every encoding, before the cheap path and before any precompile.
        _checkEncodings(certificate, signers);
        // 7. The checkpoint id. `R` is computed with `m` below: only the full path needs it.
        x.id = keccak256(certificate.header);
        // 8. The cheap path is mandatory: only `X` is used, and it is already certified.
        if (checkpointHeader[x.height] == x.id) return x;
        // 9–11. The signed message, the aggregate key and the pairing check.
        if (!_verifySignature(certificate, signers)) revert BadSignature();
        // 12. Publish every certificate that passed the full path, whatever follows.
        emit SccpCertificate(x.height, x.generation, certificate.qc, certificate.header, certificate.signature);
    }

    /// @dev Step 1: the exact lengths, in the order `QC_FIXED`, `X`, signature, committee,
    /// `signerYs`. Returns the committee size `n ∈ {4, 7, …, 31}`.
    function _committeeSize(TairaCertificateV1 calldata certificate) private pure returns (uint256 n) {
        if (certificate.qc.length != QC_FIXED_BYTES) revert BadCertificate();
        if (certificate.header.length != X_BYTES) revert BadHeader();
        if (certificate.signature.length != SIGNATURE_BYTES) revert BadCertificate();
        uint256 length = certificate.committee.length;
        n = length / FIELD_BYTES;
        if (length != n * FIELD_BYTES || n < MIN_COMMITTEE || n > MAX_COMMITTEE || (n - 1) % 3 != 0) {
            revert BadCommittee();
        }
        if (certificate.signerYs.length != FIELD_BYTES * _quorum(n)) revert BadCertificate();
    }

    /// @dev `q = n − f` with `f = (n − 1) / 3`, for `n ≥ 1`.
    function _quorum(uint256 n) private pure returns (uint256) {
        return n - (n - 1) / 3;
    }

    /// @dev Number of set bits. Each round clears the lowest set bit of a nonzero value, so
    /// nothing wraps.
    function _popcount(uint256 bits) private pure returns (uint256 count) {
        unchecked {
            for (; bits != 0; bits &= bits - 1) {
                ++count;
            }
        }
    }

    /// @dev `SccpFinalityHeaderV1::parse` for a destination (§3.6): X1, `ACTIVE`, X3–X7 in this
    /// order, every failure answering `BadHeader`. X2 constrains an inactive header only, and a
    /// destination refuses every inactive header with the same error. The caller has checked
    /// that `header` is exactly 221 bytes.
    function _parseHeader(bytes calldata header) private pure returns (FinalityHeader memory x) {
        uint256 o = _offset(header);
        uint256 flags = _be(o + 64, 1);
        if (_be(o, 16) != X_MAGIC || flags & X_FLAGS_RESERVED != 0 || flags & X_FLAG_ACTIVE == 0) {
            revert BadHeader();
        }
        x.networkId = bytes32(_be(o + 16, 32));
        x.height = uint64(_be(o + 48, 8));
        x.timestampMs = uint64(_be(o + 56, 8));
        x.rotation = flags & X_FLAG_ROTATION != 0;
        x.messageCount = uint32(_be(o + 65, 4));
        x.sccpRoot = bytes32(_be(o + 69, 32));
        x.historySize = uint64(_be(o + 101, 8));
        x.historyRoot = bytes32(_be(o + 109, 32));
        x.generation = uint64(_be(o + 141, 8));
        x.committeeRoot = bytes32(_be(o + 149, 32));
        x.validityMs = uint64(_be(o + 181, 8));
        x.nextCommitteeRoot = bytes32(_be(o + 189, 32));
        // X3
        if (x.generation == 0 || x.committeeRoot == bytes32(0)) revert BadHeader();
        // X4
        if ((x.messageCount == 0) != (x.sccpRoot == bytes32(0)) || x.messageCount > MAX_BLOCK_LEAVES) {
            revert BadHeader();
        }
        // X5
        if ((x.historySize == 0) != (x.historyRoot == bytes32(0)) || x.historySize > MAX_HISTORY_SIZE) {
            revert BadHeader();
        }
        // X6: the successor's start `height + 1` and its generation `generation + 1` are `u64` values.
        if (x.rotation) {
            if (
                x.nextCommitteeRoot == bytes32(0) || x.validityMs == 0 || x.validityMs > MAX_VALIDITY_MS
                    || x.height == type(uint64).max || x.generation == type(uint64).max
            ) revert BadHeader();
        } else if (x.nextCommitteeRoot != bytes32(0) || x.validityMs != 0) {
            revert BadHeader();
        }
        // X7
        if (x.height == 0) revert BadHeader();
    }

    /// @dev Step 6, in its order: the identity signature (`BadSignature`), every signer `y`
    /// below `p` (`BadCommittee`), every signature limb below `p` (`BadSignature`), and every
    /// signer key (`BadCommittee`). It runs before any precompile: a precompile that refuses an
    /// input consumes all gas forwarded to it.
    function _checkEncodings(TairaCertificateV1 calldata certificate, uint256 signers) private pure {
        uint256 sigma = _offset(certificate.signature);
        if (
            (
                _be(sigma, 32) | _be(sigma + 32, 32) | _be(sigma + 64, 32) | _be(sigma + 96, 32)
                    | _be(sigma + 128, 32) | _be(sigma + 160, 32)
            ) == 0
        ) revert BadSignature();
        uint256 ys = _offset(certificate.signerYs);
        uint256 key = _offset(certificate.committee);
        // Every offset below stays inside its byte array, whose length step 1 fixed, so the
        // offset arithmetic cannot wrap.
        unchecked {
            uint256 end = ys + certificate.signerYs.length;
            for (uint256 y = ys; y < end; y += FIELD_BYTES) {
                (uint256 hi, uint256 lo) = _field(y);
                if (!BLS12_381.isFieldElement(hi, lo)) revert BadCommittee();
            }
            end = sigma + SIGNATURE_BYTES;
            for (uint256 limb = sigma; limb < end; limb += FIELD_BYTES) {
                (uint256 hi, uint256 lo) = _field(limb);
                if (!BLS12_381.isFieldElement(hi, lo)) revert BadSignature();
            }
            for (; signers != 0; signers >>= 1) {
                if (signers & 1 != 0) {
                    _checkSignerKey(key, ys);
                    ys += FIELD_BYTES;
                }
                key += FIELD_BYTES;
            }
        }
    }

    /// @dev One signer: the compressed key at calldata offset `key` and its `y` at `y`. With `x`
    /// the key without its flag bits: the compression flag is set and the infinity flag clear,
    /// the sign flag equals `y > HALF_P`, `x < p`, and `(x, y) ≠ (0, 0)`, which `G1ADD` would read
    /// as the point at infinity and so drop the signer.
    function _checkSignerKey(uint256 key, uint256 y) private pure {
        (uint256 keyHi, uint256 xLo) = _field(key);
        (uint256 yHi, uint256 yLo) = _field(y);
        uint256 xHi = keyHi & KEY_X_HI_MASK;
        // Of the 128 bits of `keyHi`, bit 127 is the compression flag (0x80 of byte 0), bit 126
        // the infinity flag (0x40) and bit 125 the sign flag (0x20).
        if (
            keyHi >> 126 != 2 || ((keyHi >> 125) & 1 != 0) != BLS12_381.isAboveHalfP(yHi, yLo)
                || !BLS12_381.isFieldElement(xHi, xLo) || (xHi | xLo | yHi | yLo) == 0
        ) revert BadCommittee();
    }

    /// @dev Steps 9–11: `m`, the aggregate key, hash-to-G2 and the pairing check
    /// `e(apk, Q) · e(−g1, σ) = 1`. Reverts `BadCommittee` for the aggregate key before `σ` is
    /// read as a point; returns false when the pairing check refuses or fails.
    function _verifySignature(TairaCertificateV1 calldata certificate, uint256 signers) private view returns (bool) {
        bytes32 m = _commitMessage(certificate.qc, certificate.header);
        bytes memory pair = _aggregateKey(certificate.committee, certificate.signerYs, signers);
        bytes memory q = BLS12_381.hashToG2(m);
        return BLS12_381.pairingCheck(_pairingInput(pair, q, certificate.signature));
    }

    /// @dev `m = SHA-256(P)` for the commit preimage `P = "sumeragi/sig" ‖ 0x03 ‖ I ‖ epoch ‖
    /// epoch_context ‖ be64(X.height) ‖ view ‖ block_hash ‖ R` (165 bytes) with `R =
    /// SHA-256("iroha/sumeragi/result/v1" ‖ X ‖ result_body)` (277 bytes). `QC_FIXED` is `epoch ‖
    /// epoch_context ‖ view ‖ block_hash ‖ result_body ‖ signers`. A failed precompile call
    /// reverts with empty data, as in the library.
    function _commitMessage(bytes calldata qc, bytes calldata header) private view returns (bytes32 m) {
        bytes32 instance = CONSENSUS_INSTANCE;
        assembly ("memory-safe") {
            // Both inputs are written in full into temporary memory after the free pointer.
            let p := mload(0x40)
            mstore(p, "iroha/sumeragi/result/v1")
            calldatacopy(add(p, 24), header.offset, 221)
            calldatacopy(add(p, 245), add(qc.offset, 80), 32)
            let ok := staticcall(gas(), PRECOMPILE_SHA256, p, 277, 0x00, 0x20)
            if iszero(and(ok, eq(returndatasize(), 0x20))) { revert(0, 0) }
            let r := mload(0x00)
            mstore(p, "sumeragi/sig")
            mstore8(add(p, 12), 0x03)
            mstore(add(p, 13), instance)
            calldatacopy(add(p, 45), qc.offset, 40)
            calldatacopy(add(p, 85), add(header.offset, 48), 8)
            calldatacopy(add(p, 93), add(qc.offset, 40), 40)
            mstore(add(p, 133), r)
            ok := staticcall(gas(), PRECOMPILE_SHA256, p, 165, 0x00, 0x20)
            if iszero(and(ok, eq(returndatasize(), 0x20))) { revert(0, 0) }
            m := mload(0x00)
        }
    }

    /// @dev Step 10: `apk = Σ PK_i` over the signers, in a 256-byte `G1ADD` pair whose first
    /// point is the sum. A signer point off the curve, and then `apk = O`, answer `BadCommittee`.
    /// `G1ADD` adds any points of the curve, so only the aggregate is observed, never the
    /// subgroup of a single key (§5.1.3 step 11).
    function _aggregateKey(bytes calldata committee, bytes calldata signerYs, uint256 signers)
        private
        view
        returns (bytes memory pair)
    {
        // The sum starts as the point at infinity, the 128 zero bytes of a new array.
        pair = new bytes(BLS12_381.G1_PAIR_LENGTH);
        uint256 key = _offset(committee);
        uint256 y = _offset(signerYs);
        // The offsets stay inside the two byte arrays (step 1), so their arithmetic cannot wrap.
        unchecked {
            for (; signers != 0; signers >>= 1) {
                if (signers & 1 != 0) {
                    assembly ("memory-safe") {
                        // The second point of the pair: `x` and `y`, each zero-extended to 64 bytes.
                        let point := add(pair, 0xa0)
                        mstore(point, and(shr(128, calldataload(key)), KEY_X_HI_MASK))
                        mstore(add(point, 0x20), calldataload(add(key, 16)))
                        mstore(add(point, 0x40), shr(128, calldataload(y)))
                        mstore(add(point, 0x60), calldataload(add(y, 16)))
                    }
                    if (!BLS12_381.g1Add(pair)) revert BadCommittee();
                    y += FIELD_BYTES;
                }
                key += FIELD_BYTES;
            }
        }
        if (BLS12_381.g1IsInfinity(pair)) revert BadCommittee();
    }

    /// @dev The 768-byte pairing input `apk ‖ Q ‖ (−g1) ‖ σ` (§5.2.4). `pair` holds `apk` in its
    /// first 128 bytes, `q` is the 256-byte hash-to-G2 point, and each 48-byte limb of the
    /// 192-byte `signature` is zero-extended to 64 bytes. Every byte of the input is written here.
    function _pairingInput(bytes memory pair, bytes memory q, bytes calldata signature)
        private
        pure
        returns (bytes memory input)
    {
        bytes memory negG1 = abi.encodePacked(
            BLS12_381.G1_X_HI, BLS12_381.G1_X_LO, BLS12_381.NEG_G1_Y_HI, BLS12_381.NEG_G1_Y_LO
        );
        input = new bytes(BLS12_381.PAIRING_INPUT_LENGTH);
        assembly ("memory-safe") {
            let p := add(input, 0x20)
            mcopy(p, add(pair, 0x20), 0x80)
            mcopy(add(p, 0x80), add(q, 0x20), 0x100)
            mcopy(add(p, 0x180), add(negG1, 0x20), 0x80)
            let limb := signature.offset
            for { let w := add(p, 0x200) } lt(w, add(p, 0x300)) { w := add(w, 0x40) } {
                mstore(w, shr(128, calldataload(limb)))
                mstore(add(w, 0x20), calldataload(add(limb, 16)))
                limb := add(limb, 48)
            }
        }
    }

    // ---------------------------------------------------------------------
    // Finalization, controls and voids against an obtained `X`
    // ---------------------------------------------------------------------

    /// @dev §5.1.5 steps 3–8 after `Live`: the pause, the message, the consumed set, the cap.
    function _finalize(FinalityHeader memory x, MessageProofV1 calldata proof) private returns (bytes32 messageId) {
        if (_effectivePause(_nowMs())) revert MintingIsPaused();
        uint64 nonce;
        address recipient;
        uint256 amount;
        (messageId, nonce, recipient, amount) = _verifyMessage(x, proof, true);
        _consume(nonce);
        _mint(recipient, amount);
        _bumpOpCount();
        emit SccpFinalized(messageId, nonce, recipient, amount);
    }

    /// @dev §5.1.8 `voidExpired*`: the steps of a finalization without the pause and the cap,
    /// after the deadline. The `nonce` argument is checked after the leaf path and before the
    /// consumed set.
    function _void(FinalityHeader memory x, uint64 nonce, MessageProofV1 calldata proof) private {
        (bytes32 messageId, uint64 payloadNonce,,) = _verifyMessage(x, proof, false);
        if (nonce != payloadNonce) revert BadNonce(payloadNonce);
        _consume(nonce);
        _bumpOpCount();
        emit SccpVoided(messageId, nonce);
    }

    /// @dev §5.1.6 steps 3–5: the block reference, the leaf, the §3.4 constraints, the nonce,
    /// and then the new pause state. `parliamentPaused` is `control.parliamentPaused`.
    function _control(FinalityHeader memory x, ControlProofV1 calldata control, bool parliamentPaused) private {
        (bytes32 sccpRoot, uint256 messageCount) = _checkBlockRef(x, control.block);
        _checkLeaf(_controlLeaf(control, parliamentPaused), control.leafIndex, messageCount, control.path, sccpRoot);
        uint256 track = control.track;
        uint64 fastPauseUntilMs = control.fastPauseUntilMs;
        if (
            (track != TRACK_PARLIAMENT && track != TRACK_FAST_PAUSE)
                || (track == TRACK_FAST_PAUSE && fastPauseUntilMs == 0) || control.certificateId == bytes32(0)
                || control.effectHash == bytes32(0)
        ) revert BadControl();
        uint64 nonce = control.controlNonce;
        if (nonce <= controlNonce) revert StaleControl();
        // `min(leaf.fast_pause_until_ms, min(now_ms + MAX_FAST_PAUSE_MS, 2^64 − 1))`. The bound is
        // formed in 256 bits; an expiry above it is replaced by it, and the bound then fits `u64`.
        uint256 bound = uint256(_nowMs()) + MAX_FAST_PAUSE_MS;
        if (fastPauseUntilMs > bound) fastPauseUntilMs = uint64(bound);
        appliedParliamentPaused = parliamentPaused;
        appliedFastPauseUntilMs = fastPauseUntilMs;
        controlNonce = nonce;
        _bumpOpCount();
        emit SccpControlApplied(nonce, uint8(track), parliamentPaused, fastPauseUntilMs, control.certificateId);
    }

    /// @dev Reads the typed flag of a control. The ABI decoder checks a calldata struct member
    /// where it is read, so the entry points call this first: a `parliamentPaused` word above 1
    /// then fails in the decoder, with empty revert data, before any check of this contract (§3.4).
    function _decodedParliamentPaused(ControlProofV1 calldata control) private pure returns (bool) {
        return control.parliamentPaused;
    }

    // ---------------------------------------------------------------------
    // Message, control and history verification (§3.2 - §3.5, §5.1.5)
    // ---------------------------------------------------------------------

    /// @dev §5.1.5 steps 4 and 5 against a verified `X`: the block reference, the payload and its
    /// recipient, the deadline, then the leaf path. `mint` selects the deadline side.
    function _verifyMessage(FinalityHeader memory x, MessageProofV1 calldata proof, bool mint)
        private
        view
        returns (bytes32 messageId, uint64 nonce, address recipient, uint256 amount)
    {
        (bytes32 sccpRoot, uint256 messageCount) = _checkBlockRef(x, proof.block);
        uint256 deadlineMs;
        (nonce, deadlineMs, amount, recipient) = _parseOutboundPayload(proof.payload);
        _checkDeadline(deadlineMs, mint);
        messageId = _outboundMessageId(proof.payload);
        _checkLeaf(_transferLeaf(messageId), proof.leafIndex, messageCount, proof.path, sccpRoot);
    }

    /// @dev Mint while `now_ms ≤ deadline_ms`; void only after it (§3.2).
    function _checkDeadline(uint256 deadlineMs, bool mint) private view {
        uint256 nowMs = _nowMs();
        if (mint) {
            if (nowMs > deadlineMs) revert DeadlinePassed();
        } else if (nowMs <= deadlineMs) {
            revert DeadlineNotReached();
        }
    }

    /// @dev `BlockRefV1` against a verified `X` (§5.1.5). The certified block itself must repeat
    /// `X.sccp_root ≠ 0` and `X.message_count` and carry no history proof. An older block must be
    /// a leaf of the history accumulator after `X`. Returns the block's root and leaf count.
    function _checkBlockRef(FinalityHeader memory x, BlockRefV1 calldata blockRef)
        private
        pure
        returns (bytes32 sccpRoot, uint256 messageCount)
    {
        uint64 height = blockRef.height;
        sccpRoot = blockRef.sccpRoot;
        messageCount = blockRef.messageCount;
        if (height == x.height) {
            if (
                sccpRoot == bytes32(0) || sccpRoot != x.sccpRoot || messageCount != x.messageCount
                    || blockRef.historyIndex != 0 || blockRef.historyPath.length != 0
            ) revert BadProof();
            return (sccpRoot, messageCount);
        }
        if (
            height > x.height || messageCount == 0 || messageCount > MAX_BLOCK_LEAVES || sccpRoot == bytes32(0)
                || blockRef.historyPath.length > MAX_HISTORY_PATH
        ) revert BadProof();
        // X5 bounds `X.history_size` by 2^32, and an empty history has no leaf.
        bytes32 leaf = keccak256(abi.encodePacked(bytes15("SCCP/HISTORY/V1"), height, sccpRoot, uint32(messageCount)));
        if (_merkleRoot(leaf, blockRef.historyIndex, x.historySize, blockRef.historyPath) != x.historyRoot) {
            revert BadProof();
        }
    }

    /// @dev Leaf inclusion in a block of `messageCount` leaves (at most 9 siblings).
    function _checkLeaf(
        bytes32 leaf,
        uint256 leafIndex,
        uint256 messageCount,
        bytes32[] calldata path,
        bytes32 sccpRoot
    ) private pure {
        if (path.length > MAX_BLOCK_PATH || _merkleRoot(leaf, leafIndex, messageCount, path) != sccpRoot) {
            revert BadProof();
        }
    }

    /// @dev Positional promote-odd Merkle root (§3.4) binding the leaf index and count.
    function _merkleRoot(bytes32 leaf, uint256 index, uint256 count, bytes32[] calldata path)
        private
        pure
        returns (bytes32 node)
    {
        if (count == 0 || index >= count) revert BadProof();
        uint256 siblings = path.length;
        uint256 k;
        node = leaf;
        while (count > 1) {
            if (index & 1 == 1) {
                if (k >= siblings) revert BadProof();
                node = _node(path[k], node);
                ++k;
            } else if (index + 1 < count) {
                if (k >= siblings) revert BadProof();
                node = _node(node, path[k]);
                ++k;
            }
            index >>= 1;
            count = (count + 1) >> 1;
        }
        if (k != siblings) revert BadProof();
    }

    function _node(bytes32 left, bytes32 right) private pure returns (bytes32 node) {
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, "SCCP/NODE/V1")
            mstore(add(p, 12), left)
            mstore(add(p, 44), right)
            node := keccak256(p, 76)
        }
    }

    function _transferLeaf(bytes32 messageId) private view returns (bytes32 leaf) {
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, "SCCP/LEAF/V1")
            mstore(add(p, 12), messageId)
            mstore(add(p, 44), address())
            leaf := keccak256(p, 76)
        }
    }

    /// @dev The §3.4 control leaf (199-byte preimage) from the own immutables, the own address
    /// as destination word and the supplied fields: tag ‖ `lane_bytes(sora-taira, own)` ‖
    /// destination word ‖ revision ‖ nonce ‖ track ‖ parliament_paused ‖ fast_pause_until_ms ‖
    /// certificate_id ‖ effect_hash.
    function _controlLeaf(ControlProofV1 calldata control, bool parliamentPaused) private view returns (bytes32) {
        return keccak256(
            bytes.concat(
                abi.encodePacked(
                    bytes15("SCCP/CONTROL/V1"),
                    TAG_TAIRA,
                    TAIRA_NETWORK_ID,
                    NETWORK_TAG,
                    _identityWordOf(NETWORK_TAG),
                    uint256(uint160(address(this))),
                    ROUTE_REVISION
                ),
                abi.encodePacked(
                    control.controlNonce,
                    control.track,
                    parliamentPaused,
                    control.fastPauseUntilMs,
                    control.certificateId,
                    control.effectHash
                )
            )
        );
    }

    /// @dev `message_id` over lane `(sora-taira, own)` for an outbound calldata payload (§3.3).
    function _outboundMessageId(bytes calldata payload) private view returns (bytes32 messageId) {
        bytes32 networkId = TAIRA_NETWORK_ID;
        uint256 tag = NETWORK_TAG;
        uint256 identity = _identityWordOf(NETWORK_TAG);
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, "SCCP/PAYLOAD/V1")
            calldatacopy(add(p, 15), payload.offset, payload.length)
            let payloadHash := keccak256(p, add(15, payload.length))
            mstore(p, "SCCP/MESSAGE/V1")
            mstore8(add(p, 15), TAG_TAIRA)
            mstore(add(p, 16), networkId)
            mstore8(add(p, 48), tag)
            mstore(add(p, 49), identity)
            mstore(add(p, 81), payloadHash)
            messageId := keccak256(p, 113)
        }
    }

    /// @dev `message_id` over lane `(own, sora-taira)` for an inbound memory payload (§3.3).
    function _inboundMessageId(bytes memory payload) private view returns (bytes32 messageId) {
        bytes32 networkId = TAIRA_NETWORK_ID;
        uint256 tag = NETWORK_TAG;
        uint256 identity = _identityWordOf(NETWORK_TAG);
        assembly ("memory-safe") {
            // The 15-byte domain tag temporarily occupies the tail of the length word.
            let length := mload(payload)
            mstore(payload, shr(136, "SCCP/PAYLOAD/V1"))
            let payloadHash := keccak256(add(payload, 17), add(15, length))
            mstore(payload, length)
            let p := mload(0x40)
            mstore(p, "SCCP/MESSAGE/V1")
            mstore8(add(p, 15), tag)
            mstore(add(p, 16), identity)
            mstore8(add(p, 48), TAG_TAIRA)
            mstore(add(p, 49), networkId)
            mstore(add(p, 81), payloadHash)
            messageId := keccak256(p, 113)
        }
    }

    /// @dev Strict §3.2 decoding of a Taira -> own payload; every field is checked and no
    /// trailing byte is admitted. Reads calldata slices only.
    function _parseOutboundPayload(bytes calldata payload)
        private
        view
        returns (uint64 nonce, uint256 deadlineMs, uint256 amount, address recipient)
    {
        uint256 length = payload.length;
        if (length < MIN_PAYLOAD_BYTES || length > MAX_PAYLOAD_BYTES) revert BadPayload();
        uint256 o = _offset(payload);
        uint256 senderLength;
        (nonce, deadlineMs, amount, senderLength) = _parsePayloadHead(o);
        recipient = _parsePayloadTail(o + MIN_PAYLOAD_BYTES + senderLength, o + length);
    }

    /// @dev Fixed-layout head up to the sender length: kind, version, domains, nonce, revision,
    /// deadline, asset and amount.
    function _parsePayloadHead(uint256 o)
        private
        view
        returns (uint64 nonce, uint256 deadlineMs, uint256 amount, uint256 senderLength)
    {
        if (
            _be(o, 1) != PAYLOAD_KIND_TRANSFER || _be(o + 1, 1) != PAYLOAD_VERSION || _be(o + 2, 4) != 0
                || _be(o + 6, 4) != _domainOf(NETWORK_TAG) || _be(o + 18, 4) != ROUTE_REVISION
        ) revert BadPayload();
        nonce = uint64(_be(o + 10, 8));
        deadlineMs = _be(o + 22, 8);
        amount = _be(o + 40, 16);
        if (
            deadlineMs == 0 || _be(o + 30, 4) != 0 || _be(o + 34, 1) != CODEC_CANONICAL_TEXT || _be(o + 35, 2) != 3
                || _be(o + 37, 3) != ASSET_ID_XOR || amount == 0 || _be(o + 56, 1) != CODEC_TAIRA_ACCOUNT
        ) revert BadPayload();
        senderLength = _be(o + 57, 2);
        if (senderLength == 0 || senderLength > MAX_TAIRA_ACCOUNT_BYTES) revert BadPayload();
    }

    /// @dev Recipient and route id from calldata offset `r` to the exact payload end `end`.
    function _parsePayloadTail(uint256 r, uint256 end) private view returns (address recipient) {
        (bytes32 routeId, uint256 routeIdLength) = _routeIdOf(NETWORK_TAG);
        if (end != r + 3 + EVM_ADDRESS_BYTES + 3 + routeIdLength) revert BadPayload();
        if (_be(r, 1) != CODEC_EVM_ADDRESS20 || _be(r + 1, 2) != EVM_ADDRESS_BYTES) revert BadPayload();
        uint256 q = r + 3 + EVM_ADDRESS_BYTES;
        if (
            _be(q, 1) != CODEC_CANONICAL_TEXT || _be(q + 1, 2) != routeIdLength
                || _be(q + 3, routeIdLength) != uint256(routeId) >> (256 - 8 * routeIdLength)
        ) revert BadPayload();
        recipient = address(uint160(_be(r + 3, EVM_ADDRESS_BYTES)));
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient();
    }

    /// @dev Builds the §3.2 own -> Taira payload for `transferToTaira` in memory.
    function _inboundPayload(uint64 nonce, uint256 amount, bytes calldata tairaRecipient)
        private
        view
        returns (bytes memory payload)
    {
        (bytes32 routeId, uint256 routeIdLength) = _routeIdOf(NETWORK_TAG);
        payload = new bytes(MIN_PAYLOAD_BYTES + EVM_ADDRESS_BYTES + 3 + tairaRecipient.length + 3 + routeIdLength);
        uint256 head = (0x0201 << 32 | _domainOf(NETWORK_TAG)) << 208;
        uint256 revision = ROUTE_REVISION;
        assembly ("memory-safe") {
            let c := add(payload, 32)
            // kind, version, source domain (own), destination domain 0
            mstore(c, head)
            mstore(add(c, 10), shl(192, nonce))
            mstore(add(c, 18), shl(224, revision))
            // deadline 0, asset home domain 0, asset codec 1, asset id "xor"
            mstore(add(c, 22), 0)
            mstore(add(c, 34), or(shl(248, CODEC_CANONICAL_TEXT), or(shl(232, 3), shl(208, ASSET_ID_XOR))))
            mstore(add(c, 40), shl(128, amount))
            mstore(add(c, 56), or(shl(248, CODEC_EVM_ADDRESS20), shl(232, EVM_ADDRESS_BYTES)))
            c := add(c, 59)
            mstore(c, shl(96, caller()))
            c := add(c, 20)
            let recipientLength := tairaRecipient.length
            mstore(c, or(shl(248, CODEC_TAIRA_ACCOUNT), shl(232, recipientLength)))
            calldatacopy(add(c, 3), tairaRecipient.offset, recipientLength)
            c := add(c, add(3, recipientLength))
            mstore(c, or(shl(248, CODEC_CANONICAL_TEXT), shl(232, routeIdLength)))
            // The route id tail spills only zero bytes into unallocated memory.
            mstore(add(c, 3), routeId)
        }
    }

    /// @dev `NonCanonicalCalldata()` unless the §5.1.7 canonical encoding holds exactly.
    function _requireCanonicalTransferCalldata() private pure {
        bool canonical;
        assembly ("memory-safe") {
            let size := calldatasize()
            let length := calldataload(0x64)
            let padded := and(add(length, 31), not(31))
            canonical := and(
                and(eq(calldataload(4), 0x60), and(gt(length, 0), iszero(gt(length, MAX_TAIRA_ACCOUNT_BYTES)))),
                eq(size, add(CANONICAL_TRANSFER_HEAD, padded))
            )
            let tail := and(length, 31)
            if and(canonical, gt(tail, 0)) {
                let last := calldataload(add(CANONICAL_TRANSFER_HEAD, sub(padded, 32)))
                canonical := iszero(shl(mul(tail, 8), last))
            }
        }
        if (!canonical) revert NonCanonicalCalldata();
    }

    // ---------------------------------------------------------------------
    // State transitions
    // ---------------------------------------------------------------------

    function _consume(uint64 nonce) private {
        uint256 word = uint256(nonce) >> 8;
        uint256 bit = uint256(1) << (uint256(nonce) & 0xff);
        uint256 bits = consumedBitmap[word];
        if (bits & bit != 0) revert AlreadyConsumed(nonce);
        consumedBitmap[word] = bits | bit;
    }

    /// @dev Consumes `[first, last]` (at most 256 nonces, so at most two bitmap words).
    function _consumeRange(uint256 first, uint256 last) private {
        for (uint256 word = first >> 8; word <= last >> 8; ++word) {
            uint256 low = word == first >> 8 ? first & 0xff : 0;
            uint256 high = word == last >> 8 ? last & 0xff : 0xff;
            uint256 mask = (type(uint256).max >> (255 - high)) & (type(uint256).max << low);
            uint256 bits = consumedBitmap[word];
            uint256 taken = bits & mask;
            if (taken != 0) {
                uint256 lowest;
                while (taken & (uint256(1) << lowest) == 0) {
                    ++lowest;
                }
                revert AlreadyConsumed(uint64((word << 8) | lowest));
            }
            consumedBitmap[word] = bits | mask;
        }
    }

    /// @dev The cap is compared as `amount ≤ maxWrappedSupply − totalSupply`, so that no sum
    /// exceeds its width; `totalSupply ≤ maxWrappedSupply` holds because only this function
    /// raises the supply.
    function _mint(address recipient, uint256 amount) private {
        uint256 supply = totalSupply;
        if (amount > MAX_WRAPPED_SUPPLY - supply) revert SupplyCapExceeded();
        unchecked {
            totalSupply = supply + amount;
            balanceOf[recipient] += amount;
        }
        emit Transfer(address(0), recipient, amount);
    }

    function _burn(address sender, uint256 amount) private {
        uint256 balance = balanceOf[sender];
        if (balance < amount) revert ERC20InsufficientBalance(sender, balance, amount);
        unchecked {
            balanceOf[sender] = balance - amount;
            totalSupply -= amount;
        }
        emit Transfer(sender, address(0), amount);
    }

    function _transfer(address from, address to, uint256 value) private {
        if (from == address(0)) revert ERC20InvalidSender(address(0));
        if (to == address(0) || to == address(this)) revert ERC20InvalidReceiver(to);
        uint256 balance = balanceOf[from];
        if (balance < value) revert ERC20InsufficientBalance(from, balance, value);
        unchecked {
            balanceOf[from] = balance - value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
    }

    /// @dev `opCount` saturates at 2^64 − 1 (§5.1.1): it never wraps and never aborts a call.
    function _bumpOpCount() private {
        unchecked {
            // In 256 bits `opCount + 1` is at most 2^64, and bit 64 is set only there:
            // subtracting that bit leaves 2^64 − 1 at the bound and the sum below it.
            uint256 next = uint256(opCount) + 1;
            opCount = uint64(next - (next >> 64));
        }
    }

    // ---------------------------------------------------------------------
    // Profile and calldata helpers
    // ---------------------------------------------------------------------

    function _requireChain() private view {
        if (block.chainid != _identityWordOf(NETWORK_TAG)) revert WrongChain();
    }

    /// @dev The §2.1 identity word (the EVM chain id) of an admitted network tag.
    function _identityWordOf(uint8 tag) private pure returns (uint256) {
        return tag == TAG_ETHEREUM ? 1 : 56;
    }

    /// @dev SCCP domain of an admitted network tag (§3.2).
    function _domainOf(uint8 tag) private pure returns (uint256) {
        return tag == TAG_ETHEREUM ? 1 : 2;
    }

    /// @dev Left-aligned `route_id` text and its length (§2.3).
    function _routeIdOf(uint8 tag) private pure returns (bytes32 routeId, uint256 length) {
        if (tag == TAG_ETHEREUM) return ("taira_eth_xor", 13);
        return ("taira_bsc_xor", 13);
    }

    /// @dev Calldata offset of the first byte of `data`.
    function _offset(bytes calldata data) private pure returns (uint256 offset) {
        assembly ("memory-safe") {
            offset := data.offset
        }
    }

    /// @dev Big-endian unsigned integer of `width` (1..=32) bytes at calldata offset `offset`.
    function _be(uint256 offset, uint256 width) private pure returns (uint256 value) {
        assembly ("memory-safe") {
            value := shr(sub(256, mul(width, 8)), calldataload(offset))
        }
    }

    /// @dev The 48-byte big-endian value at calldata offset `offset` as its upper 16 bytes and
    /// its lower 32 bytes: the word pair of a 64-byte EIP-2537 field element.
    function _field(uint256 offset) private pure returns (uint256 hi, uint256 lo) {
        assembly ("memory-safe") {
            hi := shr(128, calldataload(offset))
            lo := calldataload(add(offset, 16))
        }
    }
}
