// SccpTairaXorMinter: TEP-74 Jetton master of Taira XOR on TON with the SCCP
// v1 bridge built in (specs/sccp.md §5.1, §5.3).
//
// There is no owner, admin, upgrade path or setter. The minter trusts one
// thing: a Sumeragi `CommitQC` of Taira's current committee generation over a
// finality header `X`, which is one BLS12-381 aggregate of exactly `q = n − f`
// signers whose keys the minter stores (§5.1.3). Certificates drive the
// committee state machine of §5.1.2 (checkpoints, `high`, rotations and the
// latch) and prove messages and control leaves. The minting pause changes
// only through `sccp_apply_control` / `sccp_apply_control_checkpoint` with a
// Taira control leaf (§5.1.6). The committee state is the current generation
// and three checkpoint slots: it does not grow with rotations.
// Replay flags live in `SccpConsumedBucket` children (512 nonces each), which
// the minter activates once per index (§5.3.4 step 2).
//
// Every asynchronous step either completes, bounces back to a handler that
// undoes its effect, or is recorded in `retries` for a permissionless
// `sccp_retry` (§5.3.4). External-out events are sent with bounce on action
// failure, so a failed event aborts and bounces the whole step.

import "@stdlib/gas-payments"
import "@stdlib/strings"
import "sccp-addresses"
import "sccp-cells"
import "sccp-constants"
import "sccp-crypto"
import "sccp-errors"
import "sccp-fees"
import "sccp-finality"
import "sccp-messages"
import "sccp-storage"
import "sccp-verify"

contract SccpTairaXorMinter {
    author: "Hyperledger Iroha"
    version: "1.0.0"
    description: "SCCP v1 Taira XOR Jetton master with the bridge built in (TEP-74, TEP-89)"
    storage: MinterStorage
    incomingMessages: MinterMessage
}

type MinterMessage =
    | SccpInit
    | SccpCheckpoint
    | SccpFinalize
    | SccpFinalizeCheckpoint
    | SccpVoidExpired
    | SccpVoidExpiredCheckpoint
    | SccpVoidFrozen
    | SccpApplyControl
    | SccpApplyControlCheckpoint
    | SccpDeployBuckets
    | SccpRetry
    | SccpConsumed
    | SccpAlreadyConsumed
    | SccpConsumeReverted
    | SccpRangeConsumed
    | SccpRangeRejected
    | BurnNotificationForMinter
    | TopUpTons
    | RequestWalletAddress

/// Outgoing messages whose bounces the minter handles (§5.3.4 steps 2, 6, 7).
type MinterBounce = SccpConsume | InternalTransferStep | SccpUnconsume | SccpActivateBucket

/// The certified header a finalize, void or control acts on (§5.1.3), with
/// what obtaining it changed. A stored checkpoint changes nothing.
struct ObtainedX {
    x: XHeader
    /// The signature was verified in this call, so `sccp_certificate` is due
    /// (§5.1.3 step 12). False on the cheap path and for a stored checkpoint.
    fullPath: bool
    /// `^Checkpoints` with the checkpoint of `x` recorded, so
    /// `sccp_checkpointed` is due; null when nothing was recorded.
    checkpoints: cell?
    /// The committee state with `high` raised to `x.height`; null when `high`
    /// did not rise.
    committee: Cell<CommitteeState>?
}

// ---------------------------------------------------------------------------
// Shared checks.

/// Obtains the certified header of a finalize, void or control (§5.1.2
/// "Which entry points may do what"). `source` is the `^TairaCert` of an
/// inline entry point or the `^CheckpointRef` of a `*_checkpoint` one.
///
/// Inline, in this order: `VerifyCertificate` as CUR with the keys from
/// storage (§5.1.3 steps 1–11); V1–V3, where a violation throws
/// `LatchRequired`, because only `sccp_checkpoint` latches; `Live`
/// (`Equivocated` when latched, `CommitteeNotAccepted` when expired). The
/// checkpoint is then recorded and `high` rises. A rotation installs no
/// successor here.
///
/// Checkpoint: the use check of §5.1.3 (`sccpUseCheckpoint`), which includes
/// `Live` and changes nothing.
fun obtainX(
    source: cell,
    isInline: bool,
    tairaNetworkId: int,
    instance: int,
    equivocated: bool,
    committee: CommitteeState,
    cps: Checkpoints,
    nowMs: int,
): ObtainedX {
    if (!isInline) {
        return {
            x: sccpUseCheckpoint(source, equivocated, committee, cps, nowMs),
            fullPath: false,
            checkpoints: null,
            committee: null,
        };
    }
    val verified = sccpVerifyCertificate(source, tairaNetworkId, instance, committee, cps);
    val x = verified.x;
    val (reason, _, _) = sccpViolation(x, committee, cps);
    assert (reason == 0) throw SccpErrors.LatchRequired;
    sccpRequireLive(equivocated, committee.untilMs, nowMs);
    var obtained: ObtainedX = {
        x,
        fullPath: verified.fullPath,
        checkpoints: null,
        committee: null,
    };
    var slots = cps;
    if (slots.insert(x.height, x.id)) {
        obtained.checkpoints = slots.toCell();
    }
    if (x.height > committee.high) {
        var raised = committee;
        raised.high = x.height;
        obtained.committee = raised.toCell();
    }
    return obtained;
}

/// Buckets a consume on bucket `idx` deploys: 0 when it exists, else
/// `idx − deployed + 1` up to `SCCP_MAX_DEPLOY_AHEAD` (§5.3.4 step 2).
fun bucketDeployCount(idx: int, deployed: int): int {
    if (idx < deployed) {
        return 0;
    }
    assert (idx < deployed + SCCP_MAX_DEPLOY_AHEAD) throw SccpErrors.BucketNotDeployed;
    return idx - deployed + 1;
}

/// Activates bucket `index` (bounceable, canonical StateInit attached): the
/// only message that makes a bucket accept flags (§5.3.4 step 2).
fun sendBucketActivation(minter: address, bucketCode: cell, index: int, queryId: int) {
    val activate = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        dest: sccpBucketDeployment(minter, index, bucketCode),
        value: sccpBucketActivationValue(),
        body: SccpActivateBucket { queryId, index },
    });
    activate.send(SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
}

/// Activates buckets `[first, end)`, in order.
fun sendBucketActivations(minter: address, bucketCode: cell, first: int, end: int, queryId: int) {
    var i = first;
    while (i < end) {
        sendBucketActivation(minter, bucketCode, i, queryId);
        i += 1;
    }
}

/// Sends `body` to bucket `idx` (never with a StateInit).
fun sendToBucket<TBody>(
    minter: address,
    bucketCode: cell,
    idx: int,
    body: TBody,
    value: coins,
    mode: int,
) {
    val toBucket = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        dest: sccpBucketAddress(minter, idx, bucketCode),
        value,
        body,
    });
    toBucket.send(mode);
}

/// Sends a bounceable `sccp_unconsume{nonce}` (§5.3.4 step 7); its bounce
/// records a retry.
fun sendUnconsume(minter: address, bucketCode: cell, nonce: int, mode: int) {
    sendToBucket(
        minter,
        bucketCode,
        nonce >> SCCP_BUCKET_SHIFT,
        SccpUnconsume { nonce },
        sccpUnconsumeValue(),
        mode,
    );
}

/// Emits an external-out event (§5.3.3). A failed event fails the action
/// phase and bounces the inbound message, so no step completes without it.
fun emitEvent<TBody>(body: TBody) {
    val event = createExternalLogMessage({ dest: createAddressNone(), body });
    event.send(SEND_MODE_REGULAR | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
}

/// Publishes a certificate that passed the full verification path (§5.1.3
/// step 12), whatever follows it: a checkpoint, a rotation, a latch or a use.
/// `cert` is the `^TairaCert` as it arrived. A step that later aborts drops
/// the event with its other effects.
fun emitCertificate(height: int, generation: int, cert: cell) {
    emitEvent(SccpCertificateEvent {
        height,
        generation,
        cert: cert as Cell<TairaCert>,
    });
}

/// Sends the events an obtained header owes, in the order of §5.1.3:
/// `sccp_certificate` after a full-path verification, then
/// `sccp_checkpointed` for a recorded checkpoint. `source` is the certificate
/// of the inline form; a stored checkpoint owes no event.
fun emitObtained(obtained: ObtainedX, source: cell) {
    val x = obtained.x;
    if (obtained.fullPath) {
        emitCertificate(x.height, x.generation, source);
    }
    if (obtained.checkpoints != null) {
        emitEvent(SccpCheckpointedEvent {
            height: x.height,
            id: x.id,
        });
    }
}

/// Returns everything above the reserved floor to `response` (TEP-74 excesses).
fun returnExcess(response: address, queryId: int) {
    val excess = createMessage({
        bounce: BounceMode.NoBounce,
        dest: response,
        value: 0,
        body: ReturnExcessesBack { queryId },
    });
    // SAFETY: every caller reserves the minter's floor or its prior balance
    // first (`sccpReserveMinterFloor`, `sccpReservePriorBalance`), so the
    // balance carried here is only the unspent part of the incoming value.
    excess.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_IGNORE_ERRORS);
}

// ---------------------------------------------------------------------------
// Finalize and void (§5.1.5, §5.1.8, §5.3.4 steps 1–2).

/// The minter step of `sccp_finalize*` (kind mint) and `sccp_void_expired*`
/// (kind void). `source` is the `^TairaCert` of the inline form or the
/// `^CheckpointRef` of the checkpoint form, and `message` the `^MessageProof`.
///
/// Checks, in this order (§5.1.2 "Check order and errors", §5.3.4 finalize
/// step 1); the first failure is the exit code:
///
/// 1. `initialized` (`NotInitialized`) and `GLOBALID` (`WrongChain`);
/// 2. the proof cell and the payload with its recipient (`BadSnake`,
///    `BadPayload`, `BadRecipient`), before `X`, because the required value
///    depends on the payload nonce;
/// 3. the bucket of the nonce is at most four past the deployed ones
///    (`BucketNotDeployed`);
/// 4. the entry value (`NotEnoughValue`), before any signature work;
/// 5. `X` and `Live` (`obtainX`);
/// 6. mint only: no effective pause (`MintingIsPaused`);
/// 7. the block reference (`BadSnake`, `BadProof`);
/// 8. the deadline (`DeadlinePassed` for a mint, `DeadlineNotReached` for a
///    void);
/// 9. the leaf path (`BadSnake`, `BadProof`);
/// 10. void only: `nonceArgument` is the payload nonce (`BadNonce`);
/// 11. mint only: the supply cap with the pending supply
///     (`SupplyCapExceeded`).
///
/// The step then reserves the pending supply of a mint, stores what an inline
/// certificate changed, activates the missing buckets and sends
/// `sccp_consume` to the bucket of the nonce. The bucket's reply completes or
/// refuses the step (`sccp_consumed`, `sccp_already_consumed`).
fun handleConsumeRequest(
    valueCoins: coins,
    kind: int,
    queryId: int,
    response: address,
    nonceArgument: int,
    source: cell,
    isInline: bool,
    message: cell,
) {
    var st = lazy MinterStorage.load();
    assert (st.initialized) throw SccpErrors.NotInitialized;
    assert (sccpGlobalId() == SCCP_TON_GLOBAL_ID) throw SccpErrors.WrongChain;
    val isMint = kind == SCCP_CONSUME_KIND_MINT;
    val config = st.config.load();
    val proof = sccpOpenMessageProof(message);
    val minter = contract.getAddress();
    val minterHash = minter.accountId();
    val payload = sccpParseInboundPayload(proof.payload, config.routeRevision, minterHash);
    val idx = payload.nonce >> SCCP_BUCKET_SHIFT;
    val deployed = st.deployedBuckets;
    val deployCount = bucketDeployCount(idx, deployed);
    val required = isMint
        ? sccpFinalizeRequiredValue(deployCount)
        : sccpVoidRequiredValue(deployCount);
    // §5.3.5: the value is checked before any signature is verified.
    sccpCheckEntryValue(valueCoins, required);

    val nowMs = sccpNowMs();
    val obtained = obtainX(
        source,
        isInline,
        config.tairaNetworkId,
        config.consensusInstance,
        st.equivocated,
        st.committee.load(),
        Checkpoints.load(st.checkpoints),
        nowMs,
    );
    if (isMint) {
        assert (
            !sccpEffectivePause(st.parliamentPaused, st.fastPauseUntilMs, nowMs)
        ) throw SccpErrors.MintingIsPaused;
    }
    val (sccpRoot, messageCount) = sccpCheckBlockRef(proof.block, obtained.x);
    if (isMint) {
        assert (nowMs <= payload.deadlineMs) throw SccpErrors.DeadlinePassed;
    } else {
        assert (nowMs > payload.deadlineMs) throw SccpErrors.DeadlineNotReached;
    }
    val messageId = sccpInboundMessageId(config.tairaNetworkId, payload.payloadHash);
    sccpVerifyLeaf(
        sccpTransferLeaf(messageId, minterHash),
        proof.leafIndex,
        proof.pathLen,
        proof.path,
        sccpRoot,
        messageCount,
    );
    if (!isMint) {
        // §5.1.8: after the leaf path and before the consumed set
        assert (nonceArgument == payload.nonce) throw SccpErrors.BadNonce;
    }

    var amount = 0;
    var recipient: address? = null;
    if (isMint) {
        amount = payload.amount;
        assert (
            st.totalSupply + st.pendingSupply + amount <= config.maxSupply
        ) throw SccpErrors.SupplyCapExceeded;
        st.pendingSupply += amount;
        recipient = address.fromWorkchainAndHash(SCCP_WORKCHAIN, payload.recipientHash);
    }
    if (deployCount > 0) {
        st.deployedBuckets = idx + 1;
    }
    // the checkpoint and the raised `high` of an inline certificate
    if (obtained.checkpoints != null) {
        st.checkpoints = obtained.checkpoints;
    }
    if (obtained.committee != null) {
        st.committee = obtained.committee;
    }
    st.save();

    sccpReserveMinterFloor(valueCoins, required);
    emitObtained(obtained, source);
    if (deployCount > 0) {
        sendBucketActivations(minter, config.bucketCode, deployed, idx + 1, queryId);
    }
    val tail: ConsumeTail = {
        kind,
        recipient,
        response,
        messageId,
    };
    sendToBucket(
        minter,
        config.bucketCode,
        idx,
        SccpConsume {
            queryId,
            nonce: payload.nonce,
            amount,
            tail: tail.toCell(),
        },
        0,
        SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_BOUNCE_ON_ACTION_FAIL,
    );
}

// ---------------------------------------------------------------------------
// Parliament and fast-pause controls (§5.1.6).

/// The minter step of `sccp_apply_control*`. `source` is the `^TairaCert` of
/// the inline form or the `^CheckpointRef` of the checkpoint form, and
/// `control` the `^ControlProof`. The step is permissionless and is not
/// blocked by the pause.
///
/// Checks, in this order; the first failure is the exit code:
///
/// 1. `initialized` (`NotInitialized`) and `GLOBALID` (`WrongChain`);
/// 2. the proof cell (`BadSnake`);
/// 3. the entry value (`NotEnoughValue`), before any signature work;
/// 4. `X` and `Live` (`obtainX`);
/// 5. the block reference (`BadSnake`, `BadProof`);
/// 6. the leaf path of the §3.4 control leaf, computed from the minter's own
///    network id, account id and revision and the supplied fields (`BadSnake`,
///    `BadProof`);
/// 7. the §3.4 constraints (`BadControl`);
/// 8. `control_nonce` above the stored one (`StaleControl`). Gaps are
///    allowed: only the newest control needs to be applied.
///
/// It then sets `parliament_paused`, the clamped `fast_pause_until_ms` and
/// `control_nonce`, counts the operation and emits `sccp_control_applied`.
fun handleApplyControl(
    valueCoins: coins,
    queryId: int,
    response: address,
    source: cell,
    isInline: bool,
    control: cell,
) {
    var st = lazy MinterStorage.load();
    assert (st.initialized) throw SccpErrors.NotInitialized;
    assert (sccpGlobalId() == SCCP_TON_GLOBAL_ID) throw SccpErrors.WrongChain;
    val proof = sccpOpenControlProof(control);
    val required = sccpApplyControlRequiredValue();
    // §5.3.5: the value is checked before any signature is verified.
    sccpCheckEntryValue(valueCoins, required);

    val nowMs = sccpNowMs();
    val config = st.config.load();
    val obtained = obtainX(
        source,
        isInline,
        config.tairaNetworkId,
        config.consensusInstance,
        st.equivocated,
        st.committee.load(),
        Checkpoints.load(st.checkpoints),
        nowMs,
    );
    val (sccpRoot, messageCount) = sccpCheckBlockRef(proof.block, obtained.x);
    sccpVerifyLeaf(
        sccpControlLeaf(
            config.tairaNetworkId,
            contract.getAddress().accountId(),
            config.routeRevision,
            proof.controlNonce,
            proof.track,
            proof.parliamentPaused,
            proof.fastPauseUntilMs,
            proof.certificateId,
            proof.effectHash,
        ),
        proof.leafIndex,
        proof.pathLen,
        proof.path,
        sccpRoot,
        messageCount,
    );
    sccpCheckControl(proof.track, proof.fastPauseUntilMs, proof.certificateId, proof.effectHash);
    assert (proof.controlNonce > st.controlNonce) throw SccpErrors.StaleControl;

    val fastPauseUntilMs = sccpAppliedFastPauseUntilMs(proof.fastPauseUntilMs, nowMs);
    st.parliamentPaused = proof.parliamentPaused;
    st.fastPauseUntilMs = fastPauseUntilMs;
    st.controlNonce = proof.controlNonce;
    st.opCount = sccpBumpedOpCount(st.opCount);
    // the checkpoint and the raised `high` of an inline certificate
    if (obtained.checkpoints != null) {
        st.checkpoints = obtained.checkpoints;
    }
    if (obtained.committee != null) {
        st.committee = obtained.committee;
    }
    st.save();

    sccpReserveMinterFloor(valueCoins, required);
    emitObtained(obtained, source);
    emitEvent(SccpControlAppliedEvent {
        controlNonce: proof.controlNonce,
        track: proof.track,
        parliamentPaused: proof.parliamentPaused,
        fastPauseUntilMs,
        certificateId: proof.certificateId,
    });
    returnExcess(response, queryId);
}

// ---------------------------------------------------------------------------
// Checkpoints and rotations (§5.1.2, §5.1.3).

/// The minter step of `sccp_checkpoint`: one certificate of
/// `submitCheckpoints`. It is permissionless, works while paused and does not
/// count toward `op_count`.
///
/// Checks, in this order; the first failure is the exit code:
///
/// 1. `initialized` (`NotInitialized`) and `GLOBALID` (`WrongChain`);
/// 2. the entry value (`NotEnoughValue`), before any signature work;
/// 3. `Live` (`Equivocated` when latched, `CommitteeNotAccepted` when
///    expired);
/// 4. `VerifyCertificate` as CUR with the keys from storage (§5.1.3 steps
///    1–11).
///
/// A violation V1–V3 then latches: `equivocated = true`, `cur.untilMs = 0`,
/// `sccp_latched`, and the excess returns to `response`. The latch is an
/// outcome and never throws; the keys of a successor are not read, so a
/// violating certificate latches whatever `nextKeys` holds.
///
/// Otherwise the updates of §5.1.2 apply: the checkpoint is recorded when its
/// height is absent and a slot takes it (`sccp_checkpointed`), `high` rises,
/// and a rotation installs the successor (`sccp_committee_rotated`). A
/// rotation to another root requires `nextKeys` with the keys of
/// `X.next_committee_root` (`BadCommittee`, `BadSnake`), which replace the
/// stored `KeyChunk` chain; a heartbeat keeps the chain and does not read
/// `nextKeys`. A successor that is already expired is installed all the same:
/// the state persists and the minter is `Frozen` from then on. A certificate
/// that changes nothing throws `NothingToDo`.
fun handleCheckpoint(
    valueCoins: coins,
    queryId: int,
    response: address,
    cert: cell,
    nextKeys: cell?,
) {
    var st = lazy MinterStorage.load();
    assert (st.initialized) throw SccpErrors.NotInitialized;
    assert (sccpGlobalId() == SCCP_TON_GLOBAL_ID) throw SccpErrors.WrongChain;
    val required = sccpCheckpointRequiredValue();
    // §5.3.5: the value is checked before any signature is verified.
    sccpCheckEntryValue(valueCoins, required);

    val nowMs = sccpNowMs();
    var committee = st.committee.load();
    sccpRequireLive(st.equivocated, committee.untilMs, nowMs);
    val config = st.config.load();
    var cps = Checkpoints.load(st.checkpoints);
    val verified = sccpVerifyCertificate(
        cert,
        config.tairaNetworkId,
        config.consensusInstance,
        committee,
        cps,
    );
    val x = verified.x;

    val (reason, a, b) = sccpViolation(x, committee, cps);
    if (reason != 0) {
        st.equivocated = true;
        committee.untilMs = 0;
        st.committee = committee.toCell();
        st.save();

        sccpReserveMinterFloor(valueCoins, required);
        if (verified.fullPath) {
            emitCertificate(x.height, x.generation, cert);
        }
        emitEvent(SccpLatchedEvent {
            reason,
            generation: x.generation,
            height: x.height,
            a,
            b,
        });
        returnExcess(response, queryId);
        return;
    }

    val recorded = cps.insert(x.height, x.id);
    var committeeChanged = false;
    if (x.height > committee.high) {
        committee.high = x.height;
        committeeChanged = true;
    }
    val isRotation = x.isRotation();
    if (isRotation) {
        // the successor's keys are checked only now, after V1–V3
        if (x.nextCommitteeRoot != committee.root) {
            committee.n = sccpRequireSuccessorKeys(nextKeys, x.nextCommitteeRoot);
            committee.keys = nextKeys!;
        }
        committee.root = x.nextCommitteeRoot;
        committee.untilMs = sccpRotationUntilMs(x, nowMs);
        // X6 bounds a rotation's height and generation by 2^64 − 2. No V3
        // fired, so `high` already is the handoff height; it is written as
        // §5.1.2 update 3 states the successor.
        committee.start = x.height + 1;
        committee.high = x.height;
        committee.generation = x.generation + 1;
        committeeChanged = true;
    }
    assert (recorded | committeeChanged) throw SccpErrors.NothingToDo;
    if (recorded) {
        st.checkpoints = cps.toCell();
    }
    if (committeeChanged) {
        st.committee = committee.toCell();
    }
    st.save();

    sccpReserveMinterFloor(valueCoins, required);
    if (verified.fullPath) {
        emitCertificate(x.height, x.generation, cert);
    }
    if (recorded) {
        emitEvent(SccpCheckpointedEvent {
            height: x.height,
            id: x.id,
        });
    }
    if (isRotation) {
        emitEvent(SccpCommitteeRotatedEvent {
            generation: committee.generation,
            root: committee.root,
            untilMs: committee.untilMs,
            start: committee.start,
        });
    }
    returnExcess(response, queryId);
}

// ---------------------------------------------------------------------------
// Message dispatch.

fun onInternalMessage(in: InMessage) {
    val msg = lazy MinterMessage.fromSlice(in.body);

    match (msg) {
        SccpCheckpoint => {
            handleCheckpoint(in.valueCoins, msg.queryId, msg.response, msg.cert, msg.nextKeys);
        }

        SccpFinalize => {
            handleConsumeRequest(
                in.valueCoins,
                SCCP_CONSUME_KIND_MINT,
                msg.queryId,
                msg.response,
                0,
                msg.cert,
                true,
                msg.message,
            );
        }

        SccpFinalizeCheckpoint => {
            handleConsumeRequest(
                in.valueCoins,
                SCCP_CONSUME_KIND_MINT,
                msg.queryId,
                msg.response,
                0,
                msg.ref,
                false,
                msg.message,
            );
        }

        SccpVoidExpired => {
            handleConsumeRequest(
                in.valueCoins,
                SCCP_CONSUME_KIND_VOID,
                msg.queryId,
                msg.response,
                msg.nonce,
                msg.cert,
                true,
                msg.message,
            );
        }

        SccpVoidExpiredCheckpoint => {
            handleConsumeRequest(
                in.valueCoins,
                SCCP_CONSUME_KIND_VOID,
                msg.queryId,
                msg.response,
                msg.nonce,
                msg.ref,
                false,
                msg.message,
            );
        }

        SccpApplyControl => {
            handleApplyControl(
                in.valueCoins,
                msg.queryId,
                msg.response,
                msg.cert,
                true,
                msg.control,
            );
        }

        SccpApplyControlCheckpoint => {
            handleApplyControl(
                in.valueCoins,
                msg.queryId,
                msg.response,
                msg.ref,
                false,
                msg.control,
            );
        }

        SccpConsumed => {
            var st = lazy MinterStorage.load();
            val config = st.config.load();
            val minter = contract.getAddress();
            val nonce = msg.nonce;
            assert (
                in.senderAddress ==
                sccpBucketAddress(minter, nonce >> SCCP_BUCKET_SHIFT, config.bucketCode)
            ) throw SccpErrors.NotBucket;
            val tail = msg.tail.load();
            // §5.3.4 step 4: the value was checked at entry and the floor was
            // topped up there, so this reply pays only its own step. Any
            // failure bounces to the bucket, which clears the flag and reports
            // `sccp_consume_reverted`.
            sccpReservePriorBalance(in.valueCoins);
            if (tail.kind == SCCP_CONSUME_KIND_MINT) {
                val amount = msg.amount as coins;
                st.pendingSupply -= amount;
                if (st.equivocated) {
                    // §5.3.4 item 6: the latch fired while this mint was in
                    // flight. Nothing is minted: the pending supply is
                    // released and the bucket clears the flag, so the nonce
                    // stays voidable through `sccp_void_frozen`. A bounced
                    // unconsume is recorded in `retries`. Expiry alone does
                    // not cancel a mint in flight.
                    st.save();
                    sendUnconsume(
                        minter,
                        config.bucketCode,
                        nonce,
                        SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_BOUNCE_ON_ACTION_FAIL,
                    );
                    returnExcess(tail.response, msg.queryId);
                    return;
                }
                st.totalSupply += amount;
                st.opCount = sccpBumpedOpCount(st.opCount);
                st.save();
                emitEvent(SccpFinalizedEvent {
                    messageId: tail.messageId,
                    nonce,
                });
                val mint = createMessage({
                    bounce: BounceMode.Only256BitsOfBody,
                    dest: sccpWalletDeployment(tail.recipient!, minter, config.walletCode),
                    value: 0,
                    body: InternalTransferStep {
                        queryId: nonce,
                        jettonAmount: amount,
                        transferInitiator: null,
                        sendExcessesTo: tail.response,
                        forwardTonAmount: 0,
                        forwardPayload: beginCell().storeUint(0, 1).toSlice(),
                    },
                });
                // SAFETY: `sccpReservePriorBalance` above kept the balance the
                // minter had before this reply, so the mint carries only
                // the value the reply brought.
                mint.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_BOUNCE_ON_ACTION_FAIL);
            } else {
                st.opCount = sccpBumpedOpCount(st.opCount);
                st.save();
                emitEvent(SccpVoidedEvent {
                    messageId: tail.messageId,
                    firstNonce: nonce,
                    count: 1,
                });
                returnExcess(tail.response, msg.queryId);
            }
        }

        SccpAlreadyConsumed => {
            var st = lazy MinterStorage.load();
            val config = st.config.load();
            val nonce = msg.nonce;
            assert (
                in.senderAddress ==
                sccpBucketAddress(
                    contract.getAddress(),
                    nonce >> SCCP_BUCKET_SHIFT,
                    config.bucketCode,
                )
            ) throw SccpErrors.NotBucket;
            // §5.3.4 step 5; a failure bounces to the bucket, which reports
            // `sccp_consume_reverted`.
            val tail = msg.tail.load();
            if (tail.kind == SCCP_CONSUME_KIND_MINT) {
                st.pendingSupply -= msg.amount;
                st.save();
            }
            sccpReservePriorBalance(in.valueCoins);
            returnExcess(tail.response, msg.queryId);
        }

        SccpConsumeReverted => {
            // §5.3.4 step 4: the minter bounced `sccp_consumed` or
            // `sccp_already_consumed`, so the pending amount was never moved.
            var st = lazy MinterStorage.load();
            val config = st.config.load();
            val nonce = msg.nonce;
            assert (
                in.senderAddress ==
                sccpBucketAddress(
                    contract.getAddress(),
                    nonce >> SCCP_BUCKET_SHIFT,
                    config.bucketCode,
                )
            ) throw SccpErrors.NotBucket;
            st.pendingSupply -= msg.amount;
            st.save();
        }

        SccpRangeConsumed => {
            var st = lazy MinterStorage.load();
            val config = st.config.load();
            val first = msg.first;
            assert (
                in.senderAddress ==
                sccpBucketAddress(
                    contract.getAddress(),
                    first >> SCCP_BUCKET_SHIFT,
                    config.bucketCode,
                )
            ) throw SccpErrors.NotBucket;
            st.opCount = sccpBumpedOpCount(st.opCount);
            st.save();
            // paid by the value attached to the range request; a failure
            // bounces and the bucket clears the range
            emitEvent(SccpVoidedEvent {
                messageId: 0,
                firstNonce: first,
                count: msg.count,
            });
        }

        SccpRangeRejected => {
            val st = lazy MinterStorage.load();
            val config = st.config.load();
            assert (
                in.senderAddress ==
                sccpBucketAddress(
                    contract.getAddress(),
                    msg.first >> SCCP_BUCKET_SHIFT,
                    config.bucketCode,
                )
            ) throw SccpErrors.NotBucket;
            // the value stays in the minter; the excess was returned at request time
        }

        SccpVoidFrozen => {
            // §5.1.8: the range is checked before `Frozen`.
            var st = lazy MinterStorage.load();
            assert (st.initialized) throw SccpErrors.NotInitialized;
            assert (sccpGlobalId() == SCCP_TON_GLOBAL_ID) throw SccpErrors.WrongChain;
            val first = msg.firstNonce;
            val count = msg.count;
            assert ((count >= 1) & (count <= SCCP_MAX_VOID_FROZEN_RANGE)) throw SccpErrors.BadRange;
            // One bucket. A bucket ends at a multiple of 512, so the last
            // nonce of a valid range is at most 2^64 − 1.
            val idx = first >> SCCP_BUCKET_SHIFT;
            assert (((first + count - 1) >> SCCP_BUCKET_SHIFT) == idx) throw SccpErrors.BadRange;
            // `Frozen`: latched or past `cur.untilMs`, permanently (§5.1.2)
            assert (
                !sccpIsLive(st.equivocated, st.committee.load().untilMs, sccpNowMs())
            ) throw SccpErrors.NotFrozen;
            val deployed = st.deployedBuckets;
            val deployCount = bucketDeployCount(idx, deployed);
            val required = sccpVoidFrozenRequiredValue(deployCount);
            sccpCheckEntryValue(in.valueCoins, required);
            if (deployCount > 0) {
                st.deployedBuckets = idx + 1;
                st.save();
            }
            val config = st.config.load();
            val minter = contract.getAddress();
            sccpReserveMinterFloor(in.valueCoins, required);
            if (deployCount > 0) {
                sendBucketActivations(minter, config.bucketCode, deployed, idx + 1, msg.queryId);
            }
            sendToBucket(
                minter,
                config.bucketCode,
                idx,
                SccpConsumeRange {
                    queryId: msg.queryId,
                    first,
                    count,
                },
                sccpRangeConsumeValue(),
                SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_BOUNCE_ON_ACTION_FAIL,
            );
            returnExcess(msg.response, msg.queryId);
        }

        SccpDeployBuckets => {
            var st = lazy MinterStorage.load();
            assert (st.initialized) throw SccpErrors.NotInitialized;
            assert (sccpGlobalId() == SCCP_TON_GLOBAL_ID) throw SccpErrors.WrongChain;
            val count = msg.count;
            assert (
                (count >= 1) & (count <= SCCP_MAX_DEPLOY_BUCKETS_PER_CALL)
            ) throw SccpErrors.BadRange;
            val required = sccpDeployBucketsRequiredValue(count);
            sccpCheckEntryValue(in.valueCoins, required);
            val first = st.deployedBuckets;
            st.deployedBuckets = first + count;
            st.save();
            val config = st.config.load();
            sccpReserveMinterFloor(in.valueCoins, required);
            sendBucketActivations(
                contract.getAddress(),
                config.bucketCode,
                first,
                first + count,
                msg.queryId,
            );
            returnExcess(msg.response, msg.queryId);
        }

        SccpRetry => {
            // §5.3.4: re-runs a recorded step whose message bounced. The entry
            // is removed before the resend and recorded again only if the
            // resend bounces, so each recorded step runs at most once.
            var st = lazy MinterStorage.load();
            assert (st.initialized) throw SccpErrors.NotInitialized;
            assert (sccpGlobalId() == SCCP_TON_GLOBAL_ID) throw SccpErrors.WrongChain;
            val required = sccpRetryRequiredValue();
            sccpCheckEntryValue(in.valueCoins, required);
            val nonce = msg.nonce;
            val entry = st.retries.get(nonce);
            assert (entry.isFound) throw SccpErrors.NothingToRetry;
            val kind = entry.loadValue();
            st.retries.delete(nonce);
            st.save();
            val config = st.config.load();
            val minter = contract.getAddress();
            sccpReserveMinterFloor(in.valueCoins, required);
            if (kind == SCCP_RETRY_ACTIVATE) {
                sendBucketActivation(
                    minter,
                    config.bucketCode,
                    nonce >> SCCP_BUCKET_SHIFT,
                    msg.queryId,
                );
            } else {
                sendUnconsume(
                    minter,
                    config.bucketCode,
                    nonce,
                    SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_BOUNCE_ON_ACTION_FAIL,
                );
            }
            returnExcess(msg.response, msg.queryId);
        }

        BurnNotificationForMinter => {
            var st = lazy MinterStorage.load();
            assert (st.initialized) throw SccpErrors.NotInitialized;
            assert (sccpGlobalId() == SCCP_TON_GLOBAL_ID) throw SccpErrors.WrongChain;
            val config = st.config.load();
            val owner = msg.burnInitiator;
            assert (
                in.senderAddress ==
                sccpWalletAddress(owner, contract.getAddress(), config.walletCode)
            ) throw SccpErrors.NotValidWallet;
            assert (sccpIsBasechainStd(owner)) throw SccpErrors.WrongWorkchain;
            val amount = msg.jettonAmount;
            assert ((amount > 0) & (amount < SCCP_TON_AMOUNT_LIMIT)) throw SccpErrors.BadAmount;
            val burn = msg.sccp.load();
            val (recipientChunks, recipientLen) = sccpParseSnakeBytes(
                burn.recipient,
                SCCP_MAX_TAIRA_ACCOUNT_BYTES,
                SccpErrors.BadRecipient,
            );

            // §5.1.7: source nonces are 0 ..= 2^64 − 2. An exhausted counter
            // throws `BadNonce` here, before any state change, and the bounce
            // of `burn_notification` restores the wallet balance.
            val nonce = st.outboundNonce;
            val nextNonce = sccpNextOutboundNonce(nonce);
            val payload = sccpBuildOutboundPayload(
                nonce,
                config.routeRevision,
                amount,
                owner.accountId(),
                recipientChunks,
                recipientLen,
            );
            val messageId = sccpOutboundMessageId(config.tairaNetworkId, payload.payloadHash);
            st.totalSupply -= amount;
            st.outboundNonce = nextNonce;
            st.opCount = sccpBumpedOpCount(st.opCount);
            st.save();

            // §5.3.5: a burn never pays toward the minter floor, and a failed
            // event bounces `burn_notification`, which restores the wallet.
            sccpReservePriorBalance(in.valueCoins);
            emitEvent(SccpTransferToTairaEvent {
                messageId,
                nonce,
                sender: owner,
                amount,
                payload: payload.cell,
            });
            if (msg.sendExcessesTo != null) {
                returnExcess(msg.sendExcessesTo, msg.queryId);
            }
        }

        SccpInit => {
            // §5.3.1: completes the deployment, once and for anyone. Taira
            // recomputes the minter address from the canonical initial data
            // (§4.14.3 P3); these checks hold the deployed data to it.
            var st = MinterStorage.load();
            assert (!st.initialized) throw SccpErrors.AlreadyInitialized;
            assert (sccpGlobalId() == SCCP_TON_GLOBAL_ID) throw SccpErrors.WrongChain;
            // Canonical initial data: no latch, zero counters and supplies,
            // no pause, no bucket, no checkpoint and no retry.
            assert (
                (!st.equivocated) & (st.totalSupply == 0) & (st.pendingSupply == 0) &
                (st.outboundNonce == 0) &
                (st.opCount == 0) &
                (st.controlNonce == 0) &
                (!st.parliamentPaused) &
                (st.fastPauseUntilMs == 0) &
                (st.deployedBuckets == 0) &
                Checkpoints.isCanonicalEmpty(st.checkpoints) &
                st.retries.isEmpty()
            ) throw SccpErrors.BadConfig;
            // A deployable configuration and pin (§5.1.1).
            val config = st.config.load();
            val pin = config.initial.load();
            assert (
                (config.tairaNetworkId != 0) & (config.consensusInstance != 0) &
                (config.routeRevision != 0) &
                (config.maxSupply != 0) &
                (pin.generation >= 1) &
                (pin.root != 0) &
                (pin.start >= 1)
            ) throw SccpErrors.BadConfig;
            // The stored keys are the committee of the pinned root: a valid
            // `n`, the canonical ordinary `KeyChunk` list (`BadSnake`),
            // strictly ascending keys and their keccak root.
            val committee = st.committee.load();
            assert (committee.root == pin.root) throw SccpErrors.BadCommittee;
            sccpRequireStoredCommittee(committee.keys, committee.n, pin.root);
            // The remaining committee fields are the pin, with `high = start − 1`.
            assert (
                (committee.generation == pin.generation) & (committee.start == pin.start) &
                (committee.high == pin.start - 1) &
                (committee.untilMs == pin.untilMs)
            ) throw SccpErrors.BadConfig;
            // `now_ms < until_ms ≤ now_ms + MAX_VALIDITY_MS + MAX_INIT_SLACK_MS`
            assert (sccpInitUntilMsIsValid(sccpNowMs(), pin.untilMs)) throw SccpErrors.BadConfig;
            st.initialized = true;
            st.save();
        }

        RequestWalletAddress => {
            val st = lazy MinterStorage.load();
            val config = st.config.load();
            val ownerAddress: Cell<address>? = msg.includeOwnerAddress
                ? msg.ownerAddress.toCell()
                : null;
            var walletAddress: address? = null;
            if (sccpIsBasechainStd(msg.ownerAddress)) {
                walletAddress = sccpWalletAddress(
                    msg.ownerAddress,
                    contract.getAddress(),
                    config.walletCode,
                );
            }
            val respondMsg = createMessage({
                bounce: BounceMode.NoBounce,
                dest: in.senderAddress,
                value: 0,
                body: ResponseWalletAddress {
                    queryId: msg.queryId,
                    jettonWalletAddress: walletAddress,
                    ownerAddress,
                },
            });
            respondMsg.send(
                SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE | SEND_MODE_BOUNCE_ON_ACTION_FAIL,
            );
        }

        TopUpTons => {
            // anyone may add to the minter floor (§5.3.5)
        }

        else => {
            assert (in.body.isEmpty()) throw SccpErrors.InvalidMessage;
        }
    }
}

/// Records `kind` for `key` in `retries` (§5.3.4).
fun MinterStorage.recordRetry(mutate self, key: int, kind: int) {
    self.retries.set(key, kind);
}

/// §5.3.4 step 6 (bounced `sccp_consume`: release the pending supply; the
/// value stays), step 7 (bounced `internal_transfer`: burn the unminted supply
/// and ask the bucket to clear the flag, so the message becomes finalizable
/// again) and the recorded retries: a bounced `sccp_unconsume` or
/// `sccp_activate_bucket` changed nothing at the bucket, so the step is
/// recorded for `sccp_retry`.
fun onBouncedMessage(in: InMessageBounced) {
    // A bounce may carry little value. Only the network sets the bounced flag,
    // and only for a message the minter sent, so the minter pays this handler.
    setGasLimitToMaximum();
    in.bouncedBody.skipBouncedPrefix();
    val msg = lazy MinterBounce.fromSlice(in.bouncedBody);

    match (msg) {
        SccpConsume => {
            var st = lazy MinterStorage.load();
            val config = st.config.load();
            val nonce = msg.nonce;
            assert (
                in.senderAddress ==
                sccpBucketAddress(
                    contract.getAddress(),
                    nonce >> SCCP_BUCKET_SHIFT,
                    config.bucketCode,
                )
            ) throw SccpErrors.NotBucket;
            st.pendingSupply -= msg.amount;
            st.save();
        }
        InternalTransferStep => {
            // Only the network sets the bounced flag, so this is a mint the
            // minter sent to a canonical wallet (`query_id = nonce`).
            var st = lazy MinterStorage.load();
            val config = st.config.load();
            val nonce = msg.queryId;
            st.totalSupply -= msg.jettonAmount;
            // The bounce handler cannot bounce: send the unconsume only when the
            // balance surely pays it, and otherwise record it for `sccp_retry`.
            if (
                contract.getOriginalBalance() >=
                sccpUnconsumeCost() + sccpGasFee(SCCP_GAS_MINTER_BOUNCE)
            ) {
                sendUnconsume(
                    contract.getAddress(),
                    config.bucketCode,
                    nonce,
                    SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_IGNORE_ERRORS,
                );
            } else {
                st.recordRetry(nonce, SCCP_RETRY_UNCONSUME);
            }
            st.save();
        }
        SccpUnconsume => {
            var st = lazy MinterStorage.load();
            val config = st.config.load();
            val nonce = msg.nonce;
            assert (
                in.senderAddress ==
                sccpBucketAddress(
                    contract.getAddress(),
                    nonce >> SCCP_BUCKET_SHIFT,
                    config.bucketCode,
                )
            ) throw SccpErrors.NotBucket;
            st.recordRetry(nonce, SCCP_RETRY_UNCONSUME);
            st.save();
        }
        SccpActivateBucket => {
            var st = lazy MinterStorage.load();
            val config = st.config.load();
            val index = msg.index;
            assert (
                in.senderAddress ==
                sccpBucketAddress(contract.getAddress(), index, config.bucketCode)
            ) throw SccpErrors.NotBucket;
            st.recordRetry(index << SCCP_BUCKET_SHIFT, SCCP_RETRY_ACTIVATE);
            st.save();
        }
        else => {
            // range requests, reverted reports and excess returns: the value stays
        }
    }
}

// ---------------------------------------------------------------------------
// Get methods (§5.3.6).

/// TEP-64 on-chain content built at run time from constants (§5.3.1).
fun buildJettonContent(): Cell<OnchainMetadataReply> {
    var metadata: OnchainMetadataReply = { contentDict: [] };
    metadata.contentDict.set("name".sha256(), "Taira XOR".prefixWith00());
    metadata.contentDict.set("symbol".sha256(), "tXOR".prefixWith00());
    metadata.contentDict.set("decimals".sha256(), "9".prefixWith00());
    return metadata.toCell();
}

get fun get_jetton_data(): JettonDataReply {
    val st = lazy MinterStorage.load();
    val config = st.config.load();
    return {
        totalSupply: st.totalSupply,
        mintable: true,
        adminAddress: null,
        jettonContent: buildJettonContent(),
        jettonWalletCode: config.walletCode,
    };
}

get fun get_wallet_address(ownerAddress: address): address {
    val st = lazy MinterStorage.load();
    val config = st.config.load();
    return sccpWalletAddress(ownerAddress, contract.getAddress(), config.walletCode);
}

/// The bridge state in the order of §5.3.6. `effectivePaused` is the pause
/// at the time of the call: `parliamentPaused ∨ now_ms < fastPauseUntilMs`.
get fun get_sccp_state(): SccpStateReply {
    val st = MinterStorage.load();
    val config = st.config.load();
    val pin = config.initial.load();
    val committee = st.committee.load();
    return {
        initialized: st.initialized,
        equivocated: st.equivocated,
        tairaNetworkId: config.tairaNetworkId,
        consensusInstance: config.consensusInstance,
        routeRevision: config.routeRevision,
        initialGeneration: pin.generation,
        initialRoot: pin.root,
        initialStart: pin.start,
        initialUntilMs: pin.untilMs,
        root: committee.root,
        untilMs: committee.untilMs,
        start: committee.start,
        high: committee.high,
        generation: committee.generation,
        outboundNonce: st.outboundNonce,
        opCount: st.opCount,
        parliamentPaused: st.parliamentPaused,
        fastPauseUntilMs: st.fastPauseUntilMs,
        effectivePaused: sccpEffectivePause(st.parliamentPaused, st.fastPauseUntilMs, sccpNowMs()),
        controlNonce: st.controlNonce,
        totalSupply: st.totalSupply,
        pendingSupply: st.pendingSupply,
        maxSupply: config.maxSupply,
        deployedBuckets: st.deployedBuckets,
    };
}

/// The current committee generation `cur` with its `^KeyChunk` list of `n`
/// compressed keys in canonical order (§5.1.1). A latch shows as `untilMs = 0`
/// with `equivocated` set in `get_sccp_state`.
get fun get_sccp_committee(): SccpCommitteeReply {
    val st = lazy MinterStorage.load();
    val committee = st.committee.load();
    return {
        root: committee.root,
        untilMs: committee.untilMs,
        start: committee.start,
        high: committee.high,
        generation: committee.generation,
        n: committee.n,
        keys: committee.keys,
    };
}

/// The stored checkpoints (§5.1.3): `count` slots `(height, keccak256(X))` in
/// ascending height order, unused slots zero. A `*_checkpoint` message names
/// one of them by its `X`.
get fun get_sccp_checkpoints(): SccpCheckpointsReply {
    val st = lazy MinterStorage.load();
    val cps = Checkpoints.load(st.checkpoints);
    return {
        count: cps.count,
        height0: cps.h0,
        id0: cps.id0,
        height1: cps.h1,
        id1: cps.id1,
        height2: cps.h2,
        id2: cps.id2,
    };
}

get fun get_bucket_address(index: int): address {
    val st = lazy MinterStorage.load();
    val config = st.config.load();
    return sccpBucketAddress(contract.getAddress(), index, config.bucketCode);
}

/// Deploy count a consume of `nonce` would need now (at most 4 ahead).
fun deployCountForNonce(nonce: int): int {
    val st = lazy MinterStorage.load();
    return bucketDeployCount(nonce >> SCCP_BUCKET_SHIFT, st.deployedBuckets);
}

/// `finalize_required_value()` for the message with outbound `nonce` (§5.3.5).
get fun finalize_required_value(nonce: int): int {
    return sccpMinterQuote(sccpFinalizeRequiredValue(deployCountForNonce(nonce)));
}

/// `void_required_value()` for the message with outbound `nonce` (§5.3.5).
get fun void_required_value(nonce: int): int {
    return sccpMinterQuote(sccpVoidRequiredValue(deployCountForNonce(nonce)));
}

/// Required value of `sccp_void_frozen` starting at `firstNonce`.
get fun void_frozen_required_value(firstNonce: int): int {
    return sccpMinterQuote(sccpVoidFrozenRequiredValue(deployCountForNonce(firstNonce)));
}

/// Required value of `sccp_deploy_buckets` for `count` buckets.
get fun deploy_buckets_required_value(count: int): int {
    return sccpMinterQuote(sccpDeployBucketsRequiredValue(count));
}

/// Required value of `sccp_apply_control` and `sccp_apply_control_checkpoint`.
get fun apply_control_required_value(): int {
    return sccpMinterQuote(sccpApplyControlRequiredValue());
}

/// Required value of one `sccp_checkpoint`, with or without `next_keys`.
get fun checkpoint_required_value(): int {
    return sccpMinterQuote(sccpCheckpointRequiredValue());
}

/// Required value of `sccp_retry`.
get fun retry_required_value(): int {
    return sccpMinterQuote(sccpRetryRequiredValue());
}

/// `MINTER_FLOOR` at current prices (§5.3.5).
get fun minter_floor(): int {
    return sccpMinterFloor();
}

/// The retry recorded for `nonce`: 0 (none), `SCCP_RETRY_UNCONSUME` (1) or
/// `SCCP_RETRY_ACTIVATE` (2, key = first nonce of the bucket).
get fun get_sccp_retry(nonce: int): int {
    val st = lazy MinterStorage.load();
    val entry = st.retries.get(nonce);
    return entry.isFound ? entry.loadValue() : 0;
}
