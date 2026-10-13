// TON→Taira burns (specs/sccp.md §5.1.7, §5.3.4 "Burn"): the SCCP custom
// payload is mandatory, the minter builds the §3.2 payload with a sequential
// source nonce and emits `sccp_transfer_to_taira`, and every rejection (a
// plain burn, the recipient length or shape, the owner's workchain, a foreign
// wallet, another chain, exhausted source nonces) restores the balance.
// Burns need no `Live` generation and are never paused. The two counter
// bounds of §5.1.2 are reached by storage injection: `opCount` saturates at
// 2^64 − 1, and a stored `outbound_nonce` of 2^64 − 1 answers `BadNonce`.

import "@stdlib/exotic-cells"
import "@acton/build"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@contracts/sccp-addresses"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// TON→Taira rows of `directions` in `payload_v1.json` that this suite burns.
const PINNED_OUTBOUND_PAYLOAD_VECTORS = 1

/// Sets `GLOBALID` of the emulated chain (config parameter 19).
fun setGlobalId(id: int) {
    var config = testing.getConfig();
    config.setParamRaw(19, beginCell().storeInt(id, 32).endCell());
    expect(testing.setConfig(config)).toBeTrue();
}

/// Expects a burn of `owner` that the minter refused with `exitCode`: the
/// notification bounced, the wallet holds `balance` again, and the minter
/// emitted nothing.
fun expectBurnRefused(env: Env, res: SendResultList, owner: address, exitCode: int, balance: int) {
    expect(res).toHaveFailedTx<BurnNotificationForMinter>({ to: env.minter.address, exitCode });
    expect(res).toHaveBouncedTx({ to: walletOf(env, owner).address });
    expect(
        res.findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address }) == null,
    ).toBeTrue();
    expect(jettonBalanceOf(env, owner)).toEqual(balance);
}

/// Expected `(payload cell hash, message id)` of a burn.
fun expectedBurn(env: Env, nonce: int, amount: int, owner: address, recipient: cell): (int, int) {
    val (chunks, len) = sccpParseSnakeBytes(
        recipient,
        SCCP_MAX_TAIRA_ACCOUNT_BYTES,
        SccpErrors.BadRecipient,
    );
    val payload = sccpBuildOutboundPayload(
        nonce,
        TEST_REVISION,
        amount,
        owner.accountId(),
        chunks,
        len,
    );
    return (payload.cell.hash(), sccpOutboundMessageId(env.networkId, payload.payloadHash));
}

get fun `test burn emits the transfer event with a sequential nonce`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 10000, alice);
    val recipient = snakeFromPieces(vecOutboundRecipientPieces());
    val res = sendBurn(env, alice, 2500, recipient, burnValue(env, alice));
    expect(res).toHaveSuccessfulTx<AskToBurn>({ to: walletOf(env, alice).address });
    expect(res).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: alice });
    val event = res
        .findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address })!
        .loadBody();
    val (payloadHash, messageId) = expectedBurn(env, 0, 2500, alice, recipient);
    expect(event.messageId).toEqual(messageId);
    expect(event.nonce).toEqual(0);
    expect(event.sender).toEqual(alice);
    expect(event.amount).toEqual(2500);
    expect(event.payload.hash()).toEqual(payloadHash);
    // sccp_transfer_to_taira#53435454 message_id:uint256 nonce:uint64
    // sender:MsgAddressInt amount:Coins payload:^SnakeBytes (§5.3.3), and no
    // other event
    val body = SccpTransferToTairaEvent {
        messageId,
        nonce: 0,
        sender: alice,
        amount: 2500,
        payload: event.payload,
    }.toCell();
    expectEvents(res, [body]);
    val raw = body.beginParse();
    expect(raw.preloadUint(32)).toEqual(0x53435454);
    expect(raw.remainingBitsCount()).toEqual(32 + 256 + 64 + 267 + 4 + 16);
    expect(raw.remainingRefsCount()).toEqual(1);
    expect(jettonBalanceOf(env, alice)).toEqual(7500);
    var state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(7500);
    expect(state.outboundNonce).toEqual(1);
    expect(state.opCount).toEqual(2);
    // the next burn takes nonce 1
    val second = sendBurn(env, alice, 500, recipient, burnValue(env, alice));
    val event2 = second
        .findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event2.nonce).toEqual(1);
    expect(event2.messageId).toEqual(expectedBurn(env, 1, 500, alice, recipient).1);
    state = env.minter.getSccpState();
    expect(state.outboundNonce).toEqual(2);
    expect(state.totalSupply).toEqual(7000);
}

get fun `test maximal recipient and payload`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 10, alice);
    val recipient = snakeOfLength(1024);
    val res = sendBurn(env, alice, 10, recipient, burnValue(env, alice));
    expect(res).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    val event = res
        .findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.payload.hash()).toEqual(expectedBurn(env, 0, 10, alice, recipient).0);
    val (_, len) = sccpParseSnakeBytes(
        event.payload,
        SCCP_MAX_PAYLOAD_BYTES,
        SccpErrors.BadPayload,
    );
    expect(len).toEqual(1138);
    expect(jettonBalanceOf(env, alice)).toEqual(0);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(0);
    expect(state.outboundNonce).toEqual(1);
    expect(state.opCount).toEqual(2);
}

get fun `test the TON to Taira payload vector of the fixture is what a burn emits`() {
    // `directions` of `payload_v1.json` holds one payload of this lane: a burn
    // of the largest amount by the owner `VEC_OUTBOUND_SENDER` on the minter
    // of revision 2, with source nonce 5
    var replayed = 0;
    testing.setNow(T0);
    val deployer = testing.treasury("deployer").address;
    val committee = testCommittee(4, 0);
    val env: Env = {
        minter: deployPinned(
            canonicalStorage(
                VEC_NETWORK_ID,
                VEC_CONSENSUS_INSTANCE,
                VEC_OUTBOUND_REVISION,
                SCCP_TON_AMOUNT_LIMIT,
                defaultPin(committee),
                committee.keys,
            ),
            deployer,
            grams("10"),
        ),
        deployer,
        networkId: VEC_NETWORK_ID,
        instance: VEC_CONSENSUS_INSTANCE,
        generation: TEST_GENERATION,
        committee,
    };
    val owner = address.fromWorkchainAndHash(BASECHAIN, VEC_OUTBOUND_SENDER);
    // the owner holds the amount: a mint under the same revision
    val minted = inboundPayloadCell(
        0,
        VEC_OUTBOUND_REVISION,
        T0 * 1000 + DAY_MS,
        VEC_OUTBOUND_AMOUNT,
        VEC_OUTBOUND_SENDER,
    );
    val parsed = sccpParseInboundPayload(
        minted,
        VEC_OUTBOUND_REVISION,
        env.minter.address.accountId(),
    );
    val leaf = sccpTransferLeaf(
        sccpInboundMessageId(env.networkId, parsed.payloadHash),
        env.minter.address.accountId(),
    );
    val x = blockX(env.networkId, env.generation, committee.root(), TEST_START_HEIGHT + 10, [leaf]);
    val mint = sendFinalizeCells(
        env,
        deployer,
        certifyFor(env, committee, x),
        null,
        messageProofCell(0, [], minted, ownBlockRef(x)),
        finalizeValue(env, 0),
    );
    expect(mint).toHaveSuccessfulTx<SccpConsumed>({ to: env.minter.address });
    expect(jettonBalanceOf(env, owner)).toEqual(VEC_OUTBOUND_AMOUNT);
    // the source nonce of the row (storage injection)
    var st = minterStorage(env);
    st.outboundNonce = VEC_OUTBOUND_NONCE;
    setMinterStorage(env, st);

    val recipient = snakeFromPieces(vecOutboundRecipientPieces());
    val res = sendBurn(env, owner, VEC_OUTBOUND_AMOUNT, recipient, burnValue(env, owner));
    expect(res).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    val event = res
        .findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.messageId).toEqual(VEC_OUTBOUND_MESSAGE_ID);
    expect(event.nonce).toEqual(VEC_OUTBOUND_NONCE);
    expect(event.sender).toEqual(owner);
    expect(event.amount).toEqual(VEC_OUTBOUND_AMOUNT);
    // the payload cell is the snake of the fixture's bytes, and hashes to its hash
    expect(event.payload.hash()).toEqual(snakeFromPieces(vecOutboundPayloadPieces()).hash());
    val (chunks, _) = sccpParseSnakeBytes(
        event.payload,
        SCCP_MAX_PAYLOAD_BYTES,
        SccpErrors.BadPayload,
    );
    expect(sccpPayloadHash(chunks as tuple)).toEqual(VEC_OUTBOUND_PAYLOAD_HASH);
    expect(jettonBalanceOf(env, owner)).toEqual(0);
    val state = env.minter.getSccpState();
    expect(state.outboundNonce).toEqual(VEC_OUTBOUND_NONCE + 1);
    expect(state.totalSupply).toEqual(0);
    replayed += 1;
    expect(replayed).toEqual(PINNED_OUTBOUND_PAYLOAD_VECTORS);
}

get fun `test plain burns and foreign custom payloads are rejected by the wallet`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    val wallet = walletOf(env, alice);
    val plain = wallet.sendAskToBurn(
        alice,
        1,
        10,
        alice,
        null,
        { value: burnValue(env, alice), bounce: true },
    );
    expect(
        plain,
    ).toHaveFailedTx<AskToBurn>({ to: wallet.address, exitCode: SccpErrors.BadBurnPayload as int });
    val foreign = wallet.sendAskToBurn(
        alice,
        1,
        10,
        alice,
        beginCell().storeUint(0x12345678, 32).storeRef(snakeOfLength(4)).endCell(),
        { value: burnValue(env, alice), bounce: true },
    );
    expect(
        foreign,
    ).toHaveFailedTx<AskToBurn>({ to: wallet.address, exitCode: SccpErrors.BadBurnPayload as int });
    val trailing = wallet.sendAskToBurn(
        alice,
        1,
        10,
        alice,
        beginCell().storeUint(0x53434254, 32).storeRef(snakeOfLength(4)).storeUint(1, 1).endCell(),
        { value: burnValue(env, alice), bounce: true },
    );
    expect(
        trailing,
    ).toHaveFailedTx<AskToBurn>({ to: wallet.address, exitCode: SccpErrors.BadSnake as int });
    val zero = sendBurn(env, alice, 0, snakeOfLength(4), burnValue(env, alice));
    expect(
        zero,
    ).toHaveFailedTx<AskToBurn>({ to: wallet.address, exitCode: SccpErrors.BadAmount as int });
    val poor = sendBurn(env, alice, 10, snakeOfLength(4), burnValue(env, alice) - 1);
    expect(
        poor,
    ).toHaveFailedTx<AskToBurn>({ to: wallet.address, exitCode: SccpErrors.NotEnoughValue as int });
    val stranger = testing.treasury("stranger").address;
    val notOwner = wallet.sendAskToBurn(
        stranger,
        1,
        10,
        stranger,
        (SccpBurnToTaira { recipient: snakeOfLength(4) }).toCell(),
        { value: burnValue(env, alice), bounce: true },
    );
    expect(
        notOwner,
    ).toHaveFailedTx<AskToBurn>({ to: wallet.address, exitCode: SccpErrors.NotOwner as int });
    expect(jettonBalanceOf(env, alice)).toEqual(100);
}

get fun `test malformed recipients are refused before the wallet debits or forwards`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    // a published library with a canonical recipient is still not canonical
    testing.registerLibrary(snakeOfLength(4));
    val recipients: array<[cell, int]> = [
        [snakeOfLength(1025), SccpErrors.BadRecipient as int],
        [snakeOfLength(12700), SccpErrors.BadRecipient as int],
        // no recipient byte at all
        [beginCell().endCell(), SccpErrors.BadSnake as int],
        [beginCell().storeUint(1, 4).endCell(), SccpErrors.BadSnake as int],
        [
            beginCell().storeUint(0xAB, 8).storeRef(snakeOfLength(3)).endCell(),
            SccpErrors.BadSnake as int,
        ],
        [snakeOfLength(4).toLibraryReference(), SccpErrors.BadSnake as int],
    ];
    var i = 0;
    while (i < recipients.size()) {
        val [recipient, code] = recipients.get(i);
        val res = sendBurn(env, alice, 30, recipient, burnValue(env, alice));
        expect(res).toHaveFailedTx<AskToBurn>({ to: walletOf(env, alice).address, exitCode: code });
        expect(
            res.findTransaction<BurnNotificationForMinter>({ to: env.minter.address }) == null,
        ).toBeTrue();
        expect(jettonBalanceOf(env, alice)).toEqual(100);
        // The minter independently enforces the same rule, even with its
        // authenticated sender forged by the emulator. No bounce is requested
        // because this direct notification never debited the wallet.
        val forged = net.send(
            walletOf(env, alice).address,
            createMessage({
                bounce: BounceMode.NoBounce,
                dest: env.minter.address,
                value: grams("1"),
                body: BurnNotificationForMinter {
                    queryId: 0,
                    jettonAmount: 30,
                    burnInitiator: alice,
                    sendExcessesTo: alice,
                    sccp: SccpBurnToTaira { recipient }.toCell(),
                },
            }),
        );
        expect(forged).toHaveFailedTx<BurnNotificationForMinter>({ to: env
                .minter
                .address, exitCode: code });
        i += 1;
    }
    val state = env.minter.getSccpState();
    expect(state.outboundNonce).toEqual(0);
    expect(state.totalSupply).toEqual(100);
    expect(state.opCount).toEqual(1);
}

get fun `test burn wrappers must be exact ordinary cells at both boundaries`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    val wallet = walletOf(env, alice);
    val canonical = SccpBurnToTaira { recipient: snakeOfLength(4) }.toCell();
    testing.registerLibrary(canonical);
    val wrappers: array<[cell, int]> = [
        [canonical.toLibraryReference(), SccpErrors.BadSnake as int],
        [
            SccpBurnToTaira { recipient: snakeOfLength(5) }.toCell().toLibraryReference(),
            SccpErrors.BadSnake as int,
        ],
        [beginCell().storeUint(0x53434254, 32).endCell(), SccpErrors.BadSnake as int],
        [
            beginCell()
                .storeUint(0x53434254, 32)
                .storeRef(snakeOfLength(4))
                .storeRef(snakeOfLength(4))
                .endCell(),
            SccpErrors.BadSnake as int,
        ],
        [
            beginCell()
                .storeUint(0x53434254, 32)
                .storeUint(0, 1)
                .storeRef(snakeOfLength(4))
                .endCell(),
            SccpErrors.BadSnake as int,
        ],
        [
            beginCell().storeUint(0x12345678, 32).storeRef(snakeOfLength(4)).endCell(),
            SccpErrors.BadBurnPayload as int,
        ],
    ];
    var i = 0;
    repeat (wrappers.size()) {
        val [wrapper, code] = wrappers.get(i);
        val sent = wallet.sendAskToBurn(
            alice,
            0,
            30,
            alice,
            wrapper,
            { value: burnValue(env, alice), bounce: true },
        );
        expect(sent).toHaveFailedTx<AskToBurn>({ to: wallet.address, exitCode: code });
        expect(
            sent.findTransaction<BurnNotificationForMinter>({ to: env.minter.address }) == null,
        ).toBeTrue();
        expect(jettonBalanceOf(env, alice)).toEqual(100);
        val forged = net.send(
            wallet.address,
            createMessage({
                bounce: BounceMode.NoBounce,
                dest: env.minter.address,
                value: grams("1"),
                body: BurnNotificationForMinter {
                    queryId: 0,
                    jettonAmount: 30,
                    burnInitiator: alice,
                    sendExcessesTo: alice,
                    sccp: wrapper as Cell<SccpBurnToTaira>,
                },
            }),
        );
        expect(forged).toHaveFailedTx<BurnNotificationForMinter>({ to: env
                .minter
                .address, exitCode: code });
        expect(
            forged.findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address }) ==
                null,
        ).toBeTrue();
        i += 1;
    }
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(100);
    expect(state.outboundNonce).toEqual(0);
    expect(state.opCount).toEqual(1);
}

get fun `test owners outside workchain 0 cannot burn`() {
    val env = setupEnv();
    val owner = testing.treasury("master-owner", MASTERCHAIN).address;
    val wallet = walletOf(env, owner);
    // credit the canonical wallet of a masterchain owner (only possible by
    // forging the minter as sender in the emulator)
    val credit = net.send(
        env.minter.address,
        createMessage({
            bounce: BounceMode.NoBounce,
            value: grams("1"),
            dest: sccpWalletDeployment(owner, env.minter.address, build("SccpTairaXorWallet")),
            body: InternalTransferStep {
                queryId: 0,
                jettonAmount: 50,
                transferInitiator: null,
                sendExcessesTo: null,
                forwardTonAmount: 0,
                forwardPayload: beginCell().storeUint(0, 1).toSlice(),
            },
        }),
    );
    expect(credit).toHaveSuccessfulDeploy({ to: wallet.address });
    val res = sendBurn(env, owner, 50, snakeOfLength(8), burnValue(env, owner));
    expect(res).toHaveFailedTx<BurnNotificationForMinter>({
        to: env.minter.address,
        exitCode: SccpErrors.WrongWorkchain as int,
    });
    expect(wallet.getWalletData().jettonBalance).toEqual(50);
}

get fun `test burn notifications from a non-wallet are rejected`() {
    val env = setupEnv();
    val stranger = testing.treasury("stranger").address;
    val res = env
        .minter
        .sendBurnNotificationForMinter(
            stranger,
            0,
            1000,
            stranger,
            stranger,
            { recipient: snakeOfLength(8) },
            { value: grams("1"), bounce: true },
        );
    expect(res).toHaveFailedTx<BurnNotificationForMinter>({ to: env
            .minter
            .address, exitCode: SccpErrors.NotValidWallet as int });
}

get fun `test a burn of 2^96 or more is refused by the minter`() {
    val env = setupEnvWith(4, SCCP_TON_AMOUNT_LIMIT * 4);
    val alice = testing.treasury("alice").address;
    // two mints of the largest amount: the wallet holds more than one burn may carry
    finalizeOk(env, 0, SCCP_TON_AMOUNT_LIMIT - 1, alice);
    finalizeOk(env, 1, SCCP_TON_AMOUNT_LIMIT - 1, alice);
    val held = 2 * (SCCP_TON_AMOUNT_LIMIT - 1);
    val over = sendBurn(env, alice, SCCP_TON_AMOUNT_LIMIT, snakeOfLength(8), burnValue(env, alice));
    expectBurnRefused(env, over, alice, SccpErrors.BadAmount as int, held);
    expect(env.minter.getSccpState().outboundNonce).toEqual(0);
    // the largest amount burns
    val ok = sendBurn(
        env,
        alice,
        SCCP_TON_AMOUNT_LIMIT - 1,
        snakeOfLength(8),
        burnValue(env, alice),
    );
    expect(ok).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    expect(jettonBalanceOf(env, alice)).toEqual(SCCP_TON_AMOUNT_LIMIT - 1);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(SCCP_TON_AMOUNT_LIMIT - 1);
    expect(state.outboundNonce).toEqual(1);
}

get fun `test a burn notification requires the ton mainnet global id`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    setGlobalId(-3);
    val res = sendBurn(env, alice, 30, snakeOfLength(8), burnValue(env, alice));
    expectBurnRefused(env, res, alice, SccpErrors.WrongChain as int, 100);
    var state = env.minter.getSccpState();
    expect(state.outboundNonce).toEqual(0);
    expect(state.totalSupply).toEqual(100);
    expect(state.opCount).toEqual(1);
    // chain identity comes before the wallet check: a stranger learns nothing else
    val stranger = testing.treasury("stranger").address;
    val forged = env
        .minter
        .sendBurnNotificationForMinter(
            stranger,
            0,
            1000,
            stranger,
            stranger,
            { recipient: snakeOfLength(8) },
            { value: grams("1"), bounce: true },
        );
    expect(forged).toHaveFailedTx<BurnNotificationForMinter>({
        to: env.minter.address,
        exitCode: SccpErrors.WrongChain as int,
    });
    setGlobalId(SCCP_TON_GLOBAL_ID);
    val ok = sendBurn(env, alice, 30, snakeOfLength(8), burnValue(env, alice));
    expect(ok).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    state = env.minter.getSccpState();
    expect(state.outboundNonce).toEqual(1);
    expect(state.totalSupply).toEqual(70);
}

get fun `test burns work after the generation expired`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    // Frozen by expiry: nothing is finalized any more
    testing.setNow(T0 + TEST_VALIDITY_MS / 1000 + 10 * 86400);
    val late = deliver(
        env,
        env.committee,
        env.generation,
        1,
        5,
        alice,
        (T0 + 30 * 86400) * 1000,
        0,
        1,
    );
    expectOutcome(
        sendFinalize(env, env.deployer, late, finalizeValue(env, 1)),
        SccpErrors.CommitteeNotAccepted,
    );
    val res = sendBurn(env, alice, 100, snakeOfLength(8), burnValue(env, alice));
    expect(res).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    expect(res).toEmitExternalMessage<SccpTransferToTairaEvent>();
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(0);
    expect(state.outboundNonce).toEqual(1);
    expect(state.opCount).toEqual(2);
}

get fun `test burns work on a latched minter`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    // the generation certifies a height below its start (V2)
    val below = emptyX(env.networkId, env.generation, env.committee.root(), TEST_START_HEIGHT - 1);
    expectOutcome(checkpointBy(env, env.committee, below, null), 0);
    expect(env.minter.getSccpState().equivocated).toBeTrue();
    // no message of a burn throws 433: holders can always leave
    val res = sendBurn(env, alice, 40, snakeOfLength(8), burnValue(env, alice));
    expect(res).toHaveAllSuccessfulTxs();
    expect(res).toEmitExternalMessage<SccpTransferToTairaEvent>();
    expect(jettonBalanceOf(env, alice)).toEqual(60);
    val state = env.minter.getSccpState();
    expect(state.totalSupply).toEqual(60);
    expect(state.outboundNonce).toEqual(1);
    expect(state.opCount).toEqual(2);
}

// ---------------------------------------------------------------------------
// The two counter bounds of §5.1.2, reached by storage injection.

get fun `test exhausted source nonces answer BadNonce before any state change`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val bob = testing.treasury("bob").address;
    finalizeOk(env, 0, 1000, alice);
    finalizeOk(env, 1, 500, bob);
    // source nonces are 0 ..= 2^64 − 2
    expect(sccpNextOutboundNonce(0)).toEqual(1);
    expect(sccpNextOutboundNonce(SCCP_MAX_U64 - 1)).toEqual(SCCP_MAX_U64);
    try {
        sccpNextOutboundNonce(SCCP_MAX_U64);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadNonce as int);
    }
    // storage injection: the last source nonce is still free
    var st = minterStorage(env);
    st.outboundNonce = SCCP_MAX_U64 - 1;
    setMinterStorage(env, st);
    val recipient = snakeOfLength(8);
    val last = sendBurn(env, alice, 100, recipient, burnValue(env, alice));
    expect(last).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    val event = last
        .findExternalOutMessage<SccpTransferToTairaEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.nonce).toEqual(SCCP_MAX_U64 - 1);
    expect(event.messageId).toEqual(expectedBurn(env, SCCP_MAX_U64 - 1, 100, alice, recipient).1);
    var state = env.minter.getSccpState();
    expect(state.outboundNonce).toEqual(SCCP_MAX_U64);
    expect(state.totalSupply).toEqual(1400);
    expect(state.opCount).toEqual(3);

    // exhausted: every burn of every owner answers BadNonce (425), the bounce
    // restores the wallet, and the minter changes nothing
    val before = minterStorage(env).toCell().hash();
    expectBurnRefused(
        env,
        sendBurn(env, alice, 1, recipient, burnValue(env, alice)),
        alice,
        SccpErrors.BadNonce as int,
        900,
    );
    expectBurnRefused(
        env,
        sendBurn(env, alice, 900, snakeOfLength(1024), burnValue(env, alice)),
        alice,
        SccpErrors.BadNonce as int,
        900,
    );
    expectBurnRefused(
        env,
        sendBurn(env, bob, 500, recipient, burnValue(env, bob)),
        bob,
        SccpErrors.BadNonce as int,
        500,
    );
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    state = env.minter.getSccpState();
    expect(state.outboundNonce).toEqual(SCCP_MAX_U64);
    expect(state.totalSupply).toEqual(1400);
    expect(state.opCount).toEqual(3);
    // the recipient is still validated first, so a malformed burn keeps its own code
    val malformed = sendBurn(env, bob, 500, snakeOfLength(1025), burnValue(env, bob));
    expect(malformed).toHaveFailedTx<AskToBurn>({
        to: walletOf(env, bob).address,
        exitCode: SccpErrors.BadRecipient as int,
    });
    expect(
        malformed.findTransaction<BurnNotificationForMinter>({ to: env.minter.address }) == null,
    ).toBeTrue();
    expect(jettonBalanceOf(env, bob)).toEqual(500);
    expect(minterStorage(env).toCell().hash()).toEqual(before);
    // the Taira→TON direction is unaffected
    finalizeOk(env, 2, 5, alice);
    expect(env.minter.getSccpState().totalSupply).toEqual(1405);
}

get fun `test opCount saturates at the top of u64 under a burn`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    // storage injection: one operation below the bound
    var st = minterStorage(env);
    st.opCount = SCCP_MAX_U64 - 1;
    setMinterStorage(env, st);
    val first = sendBurn(env, alice, 10, snakeOfLength(8), burnValue(env, alice));
    expect(first).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    expect(env.minter.getSccpState().opCount).toEqual(SCCP_MAX_U64);
    // the burn that meets the bound still succeeds, and the counter stays
    val second = sendBurn(env, alice, 10, snakeOfLength(8), burnValue(env, alice));
    expect(second).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    expect(second).toEmitExternalMessage<SccpTransferToTairaEvent>();
    val state = env.minter.getSccpState();
    expect(state.opCount).toEqual(SCCP_MAX_U64);
    expect(state.outboundNonce).toEqual(2);
    expect(state.totalSupply).toEqual(80);
    expect(jettonBalanceOf(env, alice)).toEqual(80);
}
