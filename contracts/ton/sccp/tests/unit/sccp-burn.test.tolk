// TON→Taira burns (§5.1.7, §5.3.4 "Burn"): the SCCP custom payload is
// mandatory, the minter builds the §3.2 payload with a sequential nonce and
// emits `sccp_transfer_to_taira`, and every rejection (plain burn, recipient
// length or shape, owner workchain, foreign wallet) restores the balance.

import "@stdlib/exotic-cells"
import "@acton/build"
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
    expect(trailing).toHaveFailedTx<AskToBurn>({ to: wallet.address, exitCode: 9 });
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

get fun `test minter rejections bounce and restore the wallet balance`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    // a published library with a canonical recipient is still not canonical
    testing.registerLibrary(snakeOfLength(4));
    val recipients: array<[cell, int]> = [
        [snakeOfLength(1025), SccpErrors.BadRecipient as int],
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
        expect(res).toHaveFailedTx<BurnNotificationForMinter>({ to: env
                .minter
                .address, exitCode: code });
        expect(res).toHaveBouncedTx({ to: walletOf(env, alice).address });
        expect(jettonBalanceOf(env, alice)).toEqual(100);
        i += 1;
    }
    val state = env.minter.getSccpState();
    expect(state.outboundNonce).toEqual(0);
    expect(state.totalSupply).toEqual(100);
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

get fun `test burns work after the committee expired`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 100, alice);
    testing.setNow(defaultPin(env.committee).untilMs / 1000 + 10 * 86400);
    val res = sendBurn(env, alice, 100, snakeOfLength(8), burnValue(env, alice));
    expect(res).toHaveSuccessfulTx<BurnNotificationForMinter>({ to: env.minter.address });
    expect(env.minter.getSccpState().totalSupply).toEqual(0);
}
