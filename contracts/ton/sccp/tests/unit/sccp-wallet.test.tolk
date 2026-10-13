// TEP-74 wallet behaviour and TEP-89 discovery of the SCCP Jetton: transfers,
// notifications, workchain and ownership rules, forged internal transfers,
// bounces, and the on-chain TEP-64 content built from constants.

import "@stdlib/gas-payments"
import "@stdlib/strings"
import "@acton/build"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@acton/types/transaction"
import "@contracts/sccp-addresses"
import "@contracts/sccp-errors"
import "@contracts/sccp-fees"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@wrappers/SccpConsumedBucket.gen"
import "@wrappers/SccpTairaXorMinter.gen"
import "@wrappers/SccpTairaXorWallet.gen"
import "sccp-test-helpers"

fun transfer(
    env: Env,
    from: address,
    to: address,
    amount: int,
    forwardTonAmount: coins,
): SendResultList {
    return walletOf(env, from).sendAskToTransfer(
        from,
        3,
        amount,
        to,
        from,
        null,
        forwardTonAmount,
        PayloadInline { value: beginCell().storeUint(0, 1).toSlice() },
        { value: grams("0.5"), bounce: true },
    );
}

get fun `test wallet to wallet transfer with notification`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val bob = testing.treasury("bob").address;
    finalizeOk(env, 0, 1000, alice);
    val res = transfer(env, alice, bob, 300, grams("0.01"));
    expect(res).toHaveSuccessfulDeploy<InternalTransferStep>({ to: walletOf(env, bob).address });
    expect(res).toHaveSuccessfulTx<TransferNotificationForRecipient>({ to: bob });
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: alice });
    expect(jettonBalanceOf(env, alice)).toEqual(700);
    expect(jettonBalanceOf(env, bob)).toEqual(300);
    expect(env.minter.getSccpState().totalSupply).toEqual(1000);
}

get fun `test large transfer payload fees cover both forwarding steps`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val bob = testing.treasury("bob").address;
    finalizeOk(env, 0, 1000, alice);
    // Unlike burns, TEP-74 transfers admit arbitrary payload sizes and price
    // both copies from the incoming message's actual forwarding fee.
    val payload = snakeOfLength(12700);
    val (cells, bits, _) = payload.calculateSizeStrict(200);
    val forwardAmount = grams("0.01");
    val smallQuote = sccpTransferRequiredValue(
        forwardAmount,
        calculateForwardFee(BASECHAIN, 8, 1),
    ) +
        1;
    val poor = walletOf(env, alice).sendAskToTransfer(
        alice,
        3,
        300,
        bob,
        alice,
        null,
        forwardAmount,
        PayloadInRef { value: payload as Cell<RemainingBitsAndRefs> },
        { value: smallQuote, bounce: true },
    );
    expect(poor).toHaveFailedTx<AskToTransfer>({ to: walletOf(
            env,
            alice,
        ).address, exitCode: SccpErrors.NotEnoughValue as int });
    expect(jettonBalanceOf(env, alice)).toEqual(1000);
    // Include the root/header bounds as well as the full 100-cell payload.
    val quote = sccpTransferRequiredValue(
        forwardAmount,
        calculateForwardFee(BASECHAIN, bits + 2000, cells + 2),
    ) +
        1;
    val sent = walletOf(env, alice).sendAskToTransfer(
        alice,
        3,
        300,
        bob,
        alice,
        null,
        forwardAmount,
        PayloadInRef { value: payload as Cell<RemainingBitsAndRefs> },
        { value: quote, bounce: true },
    );
    expect(sent).toHaveAllSuccessfulTxs();
    expect(sent).toHaveSuccessfulTx<TransferNotificationForRecipient>({ to: bob });
    expect(jettonBalanceOf(env, alice)).toEqual(700);
    expect(jettonBalanceOf(env, bob)).toEqual(300);
    expect(env.minter.getSccpState().totalSupply).toEqual(1000);
}

get fun `test transfer rules`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val bob = testing.treasury("bob").address;
    finalizeOk(env, 0, 100, alice);
    val wallet = walletOf(env, alice);
    val master = testing.treasury("master", MASTERCHAIN).address;
    expect(transfer(env, alice, master, 10, 0)).toHaveFailedTx<AskToTransfer>({
        to: wallet.address,
        exitCode: SccpErrors.WrongWorkchain as int,
    });
    expect(transfer(env, alice, bob, 101, 0)).toHaveFailedTx<AskToTransfer>({
        to: wallet.address,
        exitCode: SccpErrors.BalanceError as int,
    });
    val notOwner = wallet.sendAskToTransfer(
        bob,
        3,
        10,
        bob,
        bob,
        null,
        0,
        PayloadInline { value: beginCell().storeUint(0, 1).toSlice() },
        { value: grams("0.5"), bounce: true },
    );
    expect(
        notOwner,
    ).toHaveFailedTx<AskToTransfer>({ to: wallet.address, exitCode: SccpErrors.NotOwner as int });
    expect(jettonBalanceOf(env, alice)).toEqual(100);
}

get fun `test forged internal transfers are rejected`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val mallory = testing.treasury("mallory").address;
    finalizeOk(env, 0, 100, alice);
    val wallet = walletOf(env, alice);
    val res = wallet.sendInternalTransferStep(
        mallory,
        0,
        1000000,
        mallory,
        null,
        0,
        PayloadInline { value: beginCell().storeUint(0, 1).toSlice() },
        { value: grams("0.5"), bounce: true },
    );
    expect(
        res,
    ).toHaveFailedTx<InternalTransferStep>({ to: wallet.address, exitCode: SccpErrors.NotValidWallet as int });
    expect(jettonBalanceOf(env, alice)).toEqual(100);
}

get fun `test a bounced internal transfer restores the sender`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val bob = testing.treasury("bob").address;
    finalizeOk(env, 0, 100, alice);
    val step = testing.processSingleTraceStep(
        alice,
        createMessage({
            bounce: BounceMode.Only256BitsOfBody,
            value: grams("0.5"),
            dest: walletOf(env, alice).address,
            body: AskToTransfer {
                queryId: 0,
                jettonAmount: 40,
                transferRecipient: bob,
                sendExcessesTo: alice,
                customPayload: null,
                forwardTonAmount: 0,
                forwardPayload: beginCell().storeUint(0, 1).toSlice(),
            },
        }),
    );
    expect(jettonBalanceOf(env, alice)).toEqual(60);
    val sent = step.outMessages.at<InternalTransferStep>(0).loadBody();
    testing.processSingleTraceStep(
        walletOf(env, bob).address,
        bouncedMessage(sent, walletOf(env, alice).address, grams("0.1")),
    );
    expect(jettonBalanceOf(env, alice)).toEqual(100);
}

get fun `test provide_wallet_address`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val res = env
        .minter
        .sendRequestWalletAddress(alice, 5, alice, true, { value: grams("0.1"), bounce: true });
    expect(res).toHaveSuccessfulTx<ResponseWalletAddress>({ to: alice });
    val tx = res.findTransaction<ResponseWalletAddress>({ to: alice })!;
    val reply = tx.loadBody<ResponseWalletAddress>();
    expect(reply.queryId).toEqual(5);
    expect(reply.jettonWalletAddress!).toEqual(env.minter.getWalletAddress(alice));
    expect(reply.ownerAddress!.load()).toEqual(alice);
    val master = testing.treasury("master", MASTERCHAIN).address;
    val res2 = env
        .minter
        .sendRequestWalletAddress(alice, 6, master, false, { value: grams("0.1"), bounce: true });
    val reply2 = res2
        .findTransaction<ResponseWalletAddress>({ to: alice })!
        .loadBody<ResponseWalletAddress>();
    expect(reply2.jettonWalletAddress == null).toBeTrue();
    expect(reply2.ownerAddress == null).toBeTrue();
}

get fun `test jetton content is on-chain name, symbol and decimals`() {
    val env = setupEnv();
    val data = env.minter.getJettonData();
    val content = data.jettonContent.load();
    expect(
        content.contentDict.mustGet("name".sha256()).equalTo("Taira XOR".prefixWith00()),
    ).toBeTrue();
    expect(
        content.contentDict.mustGet("symbol".sha256()).equalTo("tXOR".prefixWith00()),
    ).toBeTrue();
    expect(content.contentDict.mustGet("decimals".sha256()).equalTo("9".prefixWith00())).toBeTrue();
    expect(content.contentDict.exists("uri".sha256())).toBeFalse();
    val alice = testing.treasury("alice").address;
    expect(env.minter.getWalletAddress(alice)).toEqual(
        sccpWalletAddress(alice, env.minter.address, build("SccpTairaXorWallet")),
    );
}

get fun `test top-ups are accepted by minter, wallet and bucket`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    finalizeOk(env, 0, 1, alice);
    val before = testing.getAccountBalance(env.minter.address);
    expect(
        env.minter.sendTopUpTons(alice, 0, { value: grams("2") }),
    ).toHaveSuccessfulTx<TopUpTons>({ to: env.minter.address });
    expect(testing.getAccountBalance(env.minter.address) > before).toBeTrue();
    expect(
        walletOf(env, alice).sendTopUpTons(alice, 0, { value: grams("1") }),
    ).toHaveSuccessfulTx<TopUpTons>({
        to: walletOf(env, alice).address,
    });
    expect(
        bucketOf(env, 0).sendTopUpTons(alice, 0, { value: grams("1") }),
    ).toHaveSuccessfulTx<TopUpTons>({
        to: bucketOf(env, 0).address,
    });
    // unknown operations are refused
    expect(
        env
            .minter
            .sendAny(
                alice,
                beginCell().storeUint(0xDEADBEEF, 32).endCell(),
                { value: grams("1"), bounce: true },
            ),
    ).toHaveFailedTx({
        to: env.minter.address,
        exitCode: SccpErrors.InvalidMessage as int,
    });
    // by the wallet and the bucket too; the deleted roster and attestation ops
    // (`sccp_rotate`, `sccp_evidence`) are unknown operations like any other
    val unknown: array<cell> = [
        beginCell().storeUint(0xDEADBEEF, 32).endCell(),
        beginCell().storeUint(0x53435231, 32).storeUint(0, 64).endCell(),
        beginCell().storeUint(0x53434531, 32).storeUint(0, 64).endCell(),
    ];
    var i = 0;
    repeat (unknown.size()) {
        expect(
            walletOf(env, alice).sendAny(
                alice,
                unknown.get(i),
                { value: grams("1"), bounce: true },
            ),
        ).toHaveFailedTx({
            to: walletOf(env, alice).address,
            exitCode: SccpErrors.InvalidMessage as int,
        });
        expect(
            bucketOf(env, 0).sendAny(alice, unknown.get(i), { value: grams("1"), bounce: true }),
        ).toHaveFailedTx({
            to: bucketOf(env, 0).address,
            exitCode: SccpErrors.InvalidMessage as int,
        });
        expect(
            env.minter.sendAny(alice, unknown.get(i), { value: grams("1"), bounce: true }),
        ).toHaveFailedTx({
            to: env.minter.address,
            exitCode: SccpErrors.InvalidMessage as int,
        });
        i += 1;
    }
    expect(jettonBalanceOf(env, alice)).toEqual(1);
    expect(isConsumedAt(env, 0)).toBeTrue();
}
