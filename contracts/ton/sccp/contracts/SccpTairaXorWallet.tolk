// SccpTairaXorWallet: TEP-74 Jetton wallet of Taira XOR on TON (§5.3).
//
// Standard transfers and receipts. A burn MUST carry the SCCP custom payload
// `sccp_burn_to_taira` (§5.3.4 "Burn"), so no value can be burned without a
// Taira record; plain TEP-74 burns are rejected.

import "@stdlib/gas-payments"
import "sccp-addresses"
import "sccp-cells"
import "sccp-constants"
import "sccp-errors"
import "sccp-fees"
import "sccp-messages"
import "sccp-storage"

contract SccpTairaXorWallet {
    author: "Hyperledger Iroha"
    version: "1.0.0"
    description: "SCCP v1 Taira XOR Jetton wallet (TEP-74); burns require the SCCP payload"
    storage: WalletStorage
    incomingMessages: WalletMessage
}

type WalletMessage = AskToTransfer | AskToBurn | InternalTransferStep | TopUpTons

type WalletBounce = InternalTransferStep | BurnNotificationForMinter

fun onBouncedMessage(in: InMessageBounced) {
    in.bouncedBody.skipBouncedPrefix();

    val msg = lazy WalletBounce.fromSlice(in.bouncedBody);
    val restoreAmount = match (msg) {
        InternalTransferStep => msg.jettonAmount,
        BurnNotificationForMinter => msg.jettonAmount,
    };

    var storage = lazy WalletStorage.load();
    storage.jettonBalance += restoreAmount;
    storage.save();
}

fun onInternalMessage(in: InMessage) {
    val msg = lazy WalletMessage.fromSlice(in.body);

    match (msg) {
        InternalTransferStep => {
            var storage = lazy WalletStorage.load();
            if (in.senderAddress != storage.minterAddress) {
                assert (
                    in.senderAddress ==
                    sccpWalletAddress(
                        msg.transferInitiator!,
                        storage.minterAddress,
                        contract.getCode(),
                    )
                ) throw SccpErrors.NotValidWallet;
            }
            storage.jettonBalance += msg.jettonAmount;
            storage.save();

            if (msg.forwardTonAmount != 0) {
                val notifyOwnerMsg = createMessage({
                    bounce: BounceMode.NoBounce,
                    dest: storage.ownerAddress,
                    value: msg.forwardTonAmount,
                    body: TransferNotificationForRecipient {
                        queryId: msg.queryId,
                        jettonAmount: msg.jettonAmount,
                        transferInitiator: msg.transferInitiator,
                        forwardPayload: msg.forwardPayload,
                    },
                });
                notifyOwnerMsg.send(
                    SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_BOUNCE_ON_ACTION_FAIL,
                );
            }

            if (msg.sendExcessesTo != null) {
                val toLeaveOnBalance = contract.getOriginalBalance() - in.valueCoins +
                    contract.getStorageDuePayment();
                reserveGramsOnBalance(
                    max(toLeaveOnBalance, sccpWalletMinStorage()),
                    RESERVE_MODE_AT_MOST,
                );

                val excessesMsg = createMessage({
                    bounce: BounceMode.NoBounce,
                    dest: msg.sendExcessesTo,
                    value: 0,
                    body: ReturnExcessesBack { queryId: msg.queryId },
                });
                excessesMsg.send(SEND_MODE_CARRY_ALL_BALANCE | SEND_MODE_IGNORE_ERRORS);
            }
        }

        AskToTransfer => {
            msg.forwardPayload.checkIsCorrectTlbEither();
            assert (sccpIsBasechainStd(msg.transferRecipient)) throw SccpErrors.WrongWorkchain;
            assert (
                in.valueCoins >
                sccpTransferRequiredValue(msg.forwardTonAmount, in.originalForwardFee)
            ) throw SccpErrors.NotEnoughValue;

            var storage = lazy WalletStorage.load();
            assert (in.senderAddress == storage.ownerAddress) throw SccpErrors.NotOwner;
            assert (storage.jettonBalance >= msg.jettonAmount) throw SccpErrors.BalanceError;
            storage.jettonBalance -= msg.jettonAmount;
            storage.save();

            val deployMsg = createMessage({
                bounce: BounceMode.Only256BitsOfBody,
                dest: sccpWalletDeployment(
                    msg.transferRecipient,
                    storage.minterAddress,
                    contract.getCode(),
                ),
                value: 0,
                body: InternalTransferStep {
                    queryId: msg.queryId,
                    jettonAmount: msg.jettonAmount,
                    transferInitiator: storage.ownerAddress,
                    sendExcessesTo: msg.sendExcessesTo,
                    forwardTonAmount: msg.forwardTonAmount,
                    forwardPayload: msg.forwardPayload,
                },
            });
            deployMsg.send(
                SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE | SEND_MODE_BOUNCE_ON_ACTION_FAIL,
            );
        }

        AskToBurn => {
            // §5.3.4 Burn step 2: the SCCP custom payload is mandatory.
            assert (msg.customPayload != null) throw SccpErrors.BadBurnPayload;
            val sccpPayload = msg.customPayload!;
            // The fee bound includes at most nine recipient cells. Validate the
            // entire ordinary canonical snake before debiting or forwarding.
            sccpParseBurnToTaira(sccpPayload);
            assert (msg.jettonAmount > 0) throw SccpErrors.BadAmount;
            assert (in.valueCoins > sccpBurnRequiredValue()) throw SccpErrors.NotEnoughValue;

            var storage = lazy WalletStorage.load();
            assert (in.senderAddress == storage.ownerAddress) throw SccpErrors.NotOwner;
            assert (storage.jettonBalance >= msg.jettonAmount) throw SccpErrors.BalanceError;
            storage.jettonBalance -= msg.jettonAmount;
            storage.save();

            val notifyMinterMsg = createMessage({
                bounce: BounceMode.Only256BitsOfBody,
                dest: storage.minterAddress,
                value: 0,
                body: BurnNotificationForMinter {
                    queryId: msg.queryId,
                    jettonAmount: msg.jettonAmount,
                    burnInitiator: storage.ownerAddress,
                    sendExcessesTo: msg.sendExcessesTo,
                    sccp: sccpPayload as Cell<SccpBurnToTaira>,
                },
            });
            notifyMinterMsg.send(
                SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE | SEND_MODE_BOUNCE_ON_ACTION_FAIL,
            );
        }

        TopUpTons => {
            // accept value
        }

        else => throw SccpErrors.InvalidMessage,
    }
}

get fun get_wallet_data(): JettonWalletDataReply {
    val storage = lazy WalletStorage.load();

    return {
        jettonBalance: storage.jettonBalance,
        ownerAddress: storage.ownerAddress,
        minterAddress: storage.minterAddress,
        jettonWalletCode: contract.getCode(),
    };
}

/// Minimal value an SCCP burn must carry (strictly more is required).
get fun burn_required_value(): int {
    return sccpBurnRequiredValue();
}
