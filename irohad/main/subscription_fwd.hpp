/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_FWD_HPP
#define IROHA_SUBSCRIPTION_FWD_HPP

#include <memory>

namespace iroha {
  enum SubscriptionEngineHandlers {
    kYac = 0,
    kRequestProposal,
    kVoteProcess,
    kProposalProcessing,
    kMetrics,
    kNotifications,
    //---------------
    kTotalCount
  };

  enum EventTypes {
    kOnOutcome = 0,
    kOnSynchronization,
    kOnInitialSynchronization,
    kOnCurrentRoundPeers,
    kOnRoundSwitch,
    kOnProposal,
    kOnVerifiedProposal,
    kOnProcessedHashes,
    kOnOutcomeFromYac,
    kOnOutcomeDelayed,
    kOnBlock,
    kOnInitialBlock,
    kOnBlockCreatorEvent,
    kOnFinalizedTxs,
    kOnApplyState,
    kOnNeedProposal,
    kOnNewProposal,
    kOnTxsEnoughForProposal,
    kOnPackProposal,
    kOnProposalResponse,
    kOnProposalSingleEvent,
    kOnProposalResponseFailed,
    kOnTransactionResponse,
    kOnConsensusGateEvent,
    kSendBatchComplete,

    kRemoteProposalDiff,

    // RDB
    kOnRdbStats,

    // Node status
    kOnIrohaStatus,

    // MST
    kOnMstStateUpdate,
    kOnMstPreparedBatches,
    kOnMstExpiredBatches,
    kOnMstMetrics,

    // YAC
    kTimer,
    kOnState,

    // TEST
    kOnTestOperationComplete
  };

  static constexpr uint32_t kThreadPoolSize = 3u;

  namespace subscription {
    struct IDispatcher;

    template <uint32_t kHandlersCount, uint32_t kPoolSize>
    class SubscriptionManager;

    template <typename EventKey,
              typename Dispatcher,
              typename Receiver,
              typename... Arguments>
    class SubscriberImpl;
  }  // namespace subscription

  using Dispatcher = subscription::IDispatcher;
  using Subscription =
      subscription::SubscriptionManager<SubscriptionEngineHandlers::kTotalCount,
                                        kThreadPoolSize>;
  template <typename ObjectType, typename... EventData>
  using BaseSubscriber = subscription::
      SubscriberImpl<EventTypes, Dispatcher, ObjectType, EventData...>;

}  // namespace iroha

#endif  // IROHA_SUBSCRIPTION_FWD_HPP
