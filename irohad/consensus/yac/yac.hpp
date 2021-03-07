/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_HPP
#define IROHA_YAC_HPP

#include "consensus/yac/transport/yac_network_interface.hpp"  // for YacNetworkNotifications
#include "consensus/yac/yac_gate.hpp"                         // for HashGate

#include <memory>
#include <mutex>

#include <boost/optional.hpp>
#include <rxcpp/rx-lite.hpp>
#include "consensus/yac/cluster_order.hpp"     //  for ClusterOrdering
#include "consensus/yac/outcome_messages.hpp"  // because messages passed by value
#include "consensus/yac/storage/yac_vote_storage.hpp"  // for VoteStorage
#include "logger/logger_fwd.hpp"
#include "main/subscription.hpp"

#include <rxcpp/operators/rx-observe_on.hpp>

namespace iroha {
  namespace consensus {
    namespace yac {

      class YacCryptoProvider;
      class Timer;

      class Yac : public HashGate,
                  public YacNetworkNotifications,
                  public std::enable_shared_from_this<Yac> {
       public:
        /**
         * Method for creating Yac consensus object
         * @param delay for timer in milliseconds
         */
        static std::shared_ptr<Yac> create(
            YacVoteStorage vote_storage,
            std::shared_ptr<YacNetwork> network,
            std::shared_ptr<YacCryptoProvider> crypto,
            std::shared_ptr<Timer> timer,
            ClusterOrdering order,
            Round round,
            rxcpp::observe_on_one_worker worker,
            logger::LoggerPtr log);

        Yac(YacVoteStorage vote_storage,
            std::shared_ptr<YacNetwork> network,
            std::shared_ptr<YacCryptoProvider> crypto,
            std::shared_ptr<Timer> timer,
            ClusterOrdering order,
            Round round,
            rxcpp::observe_on_one_worker worker,
            logger::LoggerPtr log);

        ~Yac() override;

        // ------|Hash gate|------

        void vote(YacHash hash,
                  ClusterOrdering order,
                  boost::optional<ClusterOrdering> alternative_order =
                      boost::none) override;

        // ------|Network notifications|------

        void onState(std::vector<VoteMessage> state) override;

        void stop() override;

       private:
        // ------|Private interface|------

        /**
         * Voting step is strategy of propagating vote
         * until commit/reject message received
         */
        void votingStep(VoteMessage vote, uint32_t attempt = 0ul);

        /**
         * Erase temporary data of current round
         */
        void closeRound();

        /// Get cluster_order_ or alternative_order_ if present
        ClusterOrdering &getCurrentOrder();

        /**
         * Find corresponding peer in the ledger from vote message
         * @param vote message containing peer information
         * @return peer if it is present in the ledger, boost::none otherwise
         */
        boost::optional<std::shared_ptr<shared_model::interface::Peer>>
        findPeer(const VoteMessage &vote);

        /// Remove votes from unknown peers from given vector.
        void removeUnknownPeersVotes(std::vector<VoteMessage> &votes,
                                     ClusterOrdering &order);

        // ------|Apply data|------
        /**
         * @pre lock is locked
         * @post lock is unlocked
         */
        void applyState(const std::vector<VoteMessage> &state,
                        std::unique_lock<std::mutex> &lock);

        // ------|Propagation|------
        void propagateState(const std::vector<VoteMessage> &msg);
        void propagateStateDirectly(const shared_model::interface::Peer &to,
                                    const std::vector<VoteMessage> &msg);
        void tryPropagateBack(const std::vector<VoteMessage> &state);

        // ------|Logger|------
        logger::LoggerPtr log_;

        std::mutex mutex_;

        // ------|One round|------
        ClusterOrdering cluster_order_;
        boost::optional<ClusterOrdering> alternative_order_;
        utils::RWObjectHolder<Round> round_;

        // ------|Fields|------
        YacVoteStorage vote_storage_;
        std::shared_ptr<YacNetwork> network_;
        std::shared_ptr<YacCryptoProvider> crypto_;
        std::shared_ptr<Timer> timer_;

        using ApplyStateSubscription = subscription::SubscriberImpl<
            EventTypes,
            SubscriptionDispatcher,
            utils::RWObjectHolder<Round>,
            Round>;

        std::shared_ptr<ApplyStateSubscription> apply_state_subscription_;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_HPP
