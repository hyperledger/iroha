/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_HPP
#define IROHA_YAC_HPP

#include "consensus/yac/transport/yac_network_interface.hpp"  // for YacNetworkNotifications
#include "consensus/yac/yac_gate.hpp"                         // for HashGate

#include <map>
#include <memory>
#include <unordered_set>

#include "consensus/yac/cluster_order.hpp"     //  for ClusterOrdering
#include "consensus/yac/outcome_messages.hpp"  // because messages passed by value
#include "consensus/yac/storage/yac_vote_storage.hpp"  // for VoteStorage
#include "logger/logger_fwd.hpp"

namespace iroha::consensus::yac {
  class YacCryptoProvider;
  class Timer;

  class Yac : public HashGate, public YacNetworkNotifications {
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
        shared_model::interface::types::PeerList order,
        Round round,
        logger::LoggerPtr log);

    Yac(YacVoteStorage vote_storage,
        std::shared_ptr<YacNetwork> network,
        std::shared_ptr<YacCryptoProvider> crypto,
        std::shared_ptr<Timer> timer,
        shared_model::interface::types::PeerList order,
        Round round,
        logger::LoggerPtr log);

    // ------|Hash gate|------

    void vote(YacHash hash,
              ClusterOrdering order,
              std::optional<ClusterOrdering> alternative_order =
                  std::nullopt) override;

    std::optional<Answer> processRoundSwitch(
        consensus::Round const &round,
        shared_model::interface::types::PeerList const &peers,
        shared_model::interface::types::PeerList const &sync_peers) override;

    // ------|Network notifications|------

    std::optional<Answer> onState(std::vector<VoteMessage> state) override;

    void stop() override;

   private:
    // ------|Private interface|------

    /**
     * Voting step is strategy of propagating vote
     * until commit/reject message received
     */
    void votingStep(VoteMessage vote,
                    ClusterOrdering order,
                    uint32_t attempt = 0);

    /// Get cluster_order_ or alternative_order_ if present
    shared_model::interface::types::PeerList &getCurrentOrder();

    /**
     * Find corresponding peer in the ledger from vote message
     * @param vote message containing peer information
     * @return peer if it is present in the ledger, std::nullopt otherwise
     */
    std::optional<std::shared_ptr<shared_model::interface::Peer>> findPeer(
        const VoteMessage &vote);

    /// Remove votes from unknown peers from given vector.
    void removeUnknownPeersVotes(
        std::vector<VoteMessage> &votes,
        shared_model::interface::types::PeerList const &order);

    // ------|Apply data|------
    std::optional<Answer> applyState(const std::vector<VoteMessage> &state);

    // ------|Propagation|------
    void propagateState(const std::vector<VoteMessage> &msg);
    void propagateStateDirectly(const shared_model::interface::Peer &to,
                                const std::vector<VoteMessage> &msg);
    void tryPropagateBack(const std::vector<VoteMessage> &state);

    // ------|Logger|------
    logger::LoggerPtr log_;

    // ------|One round|------
    shared_model::interface::types::PeerList cluster_order_;
    shared_model::interface::types::PeerList syncing_peers_;
    std::optional<shared_model::interface::types::PeerList> alternative_order_;
    Round round_;

    // ------|Fields|------
    YacVoteStorage vote_storage_;
    std::shared_ptr<YacNetwork> network_;
    std::shared_ptr<YacCryptoProvider> crypto_;
    std::shared_ptr<Timer> timer_;
    std::map<Round, std::unordered_set<VoteMessage>> future_states_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_HPP
