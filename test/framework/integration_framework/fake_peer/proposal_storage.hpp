/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INTEGRATION_FRAMEWORK_FAKE_PEER_PROPOSAL_STORAGE_HPP_
#define INTEGRATION_FRAMEWORK_FAKE_PEER_PROPOSAL_STORAGE_HPP_

#include <map>
#include <mutex>
#include <shared_mutex>
#include <unordered_set>

#include "backend/protobuf/proposal.hpp"
#include "consensus/round.hpp"
#include "framework/integration_framework/fake_peer/types.hpp"
#include "interfaces/iroha_internal/unsafe_proposal_factory.hpp"

namespace integration_framework {
  namespace fake_peer {

    namespace detail {

      using TxPointerType =
          std::shared_ptr<shared_model::interface::Transaction>;

      class PointerTxHasher {
       public:
        size_t operator()(const TxPointerType &tx_pointer) const;
      };

      class PointerTxHashEquality {
       public:
        bool operator()(const TxPointerType &left_tx,
                        const TxPointerType &right_tx) const;
      };

    }  // namespace detail

    class ProposalStorage final {
     public:
      using Round = iroha::consensus::Round;
      using Proposal = shared_model::proto::Proposal;
      using DefaultProvider = std::function<OrderingProposalRequestResult(
          const OrderingProposalRequest &)>;

      ProposalStorage();

      OrderingProposalRequestResult getProposal(
          const OrderingProposalRequest &round);

      ProposalStorage &storeProposal(const Round &round,
                                     std::shared_ptr<Proposal> proposal);

      /// Adds transactions to internal storage. When a proposal is asked for a
      /// round, and there was no storeProposal call for this round, a proposal
      /// with the transactions from internal storage will be returned
      void addTransactions(
          std::vector<std::shared_ptr<shared_model::interface::Transaction>>
              transactions);

      /// Adds batches to internal storage. When a proposal is asked for a
      /// round, and there was no storeProposal call for this round, a proposal
      /// with the transactions from internal storage will be returned
      void addBatches(const BatchesCollection &batches);

      ProposalStorage &setDefaultProvider(DefaultProvider provider);

     private:
      /// Create a proposal from pending transactions, if any.
      boost::optional<std::unique_ptr<Proposal>> makeProposalFromPendingTxs(
          shared_model::interface::types::HeightType height);

      OrderingProposalRequestResult getDefaultProposal(
          const Round &round) const;

      std::unique_ptr<shared_model::interface::UnsafeProposalFactory>
          proposal_factory_;

      std::shared_ptr<DefaultProvider> default_provider_;
      std::map<Round, std::shared_ptr<const Proposal>> proposals_map_;
      mutable std::shared_timed_mutex proposals_map_mutex_;

      std::unordered_set<std::shared_ptr<shared_model::interface::Transaction>,
                         detail::PointerTxHasher,
                         detail::PointerTxHashEquality>
          pending_txs_;
      mutable std::mutex pending_txs_mutex_;
    };

  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* INTEGRATION_FRAMEWORK_FAKE_PEER_PROPOSAL_STORAGE_HPP_ */
