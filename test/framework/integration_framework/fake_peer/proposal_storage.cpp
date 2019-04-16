/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/proposal_storage.hpp"

#include <atomic>
#include <mutex>

#include <boost/range/adaptor/indirected.hpp>
#include "backend/protobuf/proto_proposal_factory.hpp"
#include "common/result.hpp"
#include "datetime/time.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/default_validator.hpp"

namespace integration_framework {
  namespace fake_peer {

    ProposalStorage::ProposalStorage()
        : proposal_factory_(
              std::make_unique<shared_model::proto::ProtoProposalFactory<
                  shared_model::validation::DefaultProposalValidator>>(
                  iroha::test::kTestsValidatorsConfig)) {
      setDefaultProvider([](auto &) { return boost::none; });
    }

    OrderingProposalRequestResult ProposalStorage::getProposal(
        const Round &round) {
      // check the proposals map
      {
        std::shared_lock<std::shared_timed_mutex> lock(proposals_map_mutex_);
        auto it = proposals_map_.find(round);
        if (it != proposals_map_.end()) {
          if (it->second) {
            return it->second;
          } else {
            return boost::none;
          }
        }
      }

      // check pending transactions
      if (auto proposal_from_pending_txs =
              makeProposalFromPendingTxs(round.block_round)) {
        return std::shared_ptr<const shared_model::proto::Proposal>(
            *std::move(proposal_from_pending_txs));
      }

      // finally, use the defualt
      return getDefaultProposal(round);
    }

    ProposalStorage &ProposalStorage::storeProposal(
        const Round &round, std::shared_ptr<Proposal> proposal) {
      std::lock_guard<std::shared_timed_mutex> lock(proposals_map_mutex_);
      const auto it = proposals_map_.find(round);
      if (it == proposals_map_.end()) {
        proposals_map_.emplace(round, proposal);
      } else {
        it->second = proposal;
      }
      return *this;
    }

    void ProposalStorage::addTransactions(
        std::vector<std::shared_ptr<shared_model::interface::Transaction>>
            transactions) {
      std::lock_guard<std::mutex> guard(pending_txs_mutex_);
      std::move(transactions.begin(),
                transactions.end(),
                std::inserter(pending_txs_, pending_txs_.end()));
    }

    void ProposalStorage::addBatches(const BatchesCollection &batches) {
      std::lock_guard<std::mutex> guard(pending_txs_mutex_);
      for (const auto &batch : batches) {
        std::copy(batch->transactions().begin(),
                  batch->transactions().end(),
                  std::inserter(pending_txs_, pending_txs_.end()));
      }
    }

    boost::optional<std::unique_ptr<shared_model::proto::Proposal>>
    ProposalStorage::makeProposalFromPendingTxs(
        shared_model::interface::types::HeightType height) {
      std::lock_guard<std::mutex> lock(pending_txs_mutex_);
      if (pending_txs_.empty()) {
        return boost::none;
      }

      std::unique_ptr<shared_model::proto::Proposal> proposal{
          dynamic_cast<shared_model::proto::Proposal *>(
              proposal_factory_
                  ->unsafeCreateProposal(
                      height,
                      iroha::time::now(),
                      pending_txs_ | boost::adaptors::indirected)
                  .release())};
      pending_txs_.clear();

      return proposal;
    }

    namespace detail {

      size_t PointerTxHasher::operator()(
          const TxPointerType &tx_pointer) const {
        return std::hash<std::string>{}(tx_pointer->reducedHash().hex());
      }

      bool PointerTxHashEquality::operator()(
          const TxPointerType &left_tx, const TxPointerType &right_tx) const {
        return left_tx->reducedHash() == right_tx->reducedHash();
      }

    }  // namespace detail

    ProposalStorage &ProposalStorage::setDefaultProvider(
        DefaultProvider provider) {
      std::atomic_store(&default_provider_,
                        std::make_shared<DefaultProvider>(std::move(provider)));
      return *this;
    }

    OrderingProposalRequestResult ProposalStorage::getDefaultProposal(
        const Round &round) const {
      auto default_provider = std::atomic_load(&default_provider_);
      if (default_provider) {
        return default_provider->operator()(round);
      }
      return {};
    }

  }  // namespace fake_peer
}  // namespace integration_framework
