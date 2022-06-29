/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_GATE_HPP
#define IROHA_ON_DEMAND_ORDERING_GATE_HPP

#include "network/ordering_gate.hpp"

#include <memory>
#include <shared_mutex>

#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/unsafe_proposal_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "main/subscription.hpp"
#include "ordering/impl/on_demand_common.hpp"
#include "ordering/impl/proposal_cache.hpp"
#include "ordering/impl/round_switch.hpp"
#include "ordering/on_demand_ordering_service.hpp"
#include "ordering/on_demand_os_transport.hpp"

namespace iroha {
  namespace ametsuchi {
    class TxPresenceCache;
  }

  namespace ordering {

    /**
     * Ordering gate which requests proposals from the ordering service
     * votes for proposals, and passes committed proposals to the pipeline
     */
    class OnDemandOrderingGate
        : public network::OrderingGate,
          public std::enable_shared_from_this<OnDemandOrderingGate> {
     public:
      OnDemandOrderingGate(
          std::shared_ptr<OnDemandOrderingService> ordering_service,
          std::shared_ptr<transport::OdOsNotification> network_client,
          std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
              factory,
          std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
          size_t transaction_limit,
          logger::LoggerPtr log,
          bool syncing_mode);

      ~OnDemandOrderingGate() override;

      void initialize();

      void propagateBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> batch)
          override;

      void processRoundSwitch(RoundSwitch const &event);

      /**
       * Handle an incoming proposal from ordering service
       */
      void processProposalRequest(ProposalEvent &&event);
      std::optional<network::OrderingEvent> processProposalEvent(
          SingleProposalEvent &&event);

      void stop() override;

      consensus::Round getRound() const {
        return current_round_;
      }

     private:
      void sendCachedTransactions();

      template <typename Func, typename... Args>
      void forLocalOS(Func func, Args &&... args) {
        if (ordering_service_)
          (ordering_service_.get()->*func)(std::forward<Args>(args)...);
      }

      template <typename Func, typename... Args>
      void forLocalOS(Func func, Args &&... args) const {
        if (ordering_service_)
          (ordering_service_.get()->*func)(std::forward<Args>(args)...);
      }

      /**
       * remove already processed transactions from proposal
       */
      std::shared_ptr<const shared_model::interface::Proposal>
      removeReplaysAndDuplicates(
          std::shared_ptr<const shared_model::interface::Proposal> proposal)
          const;

      logger::LoggerPtr log_;

      /// max number of transactions passed to one ordering service
      size_t transaction_limit_;
      std::shared_ptr<OnDemandOrderingService> ordering_service_;
      std::shared_ptr<transport::OdOsNotification> network_client_;
      std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
          proposal_factory_;
      std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache_;
      consensus::Round current_round_;
      std::shared_ptr<const LedgerState> current_ledger_state_;
      std::shared_ptr<iroha::BaseSubscriber<bool, ProposalEvent>>
          failed_proposal_response_;

      std::shared_timed_mutex stop_mutex_;
      bool stop_requested_{false};
      bool syncing_mode_;
      ProposalCache proposal_cache_;
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_GATE_HPP
