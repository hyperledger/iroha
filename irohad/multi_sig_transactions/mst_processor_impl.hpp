/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_PROCESSOR_IMPL_HPP
#define IROHA_MST_PROCESSOR_IMPL_HPP

#include "multi_sig_transactions/mst_processor.hpp"
#include "network/mst_transport.hpp"

#include <memory>

#include <rxcpp/rx-lite.hpp>
#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/mst_propagation_strategy.hpp"
#include "multi_sig_transactions/mst_time_provider.hpp"
#include "multi_sig_transactions/storage/mst_storage.hpp"

namespace iroha {

  /**
   * Effective implementation of MstProcessor,
   * that implements gossip propagation of own state
   */
  class FairMstProcessor : public MstProcessor,
                           public iroha::network::MstTransportNotification {
   public:
    /**
     * @param transport - connection to other peers in network
     * @param storage  - repository for storing states
     * @param strategy - propagation mechanism for sharing state with others
     * @param time_provider - repository of current time
     */
    FairMstProcessor(std::shared_ptr<iroha::network::MstTransport> transport,
                     std::shared_ptr<MstStorage> storage,
                     std::shared_ptr<PropagationStrategy> strategy,
                     std::shared_ptr<MstTimeProvider> time_provider,
                     logger::LoggerPtr log);

    ~FairMstProcessor();

    // ------------------------| MstProcessor override |------------------------

    auto propagateBatchImpl(const DataType &batch)
        -> decltype(propagateBatch(batch)) override;

    bool batchInStorageImpl(const DataType &batch) const override;

    // ------------------| MstTransportNotification override |------------------

    void onNewState(shared_model::interface::types::PublicKeyHexStringView from,
                    MstState &&new_state) override;

    // ----------------------------| end override |-----------------------------

   private:
    // -----------------------------| private api |-----------------------------

    /**
     * Notify subscribers when some of the batches received all necessary
     * signatures and ready to move forward
     * @param state with those batches
     */
    void completedBatchesNotify(ConstRefState state) const;

    /**
     * Notify subscribers when some of the batches received new signatures, but
     * still are not completed
     * @param state with those batches
     */
    void updatedBatchesNotify(ConstRefState state) const;

    /**
     * Notify subscribers when some of the batches get expired
     * @param state with those batches
     */
    void expiredBatchesNotify(ConstRefState state) const;

    // -------------------------------| fields |--------------------------------
    logger::LoggerPtr log_;

    std::shared_ptr<iroha::network::MstTransport> transport_;
    std::shared_ptr<MstStorage> storage_;
    std::shared_ptr<PropagationStrategy> strategy_;
    std::shared_ptr<MstTimeProvider> time_provider_;

    /// use for tracking the propagation subscription
    rxcpp::composite_subscription propagation_subscriber_;
  };
}  // namespace iroha

#endif  // IROHA_MST_PROCESSOR_IMPL_HPP
