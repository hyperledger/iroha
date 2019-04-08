/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_PROPAGATION_TO_PCS
#define IROHA_MST_PROPAGATION_TO_PCS

#include <list>

#include <rxcpp/rx.hpp>
#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/mst_types.hpp"
#include "network/peer_communication_service.hpp"
#include "storage_shared_limit/limitable_storage.hpp"
#include "storage_shared_limit/limited_storage.hpp"
#include "storage_shared_limit/storage_limit.hpp"

namespace iroha {

  class MstToPcsPropagation {
   public:
    MstToPcsPropagation(
        std::shared_ptr<iroha::network::PeerCommunicationService> pcs,
        std::shared_ptr<StorageLimit<BatchPtr>> storage_limit,
        rxcpp::observable<size_t> propagation_available,
        logger::LoggerPtr log);

    virtual ~MstToPcsPropagation();

    void notifyCompletedBatch(std::shared_ptr<MovedBatch> batch);

    size_t pendingBatchesQuantity() const;

   private:
    logger::LoggerPtr log_;
    std::shared_ptr<iroha::network::PeerCommunicationService> pcs_;

    struct InternalStorage : public LimitableStorage<BatchPtr> {
      bool insert(BatchPtr batch) override;

      // Batches not yet accepted by PCS in the order they were added.
      std::list<DataType> pending_batches;
    };

    LimitedStorage<InternalStorage> pending_batches_;

    rxcpp::composite_subscription propagation_available_subscription_;
  };

}  // namespace iroha

#endif  // IROHA_MST_PROPAGATION_TO_PCS
