/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/pending_transaction_storage_init.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include <rxcpp/operators/rx-flat_map.hpp>
#include "interfaces/iroha_internal/proposal.hpp"
#include "multi_sig_transactions/mst_processor.hpp"
#include "network/peer_communication_service.hpp"
#include "pending_txs_storage/impl/pending_txs_storage_impl.hpp"

using namespace iroha;

PendingTransactionStorageInit::PendingTransactionStorageInit()
/*: updated_batches(pending_storage_lifetime),
  prepared_batch(pending_storage_lifetime),
  expired_batch(pending_storage_lifetime),
  prepared_txs(pending_storage_lifetime)*/
{}

std::shared_ptr<PendingTransactionStorage>
PendingTransactionStorageInit::createPendingTransactionsStorage() {
  return PendingTransactionStorageImpl::create(/*updated_batches.get_observable(),
                                               prepared_batch.get_observable(),
                                               expired_batch.get_observable(),
                                               prepared_txs.get_observable(),
                                               finalized_txs.get_observable()*/);
}

/*void PendingTransactionStorageInit::setMstSubscriptions(
    const MstProcessor &mst_processor) {
  mst_processor.onStateUpdate().subscribe(pending_storage_lifetime,
                                          updated_batches.get_subscriber());
  mst_processor.onPreparedBatches().subscribe(pending_storage_lifetime,
                                              prepared_batch.get_subscriber());
  mst_processor.onExpiredBatches().subscribe(pending_storage_lifetime,
                                             expired_batch.get_subscriber());
}*/

/*void PendingTransactionStorageInit::setFinalizedTxsSubscription(
    rxcpp::observable<shared_model::interface::types::HashType> finalized_txs) {
  finalized_txs.subscribe(pending_storage_lifetime,
                          this->finalized_txs.get_subscriber());
}*/

PendingTransactionStorageInit::~PendingTransactionStorageInit() {
  // pending_storage_lifetime.unsubscribe();
}
