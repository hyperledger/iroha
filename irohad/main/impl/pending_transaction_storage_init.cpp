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

PendingTransactionStorageInit::PendingTransactionStorageInit() {}

std::shared_ptr<PendingTransactionStorage>
PendingTransactionStorageInit::createPendingTransactionsStorage() {
  return PendingTransactionStorageImpl::create();
}
