/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TEST_HELPERS_HPP
#define IROHA_MST_TEST_HELPERS_HPP

#include <string>

#include "datetime/time.hpp"
#include "interfaces/common_objects/types.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"

shared_model::crypto::Keypair makeKey();

TestTransactionBuilder txBuilder(
    const shared_model::interface::types::CounterType &counter,
    iroha::TimeType created_time = iroha::time::now(),
    shared_model::interface::types::QuorumType quorum = 3,
    shared_model::interface::types::AccountIdType account_id = "user@test");

std::shared_ptr<shared_model::interface::TransactionBatch> addSignatures(
    std::shared_ptr<shared_model::interface::TransactionBatch> batch,
    int tx_number,
    std::pair<shared_model::crypto::Signed, shared_model::crypto::PublicKey>
        signature);

std::shared_ptr<shared_model::interface::TransactionBatch>
addSignaturesFromKeyPairs(
    std::shared_ptr<shared_model::interface::TransactionBatch> batch,
    int tx_number,
    shared_model::crypto::Keypair keypair);

std::pair<shared_model::crypto::Signed, shared_model::crypto::PublicKey>
makeSignature(const std::string &sign, const std::string &public_key);

std::shared_ptr<shared_model::proto::Transaction> makeTx(
    const shared_model::interface::types::CounterType &counter,
    iroha::TimeType created_time = iroha::time::now(),
    shared_model::crypto::Keypair keypair = makeKey(),
    uint8_t quorum = 3);

namespace iroha {
  class TestCompleter : public DefaultCompleter {
   public:
    explicit TestCompleter();

    bool isCompleted(const DataType &batch) const override;

    bool isExpired(const DataType &batch,
                   const TimeType &current_time) const override;
  };
}  // namespace iroha

#endif  // IROHA_MST_TEST_HELPERS_HPP
