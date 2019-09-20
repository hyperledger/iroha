/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"

using namespace iroha;

shared_model::crypto::Keypair makeKey() {
  return shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
}

TestTransactionBuilder txBuilder(
    const shared_model::interface::types::CounterType &counter,
    iroha::TimeType created_time,
    shared_model::interface::types::QuorumType quorum,
    shared_model::interface::types::AccountIdType account_id) {
  return TestTransactionBuilder()
      .createdTime(created_time)
      .creatorAccountId(account_id)
      .setAccountQuorum(account_id, counter)
      .quorum(quorum);
}

std::pair<shared_model::crypto::Signed, shared_model::crypto::PublicKey>
makeSignature(const std::string &sign, const std::string &public_key) {
  return std::make_pair(shared_model::crypto::Signed(sign),
                        shared_model::crypto::PublicKey(public_key));
}

std::shared_ptr<shared_model::proto::Transaction> makeTx(
    const shared_model::interface::types::CounterType &counter,
    iroha::TimeType created_time,
    shared_model::crypto::Keypair keypair,
    uint8_t quorum) {
  return std::make_shared<shared_model::proto::Transaction>(
      shared_model::proto::TransactionBuilder()
          .createdTime(created_time)
          .creatorAccountId("user@test")
          .setAccountQuorum("user@test", counter)
          .quorum(quorum)
          .build()
          .signAndAddSignature(keypair)
          .finish());
}

TestCompleter::TestCompleter() : DefaultCompleter(std::chrono::minutes(0)) {}

bool TestCompleter::isCompleted(const DataType &batch) const {
  return std::all_of(batch->transactions().begin(),
                     batch->transactions().end(),
                     [](const auto &tx) {
                       return boost::size(tx->signatures()) >= tx->quorum();
                     });
}

bool TestCompleter::isExpired(const DataType &batch,
                              const TimeType &current_time) const {
  return std::any_of(batch->transactions().begin(),
                     batch->transactions().end(),
                     [&current_time](const auto &tx) {
                       return tx->createdTime() < current_time;
                     });
}
