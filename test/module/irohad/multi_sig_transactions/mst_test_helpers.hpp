/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TEST_HELPERS_HPP
#define IROHA_MST_TEST_HELPERS_HPP

#include <string>
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "datetime/time.hpp"
#include "framework/batch_helper.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/builders/protobuf/transaction.hpp"
#include "multi_sig_transactions/mst_types.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"

shared_model::crypto::Keypair makeKey();

TestTransactionBuilder txBuilder(
    const shared_model::interface::types::CounterType &counter,
    iroha::TimeType created_time = iroha::time::now(),
    shared_model::interface::types::QuorumType quorum = 3,
    shared_model::interface::types::AccountIdType account_id = "user@test");

template <typename... TxBuilders>
auto makeTestBatch(TxBuilders... builders) {
  return framework::batch::makeTestBatch(builders...);
}

template <typename Batch, typename... Signatures>
auto addSignatures(Batch &&batch, int tx_number, Signatures... signatures) {
  static logger::LoggerPtr log_ = getTestLogger("addSignatures");

  auto insert_signatures = [&](auto &&sig_pair) {
    batch->addSignature(tx_number, sig_pair.first, sig_pair.second);
  };

  // pack expansion trick:
  // an ellipsis operator applies insert_signatures to each signature, operator
  // comma returns the rightmost argument, which is 0
  int temp[] = {
      (insert_signatures(std::forward<Signatures>(signatures)), 0)...};
  // use unused variable
  (void)temp;

  log_->info("Number of signatures was inserted {}",
             boost::size(batch->transactions().at(tx_number)->signatures()));
  return std::forward<Batch>(batch);
}

template <typename Batch, typename... KeyPairs>
auto addSignaturesFromKeyPairs(Batch &&batch,
                               int tx_number,
                               KeyPairs... keypairs) {
  auto create_signature = [&](auto &&key_pair) {
    auto &payload = batch->transactions().at(tx_number)->payload();
    auto signed_blob = shared_model::crypto::CryptoSigner<>::sign(
        shared_model::crypto::Blob(payload), key_pair);
    batch->addSignature(tx_number, signed_blob, key_pair.publicKey());
  };

  // pack expansion trick:
  // an ellipsis operator applies insert_signatures to each signature, operator
  // comma returns the rightmost argument, which is 0
  int temp[] = {(create_signature(std::forward<KeyPairs>(keypairs)), 0)...};
  // use unused variable
  (void)temp;

  return std::forward<Batch>(batch);
}

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
