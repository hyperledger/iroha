/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TEST_HELPERS_HPP
#define IROHA_MST_TEST_HELPERS_HPP

#include <string>
#include <string_view>

#include "builders/protobuf/transaction.hpp"
#include "datetime/time.hpp"
#include "framework/batch_helper.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

inline auto makeKey() {
  return shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
}

inline auto txBuilder(
    const shared_model::interface::types::CounterType &counter,
    shared_model::interface::types::TimestampType created_time =
        iroha::time::now(),
    shared_model::interface::types::QuorumType quorum = 3,
    shared_model::interface::types::AccountIdType account_id = "user@test") {
  return TestTransactionBuilder()
      .createdTime(created_time)
      .creatorAccountId(account_id)
      .setAccountQuorum(account_id, counter)
      .quorum(quorum);
}

template <typename... TxBuilders>
auto makeTestBatch(TxBuilders... builders) {
  return framework::batch::makeTestBatch(builders...);
}

template <typename Batch, typename... Signatures>
auto addSignatures(Batch &&batch, int tx_number, Signatures... signatures) {
  static logger::LoggerPtr log_ = getTestLogger("addSignatures");

  auto insert_signatures = [&](auto &&sig_pair) {
    batch->addSignature(
        tx_number,
        shared_model::interface::types::SignedHexStringView{sig_pair.first},
        shared_model::interface::types::PublicKeyHexStringView{
            sig_pair.second});
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
    auto signed_blob = shared_model::crypto::CryptoSigner::sign(
        shared_model::crypto::Blob(payload), key_pair);
    using namespace shared_model::interface::types;
    batch->addSignature(tx_number,
                        SignedHexStringView{signed_blob},
                        PublicKeyHexStringView{key_pair.publicKey()});
  };

  // pack expansion trick:
  // an ellipsis operator applies insert_signatures to each signature, operator
  // comma returns the rightmost argument, which is 0
  int temp[] = {(create_signature(std::forward<KeyPairs>(keypairs)), 0)...};
  // use unused variable
  (void)temp;

  return std::forward<Batch>(batch);
}

inline auto makeSignature(
    shared_model::interface::types::SignedHexStringView sign,
    shared_model::interface::types::PublicKeyHexStringView public_key) {
  return std::make_pair(std::string{std::string_view{sign}},
                        std::string{std::string_view{public_key}});
}

inline auto makeTx(const shared_model::interface::types::CounterType &counter,
                   shared_model::interface::types::TimestampType created_time =
                       iroha::time::now(),
                   shared_model::crypto::Keypair keypair = makeKey(),
                   uint8_t quorum = 3) {
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

#endif  // IROHA_MST_TEST_HELPERS_HPP
