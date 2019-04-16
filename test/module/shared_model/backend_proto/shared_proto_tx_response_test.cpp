/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"

#include <thread>

#include <gtest/gtest.h>
#include <boost/range/algorithm/for_each.hpp>
#include <boost/range/irange.hpp>
#include <boost/variant.hpp>
#include "cryptography/hash.hpp"

/**
 * @given protobuf's ToriiResponse with different tx_statuses and some hash
 * @when converting to shared model
 * @then ensure that status and hash remain the same
 */
TEST(ProtoTxResponse, TxResponseLoad) {
  iroha::protocol::ToriiResponse response;
  const std::string hash = "123";
  response.set_tx_hash(hash);
  auto desc = response.GetDescriptor();
  auto tx_status = desc->FindFieldByName("tx_status");
  ASSERT_NE(nullptr, tx_status);
  auto tx_status_enum = tx_status->enum_type();
  ASSERT_NE(nullptr, tx_status_enum);

  boost::for_each(boost::irange(0, tx_status_enum->value_count()), [&](auto i) {
    response.GetReflection()->SetEnumValue(
        &response, tx_status, tx_status_enum->value(i)->number());
    auto model_response = shared_model::proto::TransactionResponse(response);
    ASSERT_EQ(i, model_response.get().which());
    ASSERT_EQ(model_response.transactionHash(),
              shared_model::crypto::Hash::fromHexString(hash));
  });
}

/**
 * @given TransactionResponse that previously had lazy fields
 * @when those lazy fields are simultaneously accessed
 * @then there is no race condition and segfaults
 */
TEST(TxResponse, SafeToReadFromMultipleThreads) {
  const auto repetitions = 1000;
  // it usually throws a SIGSEGV during the first twenty iterations
  for (int counter = 0; counter < repetitions; ++counter) {
    iroha::protocol::ToriiResponse response;
    const std::string hash = "123";
    response.set_tx_hash(hash);
    response.set_tx_status(iroha::protocol::TxStatus::COMMITTED);
    auto model_response = shared_model::proto::TransactionResponse(response);

    auto multiple_access = [&model_response] {
      // old good way to cause race condition on lazy fields
      ASSERT_TRUE(model_response == model_response);
    };

    std::vector<std::thread> threads;
    const auto num_threads = 20;
    for (int i = 0; i < num_threads; ++i) {
      threads.emplace_back(multiple_access);
    }

    for (auto &thread : threads) {
      thread.join();
    }
  }
}
