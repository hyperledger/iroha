/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "backend/protobuf/transaction.hpp"
#include "converters/protobuf/json_proto_converter.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

using namespace shared_model::proto;
using namespace shared_model::converters::protobuf;
using namespace shared_model;

/**
 * Converts json into arbitrary transaction shared model object
 * @tparam T type of shared model object converted from json
 * @param json is the json string containing protobuf object
 * @return optional of shared model object, containing the
 * object if conversion was successful and error otherwise
 */
template <typename T, typename Checker>
void jsonToModelCheck(std::string json, Checker &&checker) {
  auto pb_result = jsonToProto<typename T::TransportType>(json);
  IROHA_ASSERT_RESULT_VALUE(pb_result);
  T proto{std::move(pb_result).assumeValue()};
  std::forward<Checker>(checker)(std::move(proto));
}

/**
 * @given sample transaction shared model object
 * @when transaction is converted to json and then converted back to shared
 * model object
 * @then original and obtained objects are equal
 */
TEST(JsonProtoConverterTest, JsonToProtoTxTest) {
  TestTransactionBuilder builder;

  std::string creator_account_id = "admin@test";

  auto orig_tx =
      builder.creatorAccountId(creator_account_id).createdTime(123).build();

  auto json = modelToJson(orig_tx);

  jsonToModelCheck<shared_model::proto::Transaction>(
      json, [&](const auto &obtained_tx) {
        ASSERT_EQ(orig_tx.getTransport().SerializeAsString(),
                  obtained_tx.getTransport().SerializeAsString());

        // check some field's values
        ASSERT_EQ(orig_tx.createdTime(), obtained_tx.createdTime());
        ASSERT_EQ(orig_tx.creatorAccountId(), obtained_tx.creatorAccountId());
      });
}

/**
 * @given invalid json string
 * @when json is converted to shared model object
 * @then none is returned
 */
TEST(JsonProtoConverterTest, InvalidJsonToProtoTx) {
  std::string json = "not json string";

  auto obtained_tx_result = jsonToProto<iroha::protocol::Transaction>(json);
  IROHA_ASSERT_RESULT_ERROR(obtained_tx_result);
}

/**
 * @given sample block shared model object
 * @when block is converted to json and then converted back to shared model
 * object
 * @then original and obtained objects are equal
 */
TEST(JsonProtoConverterTest, JsonToProtoBlockTest) {
  TestTransactionBuilder tx_builder;
  TestBlockBuilder block_builder;

  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(tx_builder.build());
  auto orig_block = block_builder.transactions(txs).createdTime(123).build();

  auto json = modelToJson(orig_block);

  jsonToModelCheck<shared_model::proto::Block>(
      std::move(json), [&](const auto &obtained_block) {
        ASSERT_EQ(orig_block.getTransport().SerializeAsString(),
                  obtained_block.getTransport().SerializeAsString());
      });
}
