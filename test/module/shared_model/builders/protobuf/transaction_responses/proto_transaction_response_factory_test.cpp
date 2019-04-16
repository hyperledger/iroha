/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/proto_tx_status_factory.hpp"

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "cryptography/hash.hpp"

using shared_model::proto::ProtoTxStatusFactory;

/**
 * @given status and hash
 * @when  model object is built using these status and hash, but with committed
 *        status
 * @then  built object has expected status and hash
 */
TEST(ProtoTransactionStatusFactoryTest, TestStatusType) {
  auto expected_hash = shared_model::crypto::Hash(std::string(32, '1'));
  auto error_cmd = std::string("AddAssets");
  size_t error_cmd_index = 42;
  uint32_t error_code = 228;

  auto response = ProtoTxStatusFactory().makeCommitted(
      expected_hash,
      ProtoTxStatusFactory::TransactionError{
          error_cmd, error_cmd_index, error_code});

  ASSERT_EQ(response->transactionHash(), expected_hash);
  ASSERT_EQ(response->statelessErrorOrCommandName(), error_cmd);
  ASSERT_EQ(response->failedCommandIndex(), error_cmd_index);
  ASSERT_EQ(response->errorCode(), error_code);

  ASSERT_NO_THROW(
      boost::get<const shared_model::interface::CommittedTxResponse &>(
          response->get()));
}

/**
 * @given fields for transaction status object
 * @when  protoTransactionStatusFactory is invoked twice with the same
 *        configuration
 * @then  two constructed TransactionStatus objects are identical
 */
TEST(ProtoTransactionStatusFactoryTest, SeveralObjectsFromOneBuilder) {
  auto expected_hash = shared_model::crypto::Hash(std::string(32, '1'));
  auto error_cmd = std::string("AddAssets");
  size_t error_cmd_index = 42;
  uint32_t error_code = 228;

  auto response1 = ProtoTxStatusFactory().makeMstExpired(
      expected_hash,
      ProtoTxStatusFactory::TransactionError{
          error_cmd, error_cmd_index, error_code});

  auto response2 = ProtoTxStatusFactory().makeMstExpired(
      expected_hash,
      ProtoTxStatusFactory::TransactionError{
          error_cmd, error_cmd_index, error_code});

  ASSERT_EQ(*response1, *response2);
}
