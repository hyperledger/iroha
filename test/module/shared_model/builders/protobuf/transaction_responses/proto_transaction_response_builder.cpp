/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "builders/protobuf/transaction_responses/proto_transaction_status_builder.hpp"
#include "cryptography/hash.hpp"

using shared_model::proto::TransactionStatusBuilder;

template <typename T>
class ProtoTransactionStatusBuilderTest : public ::testing::Test {};

template <typename Iface,
          TransactionStatusBuilder (TransactionStatusBuilder::*Member)(),
          iroha::protocol::TxStatus Status>
struct TransactionResponseBuilderTestCase {
  using IfaceType = Iface;
  static constexpr auto member = Member;
  static constexpr auto status = Status;
};

using TransactionResponsTypes =
    ::testing::Types<TransactionResponseBuilderTestCase<
                         shared_model::interface::StatelessFailedTxResponse,
                         &TransactionStatusBuilder::statelessValidationFailed,
                         iroha::protocol::STATELESS_VALIDATION_FAILED>,
                     TransactionResponseBuilderTestCase<
                         shared_model::interface::StatelessValidTxResponse,
                         &TransactionStatusBuilder::statelessValidationSuccess,
                         iroha::protocol::STATELESS_VALIDATION_SUCCESS>,
                     TransactionResponseBuilderTestCase<
                         shared_model::interface::StatefulFailedTxResponse,
                         &TransactionStatusBuilder::statefulValidationFailed,
                         iroha::protocol::STATEFUL_VALIDATION_FAILED>,
                     TransactionResponseBuilderTestCase<
                         shared_model::interface::StatefulValidTxResponse,
                         &TransactionStatusBuilder::statefulValidationSuccess,
                         iroha::protocol::STATEFUL_VALIDATION_SUCCESS>,
                     TransactionResponseBuilderTestCase<
                         shared_model::interface::CommittedTxResponse,
                         &TransactionStatusBuilder::committed,
                         iroha::protocol::COMMITTED>,
                     TransactionResponseBuilderTestCase<
                         shared_model::interface::NotReceivedTxResponse,
                         &TransactionStatusBuilder::notReceived,
                         iroha::protocol::NOT_RECEIVED> >;
TYPED_TEST_CASE(ProtoTransactionStatusBuilderTest, TransactionResponsTypes, );

/**
 * @given expected transaction status and hash
 * @when model object is built using these status and hash
 * @then built object has expected status and hash
 */
TYPED_TEST(ProtoTransactionStatusBuilderTest, TestStatusType) {
  using StatusType = typename TypeParam::IfaceType;

  auto expected_status = TypeParam::status;
  auto expected_hash = std::string(32, '1');

  auto response =
      (TransactionStatusBuilder().*TypeParam::member)()
          .txHash(shared_model::crypto::Hash::fromHexString(expected_hash))
          .build();

  ASSERT_NO_THROW(boost::get<const StatusType &>(response.get()));

  auto proto_status = response.getTransport();
  ASSERT_EQ(proto_status.tx_status(), expected_status);
  ASSERT_EQ(proto_status.tx_hash(), expected_hash);
}

/**
 * @given fields for transaction status object
 * @when TransactionStatusBuilder is invoked twice with the same configuration
 * @then Two constructed TransactionStatus objects are identical
 */
TEST(ProtoTransactionStatusBuilderTest, SeveralObjectsFromOneBuilder) {
  auto expected_status = iroha::protocol::NOT_RECEIVED;
  auto expected_hash = std::string(32, '1');

  auto state = TransactionStatusBuilder().notReceived().txHash(
      shared_model::crypto::Hash::fromHexString(expected_hash));

  auto response1 = state.build();
  auto response2 = state.build();

  ASSERT_EQ(response1, response2);
  ASSERT_EQ(response1.getTransport().tx_hash(), expected_hash);
  ASSERT_EQ(response1.getTransport().tx_status(), expected_status);
}
