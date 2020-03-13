/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/command_client.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "endpoint_mock.grpc.pb.h"
#include "framework/mock_stream.h"
#include "framework/test_logger.hpp"

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::Return;

class CommandSyncClientTest : public testing::Test {
 public:
  void SetUp() override {
    auto ustub = std::make_unique<iroha::protocol::MockCommandService_v1Stub>();
    stub = ustub.get();
    client = std::make_shared<torii::CommandSyncClient>(
        std::move(ustub), getTestLogger("CommandSyncClient"));
  }

  iroha::protocol::MockCommandService_v1Stub *stub;
  std::shared_ptr<torii::CommandSyncClient> client;

  const size_t kHashLength = 32;
  const std::string kTxHash = std::string(kHashLength, '1');
};

/**
 * @given command client
 * @when Status is called
 * @then the stub handles passed data correctly (no corruptions in both
 * directions)
 */
TEST_F(CommandSyncClientTest, Status) {
  iroha::protocol::TxStatusRequest tx_request, intermediary_tx_request;
  tx_request.set_tx_hash(kTxHash);
  iroha::protocol::ToriiResponse torii_response, intermediary_response;
  intermediary_response.set_tx_hash(kTxHash);
  EXPECT_CALL(*stub, Status(_, _, _))
      .WillOnce(DoAll(::testing::SaveArg<1>(&intermediary_tx_request),
                      ::testing::SetArgPointee<2>(intermediary_response),
                      Return(::grpc::Status::OK)));
  auto stat = client->Status(tx_request, torii_response);
  ASSERT_EQ(kTxHash, intermediary_tx_request.tx_hash());
  ASSERT_EQ(kTxHash, torii_response.tx_hash());
  ASSERT_TRUE(stat.ok());
}

/**
 * @given command client
 * @when Torii is called
 * @then the stub handles passed data correctly (no corruptions in both
 * directions)
 */
TEST_F(CommandSyncClientTest, Torii) {
  iroha::protocol::Transaction tx, intermediary_tx;
  tx.mutable_payload()->mutable_reduced_payload()->set_creator_account_id(
      kTxHash);
  EXPECT_CALL(*stub, Torii(_, _, _))
      .WillOnce(DoAll(::testing::SaveArg<1>(&intermediary_tx),
                      ::testing::Return(::grpc::Status::OK)));
  auto stat = client->Torii(tx);
  ASSERT_EQ(kTxHash,
            intermediary_tx.payload().reduced_payload().creator_account_id());
  ASSERT_TRUE(stat.ok());
}

/**
 * @given command client
 * @when ListTorii is called
 * @then the stub handles passed data correctly (no corruptions in both
 * directions)
 */
TEST_F(CommandSyncClientTest, ListTorii) {
  iroha::protocol::TxList tx_list, intermediary_tx_list;
  tx_list.add_transactions()
      ->mutable_payload()
      ->mutable_reduced_payload()
      ->set_creator_account_id(kTxHash);
  EXPECT_CALL(*stub, ListTorii(_, _, _))
      .WillOnce(DoAll(::testing::SaveArg<1>(&intermediary_tx_list),
                      ::testing::Return(::grpc::Status::OK)));
  auto stat = client->ListTorii(tx_list);
  ASSERT_EQ(kTxHash,
            intermediary_tx_list.transactions()[0]
                .payload()
                .reduced_payload()
                .creator_account_id());
  ASSERT_TRUE(stat.ok());
}

/**
 * @given command client
 * @when StatusStream is called
 * @then the stub handles passed data correctly (no corruptions in both
 * directions)
 */
TEST_F(CommandSyncClientTest, StatusStream) {
  iroha::protocol::TxStatusRequest tx, intermediary_tx;
  iroha::protocol::ToriiResponse resp;
  auto hash = std::string(kHashLength, '1');
  tx.set_tx_hash(hash);
  resp.set_tx_hash(hash);
  std::vector<iroha::protocol::ToriiResponse> responses;
  auto reader = std::make_unique<
      grpc::testing::MockClientReader<::iroha::protocol::ToriiResponse>>();

  EXPECT_CALL(*reader, Read(_))
      .WillOnce(DoAll(::testing::SetArgPointee<0>(resp), Return(true)))
      .WillOnce(Return(false));
  EXPECT_CALL(*reader, Finish()).WillOnce(Return(::grpc::Status::OK));

  EXPECT_CALL(*stub, StatusStreamRaw(_, _))
      .WillOnce(DoAll(::testing::SaveArg<1>(&intermediary_tx),
                      Return(reader.release())));
  client->StatusStream(tx, responses);
  ASSERT_EQ(intermediary_tx.tx_hash(), resp.tx_hash());
  ASSERT_EQ(responses.size(), 1);
  ASSERT_EQ(responses[0].tx_hash(), resp.tx_hash());
}
