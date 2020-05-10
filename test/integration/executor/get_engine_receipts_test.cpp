/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <string_view>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/format.hpp>
#include "ametsuchi/burrow_storage.hpp"
#include "ametsuchi/impl/block_index.hpp"
#include "backend/protobuf/queries/proto_get_engine_response.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "framework/common_constants.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "interfaces/query_responses/engine_response_record.hpp"
#include "module/irohad/ametsuchi/mock_vm_caller.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "queries.pb.h"

using namespace std::literals;

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using testing::_;

using iroha::ametsuchi::QueryExecutorResult;
using shared_model::interface::Amount;
using shared_model::interface::permissions::Role;

static const EvmCodeHexStringView kContractCode{
    "sit on a bench and have a rest"sv};
static const EvmCodeHexStringView kEvmInput{"summon satan"sv};

static const EvmAddressHexString kAddress1{"Patriarch's Ponds"};
static const EvmDataHexString kData1{"Ann has spilt the oil."};
static const EvmDataHexString kTopic1_1{"wasted"};
static const EvmDataHexString kTopic1_2{"fate"};

static const EvmAddressHexString kAddress2{"302A Sadovaya Street"};
static const EvmDataHexString kData2{"Primus is being repared."};

static const EvmAddressHexString kAddress3{"satan's ball"};
static const EvmDataHexString kData3{"Manuscripts don't burn."};
static const EvmDataHexString kTopic3_1{"not wasted"};
static const EvmDataHexString kTopic3_2{"deal"};
static const EvmDataHexString kTopic3_3{"fate"};
static const EvmDataHexString kTopic3_4{"walpurgisnacht"};

static const std::string kCall2ResultData{"Falernus wine"};
static const shared_model::interface::EngineReceipt::CallResult kCall2Result{
    kAddress1, kCall2ResultData};

const testing::Matcher<shared_model::interface::EngineReceiptsResponse const &>
getSpecificResponseChecker() {
  using namespace testing;
  using namespace shared_model::interface;
  return Property(
      &EngineReceiptsResponse::engineReceipts,
      ElementsAre(
          Matcher<EngineReceipt const &>(AllOf(
              Property(&EngineReceipt::getCaller, kUserId),
              Property(&EngineReceipt::getPayloadType,
                       EngineReceipt::PayloadType::kPayloadTypeContractAddress),
              Property(&EngineReceipt::getContractAddress, kAddress1),
              Property(&EngineReceipt::getResponseData, std::nullopt),
              Property(&EngineReceipt::getEngineLogs,
                       UnorderedElementsAre(Pointee(
                           AllOf(Property(&EngineLog::getAddress, kAddress1),
                                 Property(&EngineLog::getData, kData1),
                                 Property(&EngineLog::getTopics,
                                          UnorderedElementsAre(
                                              kTopic1_1, kTopic1_2)))))))),
          Matcher<EngineReceipt const &>(AllOf(
              Property(&EngineReceipt::getCaller, kUserId),
              Property(&EngineReceipt::getPayloadType,
                       EngineReceipt::PayloadType::kPayloadTypeCallResult),
              Property(&EngineReceipt::getContractAddress, std::nullopt),
              Property(&EngineReceipt::getResponseData, kCall2Result),
              Property(
                  &EngineReceipt::getEngineLogs,
                  UnorderedElementsAre(
                      Pointee(
                          AllOf(Property(&EngineLog::getAddress, kAddress2),
                                Property(&EngineLog::getData, kData2),
                                Property(&EngineLog::getTopics, IsEmpty()))),
                      Pointee(AllOf(Property(&EngineLog::getAddress, kAddress3),
                                    Property(&EngineLog::getData, kData3),
                                    Property(&EngineLog::getTopics,
                                             UnorderedElementsAre(
                                                 kTopic3_1,
                                                 kTopic3_2,
                                                 kTopic3_3,
                                                 kTopic3_4))))))))));
}

struct GetEngineReceiptsTest : public ExecutorTestBase {
  QueryExecutorResult getEngineReceipts(std::string const &tx_hash,
                                        AccountIdType const &issuer) {
    iroha::protocol::Query proto_query;
    {
      auto query = proto_query.mutable_payload()->mutable_get_engine_receipts();
      query->set_tx_hash(tx_hash);
    }
    return getItf().executeQuery(
        shared_model::proto::GetEngineReceipts{proto_query}, issuer);
  }

  /// @return hex hash of transaction that contains the call engine commands
  std::string prepareState() {
    SCOPED_TRACE("prepareState");
    getItf().createDomain(kSecondDomain);

    auto tx = TestTransactionBuilder{}
                  .creatorAccountId(kUserId)
                  .callEngine(kUserId, std::nullopt, kContractCode)
                  .callEngine(kUserId,
                              std::optional<EvmCalleeHexStringView>{kAddress1},
                              kEvmInput)
                  .build();
    std::string tx_hash = tx.hash().hex();
    CommandIndexType cmd_idx = 0;
    testing::Expectation vm_call_expectation;

    {  // cmd 1
      const auto burrow_storage =
          getBackendParam()->makeBurrowStorage(tx_hash, cmd_idx);
      burrow_storage->storeTxReceipt(kAddress1, kData1, {kTopic1_1, kTopic1_2});
      vm_call_expectation =
          EXPECT_CALL(*getBackendParam()->vm_caller_,
                      call(_,
                           tx_hash,
                           cmd_idx,
                           kContractCode,
                           kUserId,
                           std::optional<EvmCalleeHexStringView>{},
                           _,
                           _))
              .WillOnce(
                  ::testing::Return(iroha::expected::makeValue(kAddress1)));
    }

    {  // cmd 2
      const auto burrow_storage =
          getBackendParam()->makeBurrowStorage(tx_hash, ++cmd_idx);
      burrow_storage->storeTxReceipt(kAddress2, kData2, {});
      burrow_storage->storeTxReceipt(
          kAddress3, kData3, {kTopic3_1, kTopic3_2, kTopic3_3, kTopic3_4});
      vm_call_expectation =
          EXPECT_CALL(*getBackendParam()->vm_caller_,
                      call(_,
                           tx_hash,
                           cmd_idx,
                           kEvmInput,
                           kUserId,
                           std::optional<EvmCalleeHexStringView>(kAddress1),
                           _,
                           _))
              .After(vm_call_expectation)
              .WillOnce(::testing::Return(
                  iroha::expected::makeValue(kCall2ResultData)));
    }

    if (auto e = resultToOptionalError(getItf().executeTransaction(tx))) {
      throw std::runtime_error(e->command_error.toString());
    }

    {
      const auto block =
          TestBlockBuilder()
              .transactions(std::vector<shared_model::proto::Transaction>{tx})
              .height(1)
              .prevHash(shared_model::crypto::Hash{"prev_hash"})
              .createdTime(iroha::time::now())
              .build();
      const auto block_indexer = getBackendParam()->getBlockIndexer();
      block_indexer->index(block);
    }

    return tx_hash;
  }
};

using GetEngineReceiptsBasicTest = BasicExecutorTest<GetEngineReceiptsTest>;

/**
 * @given a user with all related permissions
 * @when GetEngineReceipts is queried on the nonexistent tx
 * @then there is an EngineReceiptsResponse reporting no receipts
 */
TEST_P(GetEngineReceiptsBasicTest, NoReceipts) {
  checkSuccessfulResult<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts("no such hash", kAdminId), [](const auto &response) {
        using namespace testing;
        EXPECT_EQ(boost::size(response.engineReceipts()), 0);
      });
}

INSTANTIATE_TEST_SUITE_P(Base,
                         GetEngineReceiptsBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using GetEngineReceiptsPermissionTest =
    query_permission_test::QueryPermissionTest<GetEngineReceiptsTest>;

TEST_P(GetEngineReceiptsPermissionTest, QueryPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(prepareState({Role::kCallEngine}));
  const auto tx_hash = GetEngineReceiptsTest::prepareState();
  checkResponse<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts(tx_hash, getSpectator()),
      [](const shared_model::interface::EngineReceiptsResponse &response) {
        EXPECT_THAT(response, getSpecificResponseChecker());
      });
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    GetEngineReceiptsPermissionTest,
    query_permission_test::getParams({Role::kGetMyEngineReceipts},
                                     {Role::kGetDomainEngineReceipts},
                                     {Role::kGetAllEngineReceipts}),
    query_permission_test::paramToString);
