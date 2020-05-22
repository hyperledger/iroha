/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <optional>
#include <string_view>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/format.hpp>
#include <utility>
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
using testing::Matcher;

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

const Matcher<shared_model::interface::EngineReceiptsResponse const &>
receiptsAre(Matcher<EngineReceiptCollectionType const &> m) {
  using namespace testing;
  using namespace shared_model::interface;
  return Property(&EngineReceiptsResponse::engineReceipts, m);
}

const Matcher<shared_model::interface::EngineReceipt const &> receiptIsDeploy(
    Matcher<CommandIndexType> cmd_index,
    Matcher<AccountIdType> caller,
    Matcher<std::string_view> deployed_address,
    std::vector<
        Matcher<std::unique_ptr<shared_model::interface::EngineLog> const &>>
        logs) {
  using namespace testing;
  using namespace shared_model::interface;
  return AllOf(
      Property(&EngineReceipt::getCommandIndex, cmd_index),
      Property(&EngineReceipt::getCaller, caller),
      Property(&EngineReceipt::getPayloadType,
               EngineReceipt::PayloadType::kPayloadTypeContractAddress),
      Property(&EngineReceipt::getResponseData, std::nullopt),
      Property(&EngineReceipt::getContractAddress, Optional(deployed_address)),
      Property(&EngineReceipt::getEngineLogs, UnorderedElementsAreArray(logs)));
}

const Matcher<shared_model::interface::EngineReceipt const &> receiptIsCall(
    Matcher<CommandIndexType> cmd_index,
    Matcher<AccountIdType> caller,
    Matcher<shared_model::interface::EngineReceipt::CallResult> call_result,
    std::vector<
        Matcher<std::unique_ptr<shared_model::interface::EngineLog> const &>>
        logs) {
  using namespace testing;
  using namespace shared_model::interface;
  return AllOf(
      Property(&EngineReceipt::getCommandIndex, cmd_index),
      Property(&EngineReceipt::getCaller, caller),
      Property(&EngineReceipt::getPayloadType,
               EngineReceipt::PayloadType::kPayloadTypeCallResult),
      Property(&EngineReceipt::getResponseData, Optional(call_result)),
      Property(&EngineReceipt::getContractAddress, std::nullopt),
      Property(&EngineReceipt::getEngineLogs, UnorderedElementsAreArray(logs)));
}

const Matcher<std::unique_ptr<shared_model::interface::EngineLog> const &>
logPtrIs(Matcher<EvmAddressHexString> address,
         Matcher<EvmDataHexString> data,
         std::vector<Matcher<EvmTopicsHexString>> topics) {
  using namespace testing;
  using namespace shared_model::interface;
  return Pointee(AllOf(
      Property(&EngineLog::getAddress, address),
      Property(&EngineLog::getData, data),
      Property(&EngineLog::getTopics, UnorderedElementsAreArray(topics))));
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

  void prepareVmCallerForCommand(
      std::string const &tx_hash,
      CommandIndexType cmd_idx,
      Matcher<EvmCodeHexStringView> input,
      Matcher<std::optional<EvmCalleeHexStringView>> callee,
      iroha::expected::Result<std::string, std::string> engine_response) {
    auto set_expectation = [this](auto &call) -> decltype(call) & {
      if (vm_call_expectation_) {
        return call.After(vm_call_expectation_.value());
      }
      return call;
    };
    vm_call_expectation_ =
        set_expectation(
            EXPECT_CALL(
                *getBackendParam()->vm_caller_,
                call(_, tx_hash, cmd_idx, input, kUserId, callee, _, _)))
            .WillOnce(::testing::Return(std::move(engine_response)));
  }

  void commitTx(shared_model::proto::Transaction tx) {
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

  std::optional<testing::Expectation> vm_call_expectation_;
};

using GetEngineReceiptsBasicTest = BasicExecutorTest<GetEngineReceiptsTest>;

/**
 * @given a user with all related permissions
 * @when GetEngineReceipts is queried on the nonexistent tx
 * @then there is an EngineReceiptsResponse reporting no receipts
 */
TEST_P(GetEngineReceiptsBasicTest, NoSuchTx) {
  checkSuccessfulResult<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts("no such hash", kAdminId), [](const auto &response) {
        using namespace testing;
        EXPECT_EQ(boost::size(response.engineReceipts()), 0);
      });
}

/**
 * @given a user with all related permissions
 * @when GetEngineReceipts is queried on a tx with vm call with no logs
 * @then there is one receipt with no logs
 */
TEST_P(GetEngineReceiptsBasicTest, DeployWithNoLogs) {
  getItf().createUserWithPerms(kUser,
                               kDomain,
                               PublicKeyHexStringView{kUserKeypair.publicKey()},
                               {Role::kCallEngine, Role::kGetMyEngineReceipts});

  auto tx = TestTransactionBuilder{}
                .creatorAccountId(kUserId)
                .callEngine(kUserId, std::nullopt, kContractCode)
                .build();
  std::string tx_hash = tx.hash().hex();
  CommandIndexType cmd_idx = 0;

  {  // cmd 1
    prepareVmCallerForCommand(tx_hash,
                              cmd_idx,
                              kContractCode,
                              std::optional<EvmCalleeHexStringView>{},
                              iroha::expected::makeValue(kAddress1));
  }

  IROHA_ASSERT_RESULT_VALUE(getItf().executeTransaction(tx));

  commitTx(std::move(tx));

  checkSuccessfulResult<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts(tx_hash, kUserId), [](const auto &response) {
        using namespace testing;
        EXPECT_THAT(response,
                    receiptsAre(ElementsAre(receiptIsDeploy(
                        0, kUserId, std::string_view{kAddress1}, {}))));
      });
}

/**
 * @given a user with all related permissions and 2 txs with engine calls
 * @when GetEngineReceipts is queried on each tx
 * @then there are correct receipts
 */
TEST_P(GetEngineReceiptsBasicTest, TwoTxs) {
  getItf().createUserWithPerms(kUser,
                               kDomain,
                               PublicKeyHexStringView{kUserKeypair.publicKey()},
                               {Role::kCallEngine, Role::kGetMyEngineReceipts});

  // --- first transaction with contract deployment command --- //

  auto tx1 = TestTransactionBuilder{}
                 .creatorAccountId(kUserId)
                 .callEngine(kUserId, std::nullopt, kContractCode)
                 .build();
  const std::string tx1_hash = tx1.hash().hex();
  CommandIndexType cmd_idx = 0;

  {  // cmd 1
    prepareVmCallerForCommand(tx1_hash,
                              cmd_idx,
                              kContractCode,
                              std::optional<EvmCalleeHexStringView>{},
                              iroha::expected::makeValue(kAddress1));
  }

  IROHA_ASSERT_RESULT_VALUE(getItf().executeTransaction(tx1));

  commitTx(std::move(tx1));

  // --- second transaction with contract invocation command --- //

  auto tx2 = TestTransactionBuilder{}
                 .creatorAccountId(kUserId)
                 .callEngine(kUserId,
                             std::optional<EvmCalleeHexStringView>{kAddress1},
                             kEvmInput)
                 .build();
  const std::string tx2_hash = tx2.hash().hex();

  {  // cmd 1
    const auto burrow_storage =
        getBackendParam()->makeBurrowStorage(tx2_hash, cmd_idx);
    burrow_storage->storeLog(kAddress2, kData2, {});
    burrow_storage->storeLog(
        kAddress3, kData3, {kTopic3_1, kTopic3_2, kTopic3_3, kTopic3_4});
    prepareVmCallerForCommand(tx2_hash,
                              cmd_idx,
                              kEvmInput,
                              std::optional<EvmCalleeHexStringView>(kAddress1),
                              iroha::expected::makeValue(kCall2ResultData));
  }

  IROHA_ASSERT_RESULT_VALUE(getItf().executeTransaction(tx2));

  commitTx(std::move(tx2));

  // --- receipts queries --- //

  checkSuccessfulResult<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts(tx1_hash, kUserId), [](const auto &response) {
        using namespace testing;
        EXPECT_THAT(response,
                    receiptsAre(ElementsAre(receiptIsDeploy(
                        0, kUserId, std::string_view{kAddress1}, {}))));
      });

  checkSuccessfulResult<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts(tx2_hash, kUserId), [](const auto &response) {
        using namespace testing;
        EXPECT_THAT(
            response,
            receiptsAre(ElementsAre(receiptIsCall(
                0,
                kUserId,
                kCall2Result,
                {logPtrIs(kAddress2, kData2, {}),
                 logPtrIs(kAddress3,
                          kData3,
                          {kTopic3_1, kTopic3_2, kTopic3_3, kTopic3_4})}))));
      });
}

INSTANTIATE_TEST_SUITE_P(Base,
                         GetEngineReceiptsBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using GetEngineReceiptsPermissionTest =
    query_permission_test::QueryPermissionTest<GetEngineReceiptsTest>;

TEST_P(GetEngineReceiptsPermissionTest, QueryPermissionTest) {
  getItf().createDomain(kSecondDomain);

  ASSERT_NO_FATAL_FAILURE(prepareState({Role::kCallEngine}));

  auto tx = TestTransactionBuilder{}
                .creatorAccountId(kUserId)
                .callEngine(kUserId, std::nullopt, kContractCode)
                .callEngine(kUserId,
                            std::optional<EvmCalleeHexStringView>{kAddress1},
                            kEvmInput)
                .build();
  std::string tx_hash = tx.hash().hex();
  CommandIndexType cmd_idx = 0;

  {  // cmd 1
    const auto burrow_storage =
        getBackendParam()->makeBurrowStorage(tx_hash, cmd_idx);
    burrow_storage->storeLog(kAddress1, kData1, {kTopic1_1, kTopic1_2});
    prepareVmCallerForCommand(tx_hash,
                              cmd_idx,
                              kContractCode,
                              std::optional<EvmCalleeHexStringView>{},
                              iroha::expected::makeValue(kAddress1));
  }

  {  // cmd 2
    const auto burrow_storage =
        getBackendParam()->makeBurrowStorage(tx_hash, ++cmd_idx);
    burrow_storage->storeLog(kAddress2, kData2, {});
    burrow_storage->storeLog(
        kAddress3, kData3, {kTopic3_1, kTopic3_2, kTopic3_3, kTopic3_4});
    prepareVmCallerForCommand(tx_hash,
                              cmd_idx,
                              kEvmInput,
                              std::optional<EvmCalleeHexStringView>(kAddress1),
                              iroha::expected::makeValue(kCall2ResultData));
  }

  IROHA_ASSERT_RESULT_VALUE(getItf().executeTransaction(tx));

  commitTx(std::move(tx));

  checkResponse<shared_model::interface::EngineReceiptsResponse>(
      getEngineReceipts(tx_hash, getSpectator()),
      [](const shared_model::interface::EngineReceiptsResponse &response) {
        using namespace testing;
        using namespace shared_model::interface;
        EXPECT_THAT(
            response,
            receiptsAre(ElementsAre(
                receiptIsDeploy(
                    0,
                    kUserId,
                    std::string_view{kAddress1},
                    {logPtrIs(kAddress1, kData1, {kTopic1_1, kTopic1_2})}),
                receiptIsCall(
                    1,
                    kUserId,
                    kCall2Result,
                    {logPtrIs(kAddress2, kData2, {}),
                     logPtrIs(
                         kAddress3,
                         kData3,
                         {kTopic3_1, kTopic3_2, kTopic3_3, kTopic3_4})}))));
      });
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    GetEngineReceiptsPermissionTest,
    query_permission_test::getParams({Role::kGetMyEngineReceipts},
                                     {Role::kGetDomainEngineReceipts},
                                     {Role::kGetAllEngineReceipts}),
    query_permission_test::paramToString);
