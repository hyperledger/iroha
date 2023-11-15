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
#include "backend/protobuf/queries/proto_get_engine_receipts.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "framework/call_engine_tests_common.hpp"
#include "framework/common_constants.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "interfaces/query_responses/engine_receipt.hpp"
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

using CallResult = shared_model::interface::EngineReceipt::CallResult;

static const EvmCodeHexStringView kContractCode{
    "sit on a bench and have a rest"sv};
static const EvmCodeHexStringView kEvmInput{"summon satan"sv};

static const EvmAddressHexString kAddress1{"Patriarch's Ponds"};
static const EvmDataHexString kData1{"Ann has spilt the oil."};
static const EvmDataHexString kTopic1_1{"wasted"};
static const EvmDataHexString kTopic1_2{"fate"};

static const EvmAddressHexString kAddress2{"302a sadovaya street  "};
static const EvmDataHexString kData2{"Primus is being repared."};

static const EvmAddressHexString kAddress3{"satan's ball"};
static const EvmDataHexString kData3{"Manuscripts don't burn."};
static const EvmDataHexString kTopic3_1{"not wasted"};
static const EvmDataHexString kTopic3_2{"deal"};
static const EvmDataHexString kTopic3_3{"fate"};
static const EvmDataHexString kTopic3_4{"walpurgisnacht"};

static const std::string kCall2ResultData{"Falernus wine"};
static const CallResult kCall2Result{kAddress1, kCall2ResultData};

struct CallEngineCmd {
  std::string caller;
  std::optional<std::string> callee;
  EvmCodeHexStringView input;
  std::optional<std::string> created_address;
  std::optional<std::string> engine_response;
  std::vector<LogData> logs;
};

CallEngineCmd makeDeployCmd(std::string caller,
                            std::string created_address,
                            EvmCodeHexStringView code,
                            std::vector<LogData> logs) {
  return CallEngineCmd{std::move(caller),
                       std::nullopt,
                       code,
                       std::move(created_address),
                       std::nullopt,
                       std::move(logs)};
}

CallEngineCmd makeCallCmd(std::string caller,
                          EvmCalleeHexStringView callee,
                          EvmCodeHexStringView input,
                          std::string engine_response,
                          std::vector<LogData> logs) {
  return CallEngineCmd{std::move(caller),
                       std::string{callee},
                       input,
                       std::nullopt,
                       std::move(engine_response),
                       std::move(logs)};
}

const Matcher<shared_model::interface::EngineReceiptsResponse const &>
receiptsAre(Matcher<EngineReceiptCollectionType const &> m) {
  using namespace testing;
  using namespace shared_model::interface;
  return Property(&EngineReceiptsResponse::engineReceipts, m);
}

const Matcher<std::unique_ptr<shared_model::interface::EngineLog> const &>
logPtrIs(LogData const &log) {
  using namespace testing;
  using namespace shared_model::interface;
  return Pointee(AllOf(
      Property(&EngineLog::getAddress, log.address),
      Property(&EngineLog::getData, log.data),
      Property(&EngineLog::getTopics, UnorderedElementsAreArray(log.topics))));
}

inline std::vector<
    Matcher<std::unique_ptr<shared_model::interface::EngineLog> const &>>
logPtrMatchers(std::vector<LogData> const &logs) {
  std::vector<
      Matcher<std::unique_ptr<shared_model::interface::EngineLog> const &>>
      matchers;
  std::transform(
      logs.begin(), logs.end(), std::back_inserter(matchers), &logPtrIs);
  return matchers;
}

const Matcher<shared_model::interface::EngineReceipt const &> receiptIs(
    Matcher<CommandIndexType> cmd_index, CallEngineCmd const &cmd) {
  using namespace testing;
  using namespace shared_model::interface;
  return AllOf(
      Property(&EngineReceipt::getPayloadType,
               cmd.created_address
                   ? EngineReceipt::PayloadType::kPayloadTypeContractAddress
                   : EngineReceipt::PayloadType::kPayloadTypeCallResult),
      Property(&EngineReceipt::getResponseData,
               cmd.engine_response
                   ? std::make_optional(
                         CallResult{cmd.callee.value(), cmd.engine_response})
                   : std::optional<CallResult>{}),
      Property(&EngineReceipt::getContractAddress, cmd.created_address),
      Property(&EngineReceipt::getEngineLogs,
               UnorderedElementsAreArray(logPtrMatchers(cmd.logs))));
}

struct GetEngineReceiptsTest : public ExecutorTestBase {
  void SetUp() {
    ExecutorTestBase::SetUp();
  }

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
      std::string engine_response) {
    auto set_expectation = [this](auto &call) -> decltype(call) & {
      if (vm_call_expectation_) {
        return call.After(vm_call_expectation_.value());
      }
      return call;
    };
    vm_call_expectation_ =
        set_expectation(
            EXPECT_CALL(
                *getBackendParam().vm_caller_,
                call(tx_hash, cmd_idx, input, kUserId, callee, _, _, _)))
            .WillOnce(::testing::Return(
                iroha::expected::makeValue(std::move(engine_response))));
  }

  void commitTx(shared_model::proto::Transaction tx) {
    const auto block =
        TestBlockBuilder()
            .transactions(std::vector<shared_model::proto::Transaction>{tx})
            .height(1)
            .prevHash(shared_model::crypto::Hash{"prev_hash"})
            .createdTime(iroha::time::now())
            .build();
    const auto block_indexer = getBackendParam().getBlockIndexer();
    block_indexer->index(block);
  }

  iroha::expected::Result<std::string, iroha::ametsuchi::TxExecutionError>
  createAndCommitTx(std::string tx_creator,
                    std::vector<CallEngineCmd> commands) {
    auto tx_builder = TestTransactionBuilder{}.creatorAccountId(tx_creator);
    for (auto const &cmd : commands) {
      tx_builder = tx_builder.callEngine(
          cmd.caller,
          cmd.callee ? std::optional<EvmCalleeHexStringView>{cmd.callee}
                     : std::optional<EvmCalleeHexStringView>{},
          cmd.input);
    }
    auto tx = tx_builder.build();

    std::string tx_hash = tx.hash().hex();
    for (CommandIndexType cmd_idx = 0;
         cmd_idx < static_cast<CommandIndexType>(commands.size());
         ++cmd_idx) {
      auto const &cmd = commands[cmd_idx];
      const auto burrow_storage =
          getBackendParam().makeBurrowStorage(tx_hash, cmd_idx);
      for (auto const &log : cmd.logs) {
        burrow_storage->storeLog(
            log.address, log.data, {log.topics.begin(), log.topics.end()});
      }
      prepareVmCallerForCommand(
          tx_hash,
          cmd_idx,
          cmd.input,
          cmd.callee ? std::optional<EvmCalleeHexStringView>{cmd.callee}
                     : std::optional<EvmCalleeHexStringView>{},
          cmd.created_address ? cmd.created_address.value()
                              : cmd.engine_response.value());
    }

    return getItf().executeTransaction(tx) | [&]() {
      commitTx(std::move(tx));
      return tx_hash;
    };
  }

  void checkReceiptsResult(
      const shared_model::interface::EngineReceiptsResponse &response,
      std::vector<CallEngineCmd> const &commands) {
    using namespace testing;
    std::vector<Matcher<shared_model::interface::EngineReceipt const &>>
        receipts_matchers;
    for (CommandIndexType cmd_idx = 0;
         cmd_idx < static_cast<CommandIndexType>(commands.size());
         ++cmd_idx) {
      receipts_matchers.emplace_back(receiptIs(cmd_idx, commands[cmd_idx]));
    }
    EXPECT_THAT(response, receiptsAre(ElementsAreArray(receipts_matchers)));
  }

  void checkReceiptsForTx(std::string issuer,
                          std::string const &tx_hash,
                          std::vector<CallEngineCmd> const &commands) {
    checkSuccessfulResult<shared_model::interface::EngineReceiptsResponse>(
        getEngineReceipts(tx_hash, issuer),
        [&](const auto &response) { checkReceiptsResult(response, commands); });
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
  checkReceiptsForTx(kAdminId, "no such hash", {});
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

  CallEngineCmd cmd = makeDeployCmd(kUserId, kAddress1, kContractCode, {});
  std::string tx_hash = createAndCommitTx(kUserId, {cmd}).assumeValue();

  checkReceiptsForTx(kUserId, tx_hash, {cmd});
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

  CallEngineCmd cmd1 = makeDeployCmd(kUserId, kAddress1, kContractCode, {});
  CallEngineCmd cmd2 = makeCallCmd(
      kUserId,
      EvmCalleeHexStringView{kAddress1},
      kEvmInput,
      kCall2ResultData,
      {LogData{kAddress2, kData2, {}},
       LogData{
           kAddress3, kData3, {kTopic3_1, kTopic3_2, kTopic3_3, kTopic3_4}}});

  std::string tx1_hash = createAndCommitTx(kUserId, {cmd1}).assumeValue();
  std::string tx2_hash = createAndCommitTx(kUserId, {cmd2}).assumeValue();

  checkReceiptsForTx(kUserId, tx1_hash, {cmd1});
  checkReceiptsForTx(kUserId, tx2_hash, {cmd2});
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

  CallEngineCmd cmd1 = makeDeployCmd(kUserId, kAddress1, kContractCode, {});
  CallEngineCmd cmd2 = makeCallCmd(
      kUserId,
      EvmCalleeHexStringView{kAddress1},
      kEvmInput,
      kCall2ResultData,
      {LogData{kAddress2, kData2, {}},
       LogData{
           kAddress3, kData3, {kTopic3_1, kTopic3_2, kTopic3_3, kTopic3_4}}});

  std::string tx_hash = createAndCommitTx(kUserId, {cmd1, cmd2}).assumeValue();
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    GetEngineReceiptsPermissionTest,
    query_permission_test::getParams({Role::kGetMyEngineReceipts},
                                     {Role::kGetDomainEngineReceipts},
                                     {Role::kGetAllEngineReceipts}),
    query_permission_test::paramToString);
