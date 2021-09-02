/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <string>
#include <string_view>

#include <gmock/gmock-actions.h>
#include <gtest/gtest.h>
#include "backend/protobuf/commands/proto_call_engine.hpp"
#include "commands.pb.h"
#include "framework/common_constants.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "integration/executor/command_permission_test.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"
#include "interfaces/permissions.hpp"
#include "module/irohad/ametsuchi/mock_vm_caller.hpp"

using namespace std::literals;
using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;
using ::testing::_;
using ::testing::Optional;

static const EvmCalleeHexStringView kCallee{"callee"sv};
static const EvmCodeHexStringView kCode{"mint(many)"sv};

class CallEngineTest : public ExecutorTestBase {
 public:
  void SetUp() {
    ExecutorTestBase::SetUp();
    if (type_ == ExecutorTestParam::ExecutorType::kRocksDb)
      GTEST_SKIP();
  }

  iroha::ametsuchi::CommandResult callEngine(
      const AccountIdType &issuer,
      const AccountIdType &caller,
      std::optional<EvmCalleeHexStringView> callee,
      EvmCodeHexStringView input,
      bool validation_enabled = true) {
    iroha::protocol::Command proto_command;
    {
      auto command = proto_command.mutable_call_engine();
      command->set_type(iroha::protocol::CallEngine::EngineType::
                            CallEngine_EngineType_kSolidity);
      command->set_caller(caller);
      if (callee) {
        std::string_view callee_sv{callee.value()};
        command->set_callee(callee_sv.data(), callee_sv.size());
      }
      const auto input_sv = static_cast<std::string_view const &>(input);
      command->set_input(input_sv.data(), input_sv.size());
    }
    return getItf().executeCommandAsAccount(
        shared_model::proto::CallEngine{proto_command},
        issuer,
        validation_enabled);
  }
};

using CallEngineBasicTest = BasicExecutorTest<CallEngineTest>;

/**
 * @given a user with all related permissions
 * @when execute CallEngine command from that user for nonexistent asset
 * @then the command fails
 * @and the asset is not added to the user
 */
TEST_P(CallEngineBasicTest, EngineError) {
  EXPECT_CALL(*getBackendParam().vm_caller_,
              call(_, _, kCode, kAdminId, Optional(kCallee), _, _, _))
      .WillOnce(::testing::Return(iroha::expected::makeError("engine error")));
  checkCommandError(callEngine(kAdminId, kAdminId, kCallee, kCode), 3);
}

INSTANTIATE_TEST_SUITE_P(Base,
                         CallEngineBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using CallEnginePermissionTest =
    command_permission_test::CommandPermissionTest<CallEngineTest>;

TEST_P(CallEnginePermissionTest, CommandPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(prepareState({}));

  EXPECT_CALL(*getBackendParam().vm_caller_,
              call(_, _, kCode, kUserId, Optional(kCallee), _, _, _))
      .Times(isEnoughPermissions() ? 1 : 0)
      .WillRepeatedly(::testing::Return(iroha::expected::makeValue("success")));

  checkResponse(
      callEngine(getActor(), kUserId, kCallee, kCode, getValidationEnabled()));
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    CallEnginePermissionTest,
    command_permission_test::getParams(Role::kCallEngine,
                                       boost::none,
                                       boost::none,
                                       Grantable::kCallEngineOnMyBehalf),
    command_permission_test::paramToString);
