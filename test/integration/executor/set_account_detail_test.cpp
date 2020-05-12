/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "backend/plain/account_detail_record_id.hpp"
#include "common/result.hpp"
#include "framework/common_constants.hpp"
#include "integration/executor/account_detail_checker.hpp"
#include "integration/executor/command_permission_test.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using iroha::ametsuchi::QueryExecutorResult;
using shared_model::interface::AccountDetailResponse;
using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;
using shared_model::plain::AccountDetailRecordId;

static const AccountDetailKeyType kKey{"key"};
static const AccountDetailValueType kVal{"value"};

class SetAccountDetailTest : public ExecutorTestBase {
 public:
  iroha::ametsuchi::CommandResult setDetail(const AccountIdType &target,
                                            const AccountDetailKeyType &key,
                                            const AccountDetailValueType &value,
                                            const AccountIdType &issuer,
                                            bool validation_enabled = true) {
    return getItf().executeCommandAsAccount(
        *getItf().getMockCommandFactory()->constructSetAccountDetail(
            target, key, value),
        issuer,
        validation_enabled);
  }

  void checkDetails(AccountIdType account,
                    DetailsByKeyByWriter reference_details) {
    IROHA_ASSERT_RESULT_VALUE(
        getItf()
            .executeQueryAndConvertResult(
                *getItf().getMockQueryFactory()->constructGetAccountDetail(
                    account, std::nullopt, std::nullopt, std::nullopt))
            .specific_response
        | [&reference_details](const auto &response) {
            checkJsonData(response.detail(), reference_details);
            return iroha::expected::Value<void>{};
          });
  }
};

using SetAccountDetailBasicTest = BasicExecutorTest<SetAccountDetailTest>;

/**
 * C274
 * @given a user without can_set_detail permission
 * @when execute SetAccountDetail command to set own detail
 * @then the command succeeds and the detail is added
 */
TEST_P(SetAccountDetailBasicTest, Self) {
  getItf().createUserWithPerms(
      kUser, kDomain, PublicKeyHexStringView{kUserKeypair.publicKey()}, {});
  IROHA_ASSERT_RESULT_VALUE(setDetail(kUserId, kKey, kVal, kUserId));
  checkDetails(kUserId, DetailsByKeyByWriter{{{kUserId, {{kKey, kVal}}}}});
}

/**
 * C273
 * @given a user with all required permissions
 * @when execute SetAccountDetail command with nonexistent user
 * @then the command fails with error code 3
 */
TEST_P(SetAccountDetailBasicTest, NonExistentUser) {
  checkCommandError(setDetail(kUserId, kKey, kVal, kAdminId), 3);
}

/**
 * C280
 * @given a pair of users and first one without permissions
 * @when the first one tries to execute SetAccountDetail on the second
 * @then the command does not succeed and the detail is not added
 */
TEST_P(SetAccountDetailBasicTest, NoPerms) {
  getItf().createUserWithPerms(
      kUser, kDomain, PublicKeyHexStringView{kUserKeypair.publicKey()}, {});
  getItf().createUserWithPerms(
      kSecondUser,
      kDomain,
      PublicKeyHexStringView{kSameDomainUserKeypair.publicKey()},
      {});
  IROHA_ASSERT_RESULT_ERROR(setDetail(kSameDomainUserId, kKey, kVal, kUserId));
  checkDetails(kSameDomainUserId, DetailsByKeyByWriter{});
}

/**
 * @given a pair of users and first one has can_set_detail permission
 * @when the first one executes SetAccountDetail on the second
 * @then the command succeeds and the detail is added
 */
TEST_P(SetAccountDetailBasicTest, ValidRolePerm) {
  getItf().createUserWithPerms(kUser,
                               kDomain,
                               PublicKeyHexStringView{kUserKeypair.publicKey()},
                               {Role::kSetDetail});
  getItf().createUserWithPerms(
      kSecondUser,
      kDomain,
      PublicKeyHexStringView{kSameDomainUserKeypair.publicKey()},
      {});
  IROHA_ASSERT_RESULT_VALUE(setDetail(kUserId, kKey, kVal, kUserId));
  checkDetails(kUserId, DetailsByKeyByWriter{{{kUserId, {{kKey, kVal}}}}});
}

/**
 * @given a pair of users and first one has can_set_my_detail grantable
 * permission from the second
 * @when the first one executes SetAccountDetail on the second
 * @then the command succeeds and the detail is added
 */
TEST_P(SetAccountDetailBasicTest, ValidGrantablePerm) {
  getItf().createUserWithPerms(kUser,
                               kDomain,
                               PublicKeyHexStringView{kUserKeypair.publicKey()},
                               {Role::kSetMyAccountDetail});
  getItf().createUserWithPerms(
      kSecondUser,
      kDomain,
      PublicKeyHexStringView{kSameDomainUserKeypair.publicKey()},
      {});
  IROHA_ASSERT_RESULT_VALUE(getItf().executeCommandAsAccount(
      *getItf().getMockCommandFactory()->constructGrantPermission(
          kSameDomainUserId, Grantable::kSetMyAccountDetail),
      kUserId,
      true));
  IROHA_ASSERT_RESULT_VALUE(setDetail(kUserId, kKey, kVal, kUserId));
  checkDetails(kUserId, DetailsByKeyByWriter{{{kUserId, {{kKey, kVal}}}}});
}

/**
 * @given a pair of users and first one has root permission
 * @when the first one executes SetAccountDetail on the second
 * @then the command succeeds and the detail is added
 */
TEST_P(SetAccountDetailBasicTest, RootPermission) {
  getItf().createUserWithPerms(kUser,
                               kDomain,
                               PublicKeyHexStringView{kUserKeypair.publicKey()},
                               {Role::kRoot});
  getItf().createUserWithPerms(
      kSecondUser,
      kDomain,
      PublicKeyHexStringView{kSameDomainUserKeypair.publicKey()},
      {});
  IROHA_ASSERT_RESULT_VALUE(setDetail(kUserId, kKey, kVal, kUserId));
  checkDetails(kUserId, DetailsByKeyByWriter{{{kUserId, {{kKey, kVal}}}}});
}

INSTANTIATE_TEST_SUITE_P(Base,
                         SetAccountDetailBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using SetAccountDetailPermissionTest =
    command_permission_test::CommandPermissionTest<SetAccountDetailTest>;

TEST_P(SetAccountDetailPermissionTest, CommandPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(getItf().createDomain(kSecondDomain));
  ASSERT_NO_FATAL_FAILURE(prepareState({}));

  if (checkResponse(
          setDetail(kUserId, kKey, kVal, getActor(), getValidationEnabled()))) {
    checkDetails(kUserId, DetailsByKeyByWriter{{{getActor(), {{kKey, kVal}}}}});
  } else {
    checkDetails(kUserId, DetailsByKeyByWriter{});
  }
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    SetAccountDetailPermissionTest,
    command_permission_test::getParams(boost::none,
                                       boost::none,
                                       Role::kSetDetail,
                                       Grantable::kSetMyAccountDetail,
                                       true),
    command_permission_test::paramToString);
