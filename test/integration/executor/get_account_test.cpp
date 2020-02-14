/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "backend/plain/account_detail_record_id.hpp"
#include "framework/common_constants.hpp"
#include "integration/executor/account_detail_checker.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using iroha::ametsuchi::QueryExecutorResult;
using shared_model::interface::AccountResponse;
using shared_model::interface::permissions::Role;

static const QuorumType kQuorum(1);

struct GetAccountTest : public ExecutorTestBase {
  /// prepare query target account.
  void prepareTargetAccount() {
    SCOPED_TRACE("GetAccountTest::prepareTargetAccount");
    const auto &detail = *details_.at(kAdminId).begin();
    IROHA_ASSERT_RESULT_VALUE(getItf().executeMaintenanceCommand(
        *getItf().getMockCommandFactory()->constructSetAccountDetail(
            kUserId, detail.first, detail.second)));
  }

  /// Query account.
  QueryExecutorResult query(const AccountIdType &query_issuer = kAdminId) {
    return getItf().executeQuery(
        *getItf().getMockQueryFactory()->constructGetAccount(kUserId),
        query_issuer);
  }

  void validateResponse(const AccountResponse &response) {
    EXPECT_EQ(response.account().accountId(), kUserId);
    EXPECT_EQ(response.account().domainId(), kDomain);
    EXPECT_EQ(response.account().quorum(), kQuorum);
    checkJsonData(response.account().jsonData(), details_);
  }

 protected:
  const DetailsByKeyByWriter details_{{{kAdminId, {{"key", "val"}}}}};
};

using GetAccountBasicTest = BasicExecutorTest<GetAccountTest>;

/**
 * @given a user with all related permissions
 * @when GetAccount is queried on non existent user
 * @then there is an NoAccountErrorResponse
 */
TEST_P(GetAccountBasicTest, NonexistentAccount) {
  checkQueryError<shared_model::interface::NoAccountErrorResponse>(
      getItf().executeQuery(
          *getItf().getMockQueryFactory()->constructGetAccount(kUserId)),
      0);
}

INSTANTIATE_TEST_SUITE_P(Base,
                         GetAccountBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using GetAccountPermissionTest =
    query_permission_test::QueryPermissionTest<GetAccountTest>;

TEST_P(GetAccountPermissionTest, QueryPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(prepareState({}));
  ASSERT_NO_FATAL_FAILURE(prepareTargetAccount());
  checkResponse<shared_model::interface::AccountResponse>(
      query(getSpectator()),
      [this](const shared_model::interface::AccountResponse &response) {
        this->validateResponse(response);
      });
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    GetAccountPermissionTest,
    query_permission_test::getParams({Role::kGetMyAccount},
                                     {Role::kGetDomainAccounts},
                                     {Role::kGetAllAccounts}),
    query_permission_test::paramToString);
