/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/error_responses/stateful_failed_error_response.hpp"
#include "instantiate_test_suite.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

struct GetRoleFixture : AcceptanceFixture,
                        ::testing::WithParamInterface<StorageType> {};

INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(GetRoleFixture);

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 *
 * @given a user with CanGetRoles permission
 * @when execute query with getRoles command
 * @then the query returns list of roles
 */
TEST_P(GetRoleFixture, CanGetRoles) {
  auto checkQuery = [](auto &query_response) {
    ASSERT_NO_THROW(boost::get<const shared_model::interface::RolesResponse &>(
        query_response.get()));
  };

  auto query = TestUnsignedQueryBuilder()
                   .createdTime(iroha::time::now())
                   .creatorAccountId(kUserId)
                   .queryCounter(1)
                   .getRoles()
                   .build()
                   .signAndAddSignature(kUserKeypair)
                   .finish();

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms(
          {shared_model::interface::permissions::Role::kGetRoles}))
      .skipProposal()
      .checkBlock(
          [](auto &block) { ASSERT_EQ(boost::size(block->transactions()), 1); })
      .sendQuery(query, checkQuery);
}

/**
 * TODO mboldyrev 18.01.2019 IR-214 remove, covered by
 * postgres_query_executor_test GetRolesExecutorTest.Invalid
 *
 * @given a user without CanGetRoles permission
 * @when execute query with getRoles command
 * @then there is no way to to get roles due to user hasn't permissions enough
 */
TEST_P(GetRoleFixture, CanNotGetRoles) {
  auto checkQuery = [](auto &query_response) {
    ASSERT_NO_THROW({
      const auto &error_rsp =
          boost::get<const shared_model::interface::ErrorQueryResponse &>(
              query_response.get());
      boost::get<const shared_model::interface::StatefulFailedErrorResponse &>(
          error_rsp.get());
    });
  };

  auto query = TestUnsignedQueryBuilder()
                   .createdTime(iroha::time::now())
                   .creatorAccountId(kUserId)
                   .queryCounter(1)
                   .getRoles()
                   .build()
                   .signAndAddSignature(kUserKeypair)
                   .finish();

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({}))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); })
      .checkBlock(
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendQuery(query, checkQuery);
}
