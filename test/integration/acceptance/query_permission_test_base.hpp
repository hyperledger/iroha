/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef QUERY_PERMISSION_TEST_BASE_HPP_
#define QUERY_PERMISSION_TEST_BASE_HPP_

#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/query_permission_fixture.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace shared_model;
using namespace integration_framework;
using namespace shared_model::interface::permissions;

using BlockType = std::shared_ptr<const shared_model::interface::Block>;

/**
 * @return a functor that verifies that query response contains specific error
 */
template <typename TError>
auto inline getQueryErrorChecker() {
  return [](auto &response) {
    ASSERT_TRUE(boost::apply_visitor(
        shared_model::interface::QueryErrorResponseChecker<TError>(),
        response.get()))
        << "Actual response: " << response.toString();
  };
}

static auto &getQueryStatefullyInvalidChecker =
    getQueryErrorChecker<shared_model::interface::StatefulFailedErrorResponse>;
static auto &getQueryStatelesslyInvalidChecker =
    getQueryErrorChecker<shared_model::interface::StatelessFailedErrorResponse>;

/**
 * @return a functor that checks that a block contains exactly the specified
 * amount of transactions
 */
std::function<void(const BlockType &)> getBlockTransactionsAmountChecker(
    int amount);

class QueryPermissionTestBase {
 public:
  std::unique_ptr<IntegrationTestFramework> itf_;

  QueryPermissionTestBase(
      const interface::RolePermissionSet &permission_to_query_myself,
      const interface::RolePermissionSet &permission_to_query_my_domain,
      const interface::RolePermissionSet &permission_to_query_everyone);

  virtual ~QueryPermissionTestBase() = default;

  /**
   * Prepare state of ledger:
   * - create accounts of target user, close and remote spectators (close
   *   spectator - another user from the same domain as the domain of target
   *   user account, remote - a user from domain different to domain of target
   *   user account).
   *
   * @param spectator_permissions - set of query permisisons for target user's
   * and spectators' accounts
   * @param target_permissions - set of additional permisisons for target user
   * @return reference to ITF
   */
  IntegrationTestFramework &prepareState(
      AcceptanceFixture &fixture,
      const interface::RolePermissionSet &spectator_permissions,
      const interface::RolePermissionSet &target_permissions);

  /**
   * Implementations must define this function to create the tested query.
   *
   * @param target - the queried user
   * @param spectator - the user issuing a query
   * @param spectator_keypair - spectator's keypair
   */
  virtual shared_model::proto::Query makeQuery(
      AcceptanceFixture &fixture,
      const interface::types::AccountIdType &target,
      const interface::types::AccountIdType &spectator,
      const crypto::Keypair &spectator_keypair) = 0;

  /**
   * Implementations must define this function to check general response
   * validity.
   */
  virtual std::function<void(const proto::QueryResponse &response)>
  getGeneralResponseChecker() = 0;

  const interface::RolePermissionSet kPermissionToQueryMyself;
  const interface::RolePermissionSet kPermissionToQueryMyDomain;
  const interface::RolePermissionSet kPermissionToQueryEveryone;
};

#endif /* QUERY_PERMISSION_TEST_BASE_HPP_ */
