/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef QUERY_PERMISSION_TEST_ACC_DETAILS_HPP_
#define QUERY_PERMISSION_TEST_ACC_DETAILS_HPP_

#include "query_permission_test_base.hpp"

using namespace shared_model;
using namespace integration_framework;
using namespace shared_model::interface::permissions;
using namespace common_constants;

class QueryPermissionAccDetails final : public QueryPermissionTestBase {
 public:
  QueryPermissionAccDetails();

  /**
   * Prepare state of ledger:
   * - create accounts of target user, close and remote spectators (close
   *   spectator - another user from the same domain as the domain of target
   *   user account, remote - a user from domain different to domain of target
   *   user account).
   * - fill some details of the user account
   *
   * @param spectator_permissions - set of query permisisons for target user's
   * and spectators' accounts
   * @return reference to ITF
   */
  IntegrationTestFramework &prepareState(
      AcceptanceFixture &fixture,
      const interface::RolePermissionSet &spectator_permissions);

  shared_model::proto::Query makeQuery(
      AcceptanceFixture &fixture,
      const interface::types::AccountIdType &target,
      const interface::types::AccountIdType &spectator,
      const crypto::Keypair &spectator_keypair) override;

  /**
   * @return a functor verifying that query response contains all the
   * account detail data
   */
  std::function<void(const proto::QueryResponse &response)>
  getGeneralResponseChecker() override;

  std::map<interface::types::AccountDetailKeyType,
           interface::types::AccountDetailValueType>
      user_acc_details_;
};

#endif /* QUERY_PERMISSION_TEST_ACC_DETAILS_HPP_ */
