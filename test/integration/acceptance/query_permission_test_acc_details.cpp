/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/query_permission_test_acc_details.hpp"

#include <regex>

#include "interfaces/query_responses/account_detail_response.hpp"
#include "framework/common_constants.hpp"

using namespace common_constants;

using interface::types::AccountDetailKeyType;
using interface::types::AccountDetailValueType;

QueryPermissionAccDetails::QueryPermissionAccDetails()
    : QueryPermissionTestBase({Role::kGetMyAccDetail},
                              {Role::kGetDomainAccDetail},
                              {Role::kGetAllAccDetail}) {
  user_acc_details_.emplace(std::make_pair(AccountDetailKeyType("key1"),
                                           AccountDetailValueType("val1")));
  user_acc_details_.emplace(std::make_pair(AccountDetailKeyType("key2"),
                                           AccountDetailValueType("val2")));
}

IntegrationTestFramework &QueryPermissionAccDetails::prepareState(
    AcceptanceFixture &fixture,
    const interface::RolePermissionSet &spectator_permissions) {
  auto target_permissions = spectator_permissions;
  target_permissions.set(Role::kSetDetail);

  // initial state setup
  auto &itf = QueryPermissionTestBase::prepareState(
      fixture, spectator_permissions, target_permissions);

  for (const auto &details : user_acc_details_) {
    itf.sendTxAwait(fixture.complete(fixture.baseTx(kUserId).setAccountDetail(
                        kUserId, details.first, details.second)),
                    getBlockTransactionsAmountChecker(1));
  }

  return itf;
}

/// check JSON value by key, disregarding hierarchy
void checkJSONvalue(const std::string &json_str,
                    const std::string &key,
                    const std::string &value) {
  std::regex keyval_regex(
      std::string("\"") + key + R"("[ \t\r\n]*:[ \t\r\n]*")" + value + "\"",
      std::regex_constants::ECMAScript);
  ASSERT_TRUE(std::regex_search(json_str, keyval_regex))
      << "Wrong JSON: expected " << key << " to have value " << value
      << ", but got " << std::endl
      << json_str << std::endl;
}

std::function<void(const proto::QueryResponse &response)>
QueryPermissionAccDetails::getGeneralResponseChecker() {
  return [this](const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const interface::AccountDetailResponse &>(response.get());

      const std::string &resp_str = resp.detail();

      for (const auto &expected_detail : user_acc_details_) {
        checkJSONvalue(resp_str, expected_detail.first, expected_detail.second);
      }
    }) << "Actual response: "
       << response.toString();
  };
}

shared_model::proto::Query QueryPermissionAccDetails::makeQuery(
    AcceptanceFixture &fixture,
    const interface::types::AccountIdType &target,
    const interface::types::AccountIdType &spectator,
    const crypto::Keypair &spectator_keypair) {
  return fixture.complete(
      fixture.baseQry(spectator).getAccountDetail(kMaxPageSize, target),
      spectator_keypair);
}
