/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/query_permission_test_signatories.hpp"

#include "interfaces/query_responses/signatories_response.hpp"

using namespace common_constants;

constexpr int kNumSignatories = 5;

QueryPermissionSignatories::QueryPermissionSignatories()
    : QueryPermissionTestBase({Role::kGetMySignatories},
                              {Role::kGetDomainSignatories},
                              {Role::kGetAllSignatories}) {
  std::generate_n(std::back_inserter(user_signatories_), kNumSignatories, []() {
    return crypto::DefaultCryptoAlgorithmType::generateKeypair().publicKey();
  });
}

IntegrationTestFramework &QueryPermissionSignatories::prepareState(
    AcceptanceFixture &fixture,
    const interface::RolePermissionSet &spectator_permissions) {
  auto target_permissions = spectator_permissions;
  target_permissions.set(Role::kAddSignatory);

  // initial state setup
  auto &itf = QueryPermissionTestBase::prepareState(
      fixture, spectator_permissions, target_permissions);

  // Add assets to target user
  for (const auto &public_key : user_signatories_) {
    itf.sendTxAwait(fixture.complete(fixture.baseTx(kUserId).addSignatory(
                                         kUserId, public_key),
                                     kUserKeypair),
                    getBlockTransactionsAmountChecker(1));
  }

  return itf;
}

std::function<void(const proto::QueryResponse &response)>
QueryPermissionSignatories::getGeneralResponseChecker() {
  return [this](const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const interface::SignatoriesResponse &>(response.get());

      const auto &resp_keys = resp.keys();
      ASSERT_EQ(
          boost::size(resp_keys),
          user_signatories_.size() + 1);  // 1 more for user's initial keypair

      // check that every initially added signatory key is in the result
      for (const auto &key : user_signatories_) {
        ASSERT_NE(std::find(resp_keys.begin(), resp_keys.end(), key),
                  resp_keys.end());
      }
      // check that user's initial public key is also in the result
      ASSERT_NE(
          std::find(
              resp_keys.begin(), resp_keys.end(), kUserKeypair.publicKey()),
          resp_keys.end());
    }) << "Actual response: "
       << response.toString();
  };
}

shared_model::proto::Query QueryPermissionSignatories::makeQuery(
    AcceptanceFixture &fixture,
    const interface::types::AccountIdType &target,
    const interface::types::AccountIdType &spectator,
    const crypto::Keypair &spectator_keypair) {
  return fixture.complete(fixture.baseQry(spectator).getSignatories(target),
                          spectator_keypair);
}
