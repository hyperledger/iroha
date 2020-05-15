/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "query_permission_test_base.hpp"

using namespace common_constants;

using shared_model::interface::types::PublicKeyHexStringView;

QueryPermissionTestBase::QueryPermissionTestBase(
    const interface::RolePermissionSet &permission_to_query_myself,
    const interface::RolePermissionSet &permission_to_query_my_domain,
    const interface::RolePermissionSet &permission_to_query_everyone)
    : kPermissionToQueryMyself(permission_to_query_myself),
      kPermissionToQueryMyDomain(permission_to_query_my_domain),
      kPermissionToQueryEveryone(permission_to_query_everyone) {}

IntegrationTestFramework &QueryPermissionTestBase::prepareState(
    AcceptanceFixture &fixture,
    const interface::RolePermissionSet &spectator_permissions,
    const interface::RolePermissionSet &target_permissions) {
  return itf_
      ->sendTxAwait(fixture.makeUserWithPerms(target_permissions),
                    getBlockTransactionsAmountChecker(1))
      .sendTxAwait(
          fixture.complete(
              fixture.baseTx(kAdminId)
                  .createRole(kSecondUser, spectator_permissions)
                  .createDomain(kSecondDomain, kSecondUser)
                  .createAccount(kSecondUser,
                                 kDomain,
                                 PublicKeyHexStringView{
                                     kSameDomainUserKeypair.publicKey()})
                  .createAccount(kSecondUser,
                                 kSecondDomain,
                                 PublicKeyHexStringView{
                                     kSecondDomainUserKeypair.publicKey()})
                  // Assign the close spectator the spectator role. Remote
                  // spectator gets this role by default (from domain)
                  .appendRole(kSameDomainUserId, kSecondUser)
                  .detachRole(kSameDomainUserId, kDefaultRole),
              kAdminKeypair),
          getBlockTransactionsAmountChecker(1));
}

std::function<void(const BlockType &)> getBlockTransactionsAmountChecker(
    int amount) {
  return [amount](auto &block) {
    ASSERT_EQ(block->transactions().size(), amount);
  };
}
