/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/permissions.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;
using namespace shared_model::interface::permissions;

using shared_model::interface::types::PublicKeyHexStringView;

class ReplayFixture : public AcceptanceFixture {
 public:
  ReplayFixture()
      : itf(1, iroha::StorageType::kRocksDb), kReceiverRole("receiver") {}

  void SetUp() override {
    auto create_user_tx = complete(
        baseTx(kAdminId)
            .createAccount(kUser,
                           kDomain,
                           PublicKeyHexStringView{kUserKeypair.publicKey()})
            .createRole(kReceiverRole, {Role::kReceive})
            .appendRole(kUserId, kReceiverRole)
            .addAssetQuantity(kAssetId, "10000.0"),
        kAdminKeypair);
    itf.setInitialState(kAdminKeypair)
        .sendTxAwait(create_user_tx, CHECK_TXS_QUANTITY(1));
  }

  IntegrationTestFramework itf;
  const interface::types::RoleIdType kReceiverRole;
};

/**
 * @given ITF with hacked OS that provides the same proposal twice
 * @when YAC accepts the proposal twice
 * @then a transaction from proposal would not be committed twice
 */
TEST_F(ReplayFixture, DISABLED_ConsensusReplay) {
  // TODO 2019-01-09 igor-egorov IR-153
}
