/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_FAKE_PEER_FIXTURE_HPP
#define IROHA_FAKE_PEER_FIXTURE_HPP

#include <string_view>

#include "integration/acceptance/acceptance_fixture.hpp"

#include "backend/protobuf/block.hpp"
#include "framework/integration_framework/fake_peer/fake_peer.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "framework/make_peer_pointee_matcher.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

template <size_t N>
void checkBlockHasNTxs(
    const std::shared_ptr<const shared_model::interface::Block> &block) {
  ASSERT_EQ(block->transactions().size(), N);
}

class FakePeerFixture : public AcceptanceFixture {
 public:
  using FakePeer = integration_framework::fake_peer::FakePeer;

  std::unique_ptr<integration_framework::IntegrationTestFramework> itf_;

  /**
   * Create honest fake iroha peers
   *
   * @param num_fake_peers - the amount of fake peers to create
   */
  void createFakePeers(size_t num_fake_peers) {
    fake_peers_ = itf_->addFakePeers(num_fake_peers);
  }

  /**
   * Prepare state of ledger:
   * - create account of target user
   * - add assets to admin
   *
   * @return reference to ITF
   */
  integration_framework::IntegrationTestFramework &prepareState() {
    itf_->setGenesisBlock(itf_->defaultBlock()).subscribeQueuesAndRun();

    auto permissions = shared_model::interface::RolePermissionSet(
        {shared_model::interface::permissions::Role::kReceive,
         shared_model::interface::permissions::Role::kTransfer});

    return itf_
        ->sendTxAwait(makeUserWithPerms(permissions), checkBlockHasNTxs<1>)
        .sendTxAwait(complete(baseTx(common_constants::kAdminId)
                                  .addAssetQuantity(common_constants::kAssetId,
                                                    "20000.0"),
                              *common_constants::kAdminSigner),
                     checkBlockHasNTxs<1>);
  }

 protected:
  void SetUp() override {
    itf_ = std::make_unique<integration_framework::IntegrationTestFramework>(
        1, boost::none, iroha::StartupWsvDataPolicy::kDrop, true, true);
    itf_->initPipeline(common_constants::kAdminSigner);
  }

  std::vector<std::shared_ptr<FakePeer>> fake_peers_;
};

#endif  // IROHA_FAKE_PEER_FIXTURE_HPP
