/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <benchmark/benchmark.h>
#include <string>

#include <boost/filesystem.hpp>
#include "backend/protobuf/transaction.hpp"
#include "benchmark/bm_utils.hpp"
#include "builders/protobuf/unsigned_proto.hpp"
#include "datetime/time.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace benchmark::utils;
using namespace common_constants;

auto baseTx() {
  return TestUnsignedTransactionBuilder().creatorAccountId(kUserId).createdTime(
      iroha::time::now());
}

const auto kProposalSize = 100;
const auto kTransactionSize = 100;
const std::string kAmount = "1.0";

/**
 * This benchmark runs execution of the add asset quantity command in order to
 * measure execution performance
 * @param state
 */
static void BM_AddAssetQuantity(benchmark::State &state) {
  for (auto const type :
       {iroha::StorageType::kPostgres, iroha::StorageType::kRocksDb}) {
    integration_framework::IntegrationTestFramework itf(
        kProposalSize,
        type,
        boost::none,
        iroha::StartupWsvDataPolicy::kDrop,
        false,
        false,
        (boost::filesystem::temp_directory_path()
         / boost::filesystem::unique_path())
            .string(),
        std::chrono::hours(1),
        std::chrono::hours(1));
    itf.setInitialState(kAdminKeypair);
    for (int i = 0; i < kProposalSize; i++) {
      using shared_model::interface::types::PublicKeyHexStringView;
      itf.sendTx(createUserWithPerms(
                     kUser,
                     PublicKeyHexStringView{kUserKeypair.publicKey()},
                     kRole,
                     {shared_model::interface::permissions::Role::kAddAssetQty})
                     .build()
                     .signAndAddSignature(kAdminKeypair)
                     .finish());
    }
    itf.skipBlock().skipProposal();

    while (state.KeepRunning()) {
      auto make_base = [&]() {
        auto base = baseTx();
        for (int i = 0; i < kTransactionSize; i++) {
          base = base.addAssetQuantity(kAssetId, kAmount);
        }
        return base.quorum(1)
            .build()
            .signAndAddSignature(kUserKeypair)
            .finish();
      };

      for (int i = 0; i < kProposalSize; i++) {
        itf.sendTx(make_base());
      }
      itf.skipProposal().skipBlock();
    }
    itf.done();
  }
}

BENCHMARK(BM_AddAssetQuantity)->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
