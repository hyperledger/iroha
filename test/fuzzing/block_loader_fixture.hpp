/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_LOADER_FIXTURE_HPP
#define IROHA_BLOCK_LOADER_FIXTURE_HPP

#include <memory>

#include <gtest/gtest.h>
#include <libfuzzer/libfuzzer_macro.h>

#include "consensus/consensus_block_cache.hpp"
#include "logger/dummy_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "network/impl/block_loader_service.hpp"

using namespace testing;

namespace fuzzing {

  struct BlockLoaderFixture {
    std::shared_ptr<NiceMock<iroha::ametsuchi::MockBlockQuery>> storage_;
    std::shared_ptr<NiceMock<iroha::ametsuchi::MockBlockQueryFactory>>
        block_query_factory_;
    std::shared_ptr<iroha::consensus::ConsensusResultCache> block_cache_;
    std::shared_ptr<iroha::network::BlockLoaderService> block_loader_service_;

    BlockLoaderFixture() {
      storage_ = std::make_shared<NiceMock<iroha::ametsuchi::MockBlockQuery>>();
      block_query_factory_ =
          std::make_shared<NiceMock<iroha::ametsuchi::MockBlockQueryFactory>>();
      block_cache_ = std::make_shared<iroha::consensus::ConsensusResultCache>();
      block_loader_service_ =
          std::make_shared<iroha::network::BlockLoaderService>(
              block_query_factory_, block_cache_, logger::getDummyLoggerPtr());
      EXPECT_CALL(*block_query_factory_, createBlockQuery())
          .WillRepeatedly(Return(boost::make_optional(
              std::shared_ptr<iroha::ametsuchi::BlockQuery>(storage_))));
      EXPECT_CALL(*storage_, getBlock(_)).WillRepeatedly(Invoke([](auto) {
        return iroha::expected::makeValue(
            clone<shared_model::interface::Block>(TestBlockBuilder().build()));
      }));
    }
  };

}  // namespace fuzzing

#endif  // IROHA_BLOCK_LOADER_FIXTURE_HPP
