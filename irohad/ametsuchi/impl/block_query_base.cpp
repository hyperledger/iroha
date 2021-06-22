/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/block_query_base.hpp"

#include <boost/format.hpp>

#include "common/byteutils.hpp"
#include "common/cloneable.hpp"
#include "logger/logger.hpp"

namespace iroha::ametsuchi {

  BlockQueryBase::BlockQueryBase(BlockStorage &block_storage,
                                 logger::LoggerPtr log)
      : block_storage_(block_storage), log_(std::move(log)) {}

  BlockQuery::BlockResult BlockQueryBase::getBlock(
      shared_model::interface::types::HeightType height) {
    auto block = block_storage_.fetch(height);
    if (not block) {
      auto error =
          boost::format("Failed to retrieve block with height %d") % height;
      return expected::makeError(
          GetBlockError{GetBlockError::Code::kNoBlock, error.str()});
    }
    return std::move(*block);
  }

  shared_model::interface::types::HeightType
  BlockQueryBase::getTopBlockHeight() {
    return block_storage_.size();
  }

  void BlockQueryBase::reloadBlockstore() {
    block_storage_.reload();
  }

  std::optional<TxCacheStatusType> BlockQueryBase::checkTxPresence(
      const shared_model::crypto::Hash &hash) {
    int res = -1;
    if (auto status = getTxStatus(hash); !status)
      return std::nullopt;
    else
      res = *status;

    if (res > 0) {
      return std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Committed{hash});
    } else if (res == 0) {
      return std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Rejected{hash});
    }
    return std::make_optional<TxCacheStatusType>(
        tx_cache_status_responses::Missing{hash});
  }

}  // namespace iroha::ametsuchi
