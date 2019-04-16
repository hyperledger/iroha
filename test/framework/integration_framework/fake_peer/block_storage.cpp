/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/block_storage.hpp"

#include <mutex>

#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/max_element.hpp>
#include "backend/protobuf/block.hpp"
#include "framework/integration_framework/fake_peer/fake_peer.hpp"
#include "logger/logger.hpp"

/// Emplace to a map.
/// @return true if overwritten.
template <typename MapType, typename KeyType, typename ValueType>
static bool emplaceCheckingOverwrite(MapType &map,
                                     const KeyType &key,
                                     const ValueType &value) {
  const bool overwritten = map.find(key) == map.end();
  map[key] = value;
  return overwritten;
}

namespace integration_framework {
  namespace fake_peer {

    BlockStorage::BlockStorage(logger::LoggerPtr log) : log_(std::move(log)) {}

    BlockStorage::BlockStorage(const BlockStorage &other)
        : blocks_by_height_(other.blocks_by_height_),
          blocks_by_hash_(other.blocks_by_hash_),
          log_(other.log_) {}

    BlockStorage::BlockStorage(BlockStorage &&other)
        : blocks_by_height_(std::move(other.blocks_by_height_)),
          blocks_by_hash_(std::move(other.blocks_by_hash_)),
          log_(std::move(other.log_)) {}

    void BlockStorage::storeBlock(
        const std::shared_ptr<const shared_model::proto::Block> &block) {
      std::lock_guard<std::shared_timed_mutex> lock(block_maps_mutex_);
      if (emplaceCheckingOverwrite(blocks_by_height_, block->height(), block)) {
        log_->warn("Overwriting block with height {}.", block->height());
      }
      if (emplaceCheckingOverwrite(blocks_by_hash_, block->hash(), block)) {
        log_->warn("Overwriting block with hash {}.", block->hash().toString());
      }
    }

    std::shared_ptr<const shared_model::proto::Block>
    BlockStorage::getBlockByHeight(BlockStorage::HeightType height) const {
      std::shared_lock<std::shared_timed_mutex> lock(block_maps_mutex_);
      const auto found = blocks_by_height_.find(height);
      if (found == blocks_by_height_.end()) {
        log_->info("Requested block with height {} not found in block storage.",
                   height);
        return {};
      }
      return found->second;
    }

    std::shared_ptr<const shared_model::proto::Block>
    BlockStorage::getBlockByHash(const BlockStorage::HashType &hash) const {
      std::shared_lock<std::shared_timed_mutex> lock(block_maps_mutex_);
      const auto found = blocks_by_hash_.find(hash);
      if (found == blocks_by_hash_.end()) {
        log_->info("Requested block with hash {} not found in block storage.",
                   hash.toString());
        return {};
      }
      return found->second;
    }

    std::shared_ptr<const shared_model::proto::Block>
    BlockStorage::getTopBlock() const {
      std::shared_lock<std::shared_timed_mutex> lock(block_maps_mutex_);
      if (blocks_by_height_.empty()) {
        log_->info("Requested top block, but the block storage is empty.");
        return {};
      }
      return blocks_by_height_.at(*boost::range::max_element(
          blocks_by_height_ | boost::adaptors::map_keys));
    }

  }  // namespace fake_peer
}  // namespace integration_framework
