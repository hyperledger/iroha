/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/in_memory_block_storage.hpp"

using namespace iroha::ametsuchi;

bool InMemoryBlockStorage::insert(
    std::shared_ptr<const shared_model::interface::Block> block) {
  auto height = block->height();
  return block_store_.emplace(height, std::move(block)).second;
}

boost::optional<std::unique_ptr<shared_model::interface::Block>>
InMemoryBlockStorage::fetch(
    shared_model::interface::types::HeightType height) const {
  auto it = block_store_.find(height);
  if (it != block_store_.end()) {
    return clone(*(it->second));
  } else {
    return boost::none;
  }
}

size_t InMemoryBlockStorage::size() const {
  return block_store_.size();
}
void InMemoryBlockStorage::reload() {
  // no need to reload
}

void InMemoryBlockStorage::clear() {
  block_store_.clear();
}

iroha::expected::Result<void, std::string> InMemoryBlockStorage::forEach(
    FunctionType function) const {
  for (const auto &pair : block_store_) {
    auto maybe_error = function(pair.second);
    if (iroha::expected::hasError(maybe_error)) {
      return maybe_error.assumeError();
    }
  }
  return {};
}
