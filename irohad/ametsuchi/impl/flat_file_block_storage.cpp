/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/flat_file_block_storage.hpp"

#include <boost/filesystem.hpp>

#include "backend/protobuf/block.hpp"
#include "common/byteutils.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

FlatFileBlockStorage::FlatFileBlockStorage(
    std::unique_ptr<FlatFile> flat_file,
    std::shared_ptr<shared_model::interface::BlockJsonConverter> json_converter,
    logger::LoggerPtr log)
    : flat_file_storage_(std::move(flat_file)),
      json_converter_(std::move(json_converter)),
      log_(std::move(log)) {}

bool FlatFileBlockStorage::insert(
    std::shared_ptr<const shared_model::interface::Block> block) {
  return json_converter_->serialize(*block).match(
      [&](const auto &block_json) {
        return flat_file_storage_->add(block->height(),
                                       stringToBytes(block_json.value));
      },
      [this](const auto &error) {
        log_->warn("Error while block serialization: {}", error.error);
        return false;
      });
}

boost::optional<std::unique_ptr<shared_model::interface::Block>>
FlatFileBlockStorage::fetch(
    shared_model::interface::types::HeightType height) const {
  auto storage_block = flat_file_storage_->get(height);
  if (not storage_block) {
    return boost::none;
  }

  return json_converter_->deserialize(bytesToString(*storage_block))
      .match(
          [&](auto &&block) {
            return boost::make_optional<
                std::unique_ptr<shared_model::interface::Block>>(
                std::move(block.value));
          },
          [&](const auto &error)
              -> boost::optional<
                  std::unique_ptr<shared_model::interface::Block>> {
            log_->warn("Error while block deserialization: {}", error.error);
            return boost::none;
          });
}

size_t FlatFileBlockStorage::size() const {
  return flat_file_storage_->last_id();
}

void FlatFileBlockStorage::reload() {
  flat_file_storage_->reload();
}

void FlatFileBlockStorage::clear() {
  flat_file_storage_->dropAll();
}

iroha::expected::Result<void, std::string> FlatFileBlockStorage::forEach(
    iroha::ametsuchi::BlockStorage::FunctionType function) const {
  for (auto block_id : flat_file_storage_->blockIdentifiers()) {
    auto maybe_block = fetch(block_id);
    if (maybe_block) {
      auto maybe_error = function(std::move(maybe_block).value());
      if (iroha::expected::hasError(maybe_error)) {
        return maybe_error.assumeError();
      }
    } else {
      return fmt::format("Failed to fetch block {}", block_id);
    }
  }
  return {};
}
