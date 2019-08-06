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

boost::optional<std::shared_ptr<const shared_model::interface::Block>>
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
                std::shared_ptr<const shared_model::interface::Block>>(
                std::move(block.value));
          },
          [&](const auto &error)
              -> boost::optional<
                  std::shared_ptr<const shared_model::interface::Block>> {
            log_->warn("Error while block deserialization: {}", error.error);
            return boost::none;
          });
}

size_t FlatFileBlockStorage::size() const {
  return flat_file_storage_->blockIdentifiers().size();
}

void FlatFileBlockStorage::clear() {
  flat_file_storage_->dropAll();
}

void FlatFileBlockStorage::forEach(
    iroha::ametsuchi::BlockStorage::FunctionType function) const {
  for (auto block_id : flat_file_storage_->blockIdentifiers()) {
    auto block = fetch(block_id);
    BOOST_ASSERT(block);
    function(*block);
  }
}
