/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/flat_file_block_storage_factory.hpp"

#include "ametsuchi/impl/flat_file_block_storage.hpp"

using namespace iroha::ametsuchi;

FlatFileBlockStorageFactory::FlatFileBlockStorageFactory(
    std::function<std::string()> path_provider,
    std::shared_ptr<shared_model::interface::BlockJsonConverter>
        json_block_converter,
    logger::LoggerManagerTreePtr log_manager)
    : path_provider_(std::move(path_provider)),
      json_block_converter_(std::move(json_block_converter)),
      log_manager_(std::move(log_manager)) {}

iroha::expected::Result<std::unique_ptr<BlockStorage>, std::string>
FlatFileBlockStorageFactory::create() {
  return FlatFile::create(path_provider_(),
                          log_manager_->getChild("FlatFile")->getLogger())
      | [this](auto &&flat_file) {
          return std::make_unique<FlatFileBlockStorage>(
              std::move(flat_file),
              json_block_converter_,
              log_manager_->getChild("FlatFileBlockFactory")->getLogger());
        };
}
