/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_block_storage.hpp"

#include "ametsuchi/impl/rocksdb_common.hpp"
#include "backend/protobuf/block.hpp"
#include "common/byteutils.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

#define CHECK_OPERATION(command, ...)                                          \
  if (auto result = (__VA_ARGS__); expected::hasError(result)) {               \
    log_->error("Error while block {} " command ". Code: {}. Description: {}", \
                block->height(),                                               \
                result.assumeError().code,                                     \
                result.assumeError().description);                             \
    return false;                                                              \
  }

namespace {
  inline iroha::expected::Result<void, DbError> incrementTotalBlocksCount(
      iroha::ametsuchi::RocksDbCommon &common) {
    RDB_TRY_GET_VALUE(
        opt_count,
        forBlocksTotalCount<kDbOperation::kGet, kDbEntry::kCanExist>(common));

    common.encode(opt_count ? *opt_count + 1ull : 1ull);
    RDB_ERROR_CHECK(
        forBlocksTotalCount<kDbOperation::kPut, kDbEntry::kMustExist>(common));

    return {};
  }
}  // namespace

RocksDbBlockStorage::RocksDbBlockStorage(
    std::shared_ptr<RocksDBContext> db_context,
    std::shared_ptr<shared_model::interface::BlockJsonConverter> json_converter,
    logger::LoggerPtr log)
    : db_context_(std::move(db_context)),
      json_converter_(std::move(json_converter)),
      log_(std::move(log)) {}

bool RocksDbBlockStorage::insert(
    std::shared_ptr<const shared_model::interface::Block> block) {
  return json_converter_->serialize(*block).match(
      [&](const auto &block_json) {
        RocksDbCommon common(db_context_);
        CHECK_OPERATION("insertion",
                        forBlock<kDbOperation::kCheck, kDbEntry::kMustNotExist>(
                            common, block->height()));

        common.valueBuffer() = block_json.value;
        CHECK_OPERATION("storing",
                        forBlock<kDbOperation::kPut>(common, block->height()));

        CHECK_OPERATION("total count storing",
                        incrementTotalBlocksCount(common));
        return true;
      },
      [this](const auto &error) {
        log_->warn("Error while block serialization: {}", error.error);
        return false;
      });
}

boost::optional<std::unique_ptr<shared_model::interface::Block>>
RocksDbBlockStorage::fetch(
    shared_model::interface::types::HeightType height) const {
  RocksDbCommon common(db_context_);
  if (auto result =
          forBlock<kDbOperation::kGet, kDbEntry::kMustExist>(common, height);
      expected::hasError(result)) {
    log_->error("Error while block {} reading. Code: {}. Description: {}",
                height,
                result.assumeError().code,
                result.assumeError().description);
    return boost::none;
  }

  return json_converter_->deserialize(common.valueBuffer())
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

size_t RocksDbBlockStorage::size() const {
  RocksDbCommon common(db_context_);
  if (auto result =
          forBlocksTotalCount<kDbOperation::kGet, kDbEntry::kMustExist>(common);
      expected::hasValue(result))
    return *result.assumeValue();
  return 0ull;
}

void RocksDbBlockStorage::reload() {}

void RocksDbBlockStorage::clear() {
  RocksDbCommon common(db_context_);

  if (auto res = dropStore(common); expected::hasError(res))
    log_->error("Unable to delete Store. Description: {}",
                res.assumeError().description);

  if (auto res = dropWSV(common); expected::hasError(res))
    log_->error("Unable to delete WSV. Description: {}",
                res.assumeError().description);
}

iroha::expected::Result<void, std::string> RocksDbBlockStorage::forEach(
    iroha::ametsuchi::BlockStorage::FunctionType function) const {
  uint64_t const blocks_count = size();
  for (uint64_t ix = 1; ix <= blocks_count; ++ix) {
    auto maybe_block = fetch(ix);
    if (maybe_block) {
      auto maybe_error = function(std::move(maybe_block).value());
      if (iroha::expected::hasError(maybe_error)) {
        return maybe_error.assumeError();
      }
    } else {
      return fmt::format("Failed to fetch block {}", ix);
    }
  }
  return {};
}
