/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STORAGE_INIT_HPP
#define IROHA_STORAGE_INIT_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <boost/optional/optional_fwd.hpp>
#include "common/result_fwd.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace shared_model::interface {
  class Block;
  class QueryResponseFactory;
}  // namespace shared_model::interface

namespace iroha {
  class PendingTransactionStorage;

  namespace ametsuchi {
    struct PoolWrapper;
    class PostgresOptions;
    class RocksDbOptions;
    class Storage;
    class VmCaller;
    struct RocksDBContext;
  }  // namespace ametsuchi

  expected::Result<std::shared_ptr<iroha::ametsuchi::Storage>, std::string>
  initStorage(
      std::shared_ptr<ametsuchi::RocksDBContext> db_context,
      std::shared_ptr<iroha::PendingTransactionStorage> pending_txs_storage,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory,
      boost::optional<std::string> block_storage_dir,
      std::optional<std::reference_wrapper<const iroha::ametsuchi::VmCaller>>
          vm_caller_ref,
      std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
          callback,
      logger::LoggerManagerTreePtr log_manager);

  expected::Result<std::shared_ptr<iroha::ametsuchi::Storage>, std::string>
  initStorage(
      iroha::ametsuchi::PostgresOptions const &pg_opt,
      std::shared_ptr<iroha::ametsuchi::PoolWrapper> pool_wrapper,
      std::shared_ptr<iroha::PendingTransactionStorage> pending_txs_storage,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory,
      boost::optional<std::string> block_storage_dir,
      std::optional<std::reference_wrapper<const iroha::ametsuchi::VmCaller>>
          vm_caller_ref,
      std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
          callback,
      logger::LoggerManagerTreePtr log_manager);
}  // namespace iroha

#endif
