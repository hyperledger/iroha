/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RDB_STATUS_HPP
#define IROHA_RDB_STATUS_HPP

#include <optional>

namespace iroha {

  struct RocksDbStatus {
    std::optional<uint64_t> block_cache_capacity;
    std::optional<uint64_t> block_cache_usage;
    std::optional<uint64_t> all_mem_tables_sz;
    std::optional<uint64_t> num_snapshots;
    std::optional<uint64_t> sst_files_size;
  };

}  // namespace iroha

#endif  // IROHA_RDB_STATUS_HPP
