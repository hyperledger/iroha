/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <gtest/gtest.h>

#include "main/startup_params.hpp"

using iroha::StorageType;

inline static const char *StorageTypeToString(StorageType const &st) {
  switch (st) {
    case StorageType::kPostgres:
      return "kPostgres";
    case StorageType::kRocksDb:
      return "kRocksDb";
    default:
      return "UNKNOWN";
  }
}

inline static const char *TestParamInfoStorageTypeToString(
    const testing::TestParamInfo<StorageType> &info) {
  return StorageTypeToString(info.param);
}

#define INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes_list(fixture,     \
                                                            params_list) \
  INSTANTIATE_TEST_SUITE_P(DifferentStorageTypes,                        \
                           fixture,                                      \
                           params_list,                                  \
                           TestParamInfoStorageTypeToString)

#define INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(fixture) \
  INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes_list(          \
      fixture, testing::Values(StorageType::kPostgres, StorageType::kRocksDb))

#define INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes_FROM_FIXTURE(fixture) \
  INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes_list(fixture,               \
                                                      fixture::storage_types)
