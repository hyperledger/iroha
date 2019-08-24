/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_ACCOUNT_DETAIL_CHECKER_HPP
#define TEST_ACCOUNT_DETAIL_CHECKER_HPP

#include <map>

#include "interfaces/common_objects/types.hpp"

namespace executor_testing {
  // account details, {writer -> {key -> value}}
  using DetailsByKeyByWriter = std::map<
      shared_model::interface::types::AccountIdType,
      std::map<shared_model::interface::types::AccountDetailKeyType,
               shared_model::interface::types::AccountDetailValueType>>;

  /// Check JSON data against reference map.
  void checkJsonData(const std::string &test_data,
                     const DetailsByKeyByWriter &reference_data);

}  // namespace executor_testing

#endif /* TEST_ACCOUNT_DETAIL_CHECKER_HPP */
