/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_EXECUTOR_COMMON_HPP
#define IROHA_AMETSUCHI_EXECUTOR_COMMON_HPP

#include "interfaces/common_objects/types.hpp"

#include <algorithm>
#include <array>

namespace iroha::ametsuchi {

  extern const std::string kRootRolePermStr;

  std::string_view getDomainFromName(std::string_view account_id);

  std::vector<std::string_view> splitId(std::string_view id);

  std::vector<std::string_view> split(std::string_view str,
                                      std::string_view delims);

  template <size_t C>
  std::array<std::string_view, C> staticSplitId(
      std::string_view const str, std::string_view const delims = "@#") {
    std::array<std::string_view, C> output;

    auto it_first = str.data();
    auto it_second = str.data();
    auto it_end = str.data() + str.size();
    size_t counter = 0;

    while (it_first != it_end && counter < C) {
      it_second = std::find_first_of(
          it_first, it_end, std::cbegin(delims), std::cend(delims));

      output[counter++] = std::string_view(it_first, it_second - it_first);
      it_first = it_second != it_end ? it_second + 1ull : it_end;
    }
    return output;
  }

}  // namespace iroha::ametsuchi

#endif  // IROHA_AMETSUCHI_EXECUTOR_COMMON_HPP
