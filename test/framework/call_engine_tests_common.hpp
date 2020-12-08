/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_CALL_ENGINE_TESTS_COMMON_HPP
#define IROHA_TEST_CALL_ENGINE_TESTS_COMMON_HPP

#include <ostream>
#include <string>
#include <vector>

#include "utils/string_builder.hpp"

struct LogData {
  std::string address;
  std::string data;
  std::vector<std::string> topics;

  LogData(std::string address,
          std::string data,
          std::vector<std::string> topics)
      : address(std::move(address)),
        data(std::move(data)),
        topics(std::move(topics)) {}
};

inline std::ostream &operator<<(std::ostream &os, LogData const &log) {
  return os << shared_model::detail::PrettyStringBuilder{}
                   .init("Log")
                   .appendNamed("address", log.address)
                   .appendNamed("data", log.data)
                   .appendNamed("topics", log.topics)
                   .finalize();
}

#endif
