/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RESULT_TRY_HPP
#define IROHA_RESULT_TRY_HPP

#include "common/result.hpp"

#define IROHA_EXPECTED_ERROR_CHECK(...)        \
  if (auto _tmp_gen_var = (__VA_ARGS__);       \
      iroha::expected::hasError(_tmp_gen_var)) \
  return _tmp_gen_var.assumeError()

#define IROHA_EXPECTED_TRY_GET_VALUE(name, ...)        \
  typename decltype(__VA_ARGS__)::ValueInnerType name; \
  if (auto _tmp_gen_var = (__VA_ARGS__);               \
      iroha::expected::hasError(_tmp_gen_var))         \
    return _tmp_gen_var.assumeError();                 \
  else                                                 \
    name = std::move(_tmp_gen_var.assumeValue())

#endif  // IROHA_RESULT_TRY_HPP
