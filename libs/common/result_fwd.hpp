/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RESULT_FWD_HPP
#define IROHA_RESULT_FWD_HPP

namespace iroha {
  namespace expected {

    struct ValueBase;

    template <typename T>
    struct Value;

    struct ErrorBase;

    template <typename E>
    struct Error;

    class ResultException;

    struct ResultBase;

    template <typename V, typename E>
    class Result;

  }  // namespace expected
}  // namespace iroha

#endif  // IROHA_RESULT_FWD_HPP
