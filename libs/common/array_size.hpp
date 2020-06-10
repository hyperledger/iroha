/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_ARRAY_SIZE_HPP
#define IROHA_COMMON_ARRAY_SIZE_HPP

#ifdef IROHA_ARRAY_SIZE
#error IROHA_ARRAY_SIZE already defined.
#endif  // IROHA_ARRAY_SIZE

#ifndef IROHA_ARRAY_SIZE
template <typename T, size_t N>
char (&IrohaArraySizeHelper(T (&array)[N]))[N];
#define IROHA_ARRAY_SIZE(array) (sizeof(IrohaArraySizeHelper(array)))
#endif  // IROHA_ARRAY_SIZE

#endif  // IROHA_COMMON_ARRAY_SIZE_HPP
