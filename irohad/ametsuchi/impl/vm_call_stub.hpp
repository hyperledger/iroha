/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_VM_CALL_STUB_HPP
#define IROHA_AMETSUCHI_VM_CALL_STUB_HPP

inline auto VmCall(char *, char *, char *, void *, void *) {
  struct {
    char *r0;
    unsigned char r1;
  } result{};
  return result;
}

#endif  // IROHA_AMETSUCHI_VM_CALL_STUB_HPP
