/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_BURROW_STORAGE_H
#define IROHA_AMETSUCHI_BURROW_STORAGE_H

#ifdef __cplusplus
extern "C" {
#endif

struct Iroha_Result {
  char *result;
  char *error;
};

struct Iroha_CharBuffer {
  char *data;
  unsigned long long size;
};

struct Iroha_CharBufferArray {
  struct Iroha_CharBuffer *data;
  unsigned long long size;
};

extern struct Iroha_Result Iroha_GetAccount(void *storage,
                                            struct Iroha_CharBuffer address);

extern struct Iroha_Result Iroha_UpdateAccount(void *storage,
                                               struct Iroha_CharBuffer address,
                                               struct Iroha_CharBuffer account);

extern struct Iroha_Result Iroha_RemoveAccount(void *storage,
                                               struct Iroha_CharBuffer address);

extern struct Iroha_Result Iroha_GetStorage(void *storage,
                                            struct Iroha_CharBuffer address,
                                            struct Iroha_CharBuffer key);

extern struct Iroha_Result Iroha_SetStorage(void *storage,
                                            struct Iroha_CharBuffer address,
                                            struct Iroha_CharBuffer key,
                                            struct Iroha_CharBuffer value);

extern struct Iroha_Result Iroha_StoreTxReceipt(
    void *storage,
    struct Iroha_CharBuffer address,
    struct Iroha_CharBuffer data,
    struct Iroha_CharBufferArray topics);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
