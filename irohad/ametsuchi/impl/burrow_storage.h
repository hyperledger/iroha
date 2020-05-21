/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_BURROW_STORAGE_H
#define IROHA_AMETSUCHI_BURROW_STORAGE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  char *data;
  unsigned long long size;
} Iroha_CharBuffer;

typedef struct {
  Iroha_CharBuffer *data;
  unsigned long long size;
} Iroha_CharBufferArray;

typedef enum {
  Iroha_Result_Type_Value,
  Iroha_Result_Type_Error
} Iroha_Result_Type;

typedef struct {
  Iroha_CharBuffer data;
  Iroha_Result_Type which;
} Iroha_Result;

extern Iroha_Result Iroha_GetAccount(void *storage, Iroha_CharBuffer address);

extern Iroha_Result Iroha_UpdateAccount(void *storage,
                                        Iroha_CharBuffer address,
                                        Iroha_CharBuffer account);

extern Iroha_Result Iroha_RemoveAccount(void *storage,
                                        Iroha_CharBuffer address);

extern Iroha_Result Iroha_GetStorage(void *storage,
                                     Iroha_CharBuffer address,
                                     Iroha_CharBuffer key);

extern Iroha_Result Iroha_SetStorage(void *storage,
                                     Iroha_CharBuffer address,
                                     Iroha_CharBuffer key,
                                     Iroha_CharBuffer value);

extern Iroha_Result Iroha_StoreLog(void *storage,
                                   Iroha_CharBuffer address,
                                   Iroha_CharBuffer data,
                                   Iroha_CharBufferArray topics);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
