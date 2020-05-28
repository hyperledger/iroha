/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_C_TYPES_H
#define IROHA_COMMON_C_TYPES_H

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

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
