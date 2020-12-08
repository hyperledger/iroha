/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_PROTO_COMMAND_EXECUTOR_H
#define IROHA_AMETSUCHI_PROTO_COMMAND_EXECUTOR_H

#include "ametsuchi/impl/common_c_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  Iroha_CharBuffer command_name;
  int error_code;
  Iroha_CharBuffer error_extra;
} Iroha_CommandError;

extern Iroha_CommandError Iroha_ProtoCommandExecutorExecute(
    void *executor, void *data, int size, char *account_id);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // IROHA_AMETSUCHI_PROTO_COMMAND_EXECUTOR_H
