/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_PROTO_COMMAND_EXECUTOR_H
#define IROHA_AMETSUCHI_PROTO_COMMAND_EXECUTOR_H

#ifdef __cplusplus
extern "C" {
#endif

struct Iroha_CommandError {
  char *command_name;
  int error_code;
  char *error_extra;
};

extern struct Iroha_CommandError Iroha_ProtoCommandExecutorExecute(
    void *executor, void *data, int size, char *account_id);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // IROHA_AMETSUCHI_PROTO_COMMAND_EXECUTOR_H
