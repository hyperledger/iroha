/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_PROTO_QUERY_EXECUTOR_H
#define IROHA_AMETSUCHI_PROTO_QUERY_EXECUTOR_H

#ifdef __cplusplus
extern "C" {
#endif

struct Iroha_ProtoQueryResponse {
  void *data;
  int size;
};

extern struct Iroha_ProtoQueryResponse Iroha_ProtoQueryExecutorExecute(
    void *executor, void *data, int size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // IROHA_AMETSUCHI_PROTO_QUERY_EXECUTOR_H
