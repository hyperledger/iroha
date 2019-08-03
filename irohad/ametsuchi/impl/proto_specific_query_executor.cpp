/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/proto_specific_query_executor.h"

#include "ametsuchi/specific_query_executor.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"

Iroha_ProtoQueryResponse Iroha_ProtoSpecificQueryExecutorExecute(void *executor,
                                                                 void *data,
                                                                 int size) {
  Iroha_ProtoQueryResponse result{};

  iroha::protocol::Query query;
  if (!query.ParseFromArray(data, size)) {
    return result;
  }

  auto response =
      reinterpret_cast<iroha::ametsuchi::SpecificQueryExecutor *>(executor)
          ->execute(shared_model::proto::Query(query));
  auto &proto_response =
      static_cast<shared_model::proto::QueryResponse *>(response.get())
          ->getTransport();
  result.size = proto_response.ByteSize();
  result.data = malloc(result.size);
  proto_response.SerializeToArray(result.data, result.size);
  return result;
}
