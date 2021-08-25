/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/proto_specific_query_executor.h"

#include <boost/variant.hpp>
#include "ametsuchi/specific_query_executor.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "validators/field_validator.hpp"
#include "validators/protobuf/proto_query_validator.hpp"
#include "validators/query_validator.hpp"
#include "validators/validators_common.hpp"

namespace {
  Iroha_ProtoQueryResponse serialize(iroha::protocol::QueryResponse response) {
    Iroha_ProtoQueryResponse result{};

    result.size = response.ByteSizeLong();
    result.data = malloc(result.size);
    response.SerializeToArray(result.data, result.size);

    return result;
  }

  iroha::protocol::QueryResponse makeErrorResponse(int code,
                                                   std::string message) {
    iroha::protocol::QueryResponse result{};

    auto *error_response = result.mutable_error_response();
    error_response->set_error_code(code);
    error_response->set_message(std::move(message));

    return result;
  }
}  // namespace

Iroha_ProtoQueryResponse Iroha_ProtoSpecificQueryExecutorExecute(void *executor,
                                                                 void *data,
                                                                 int size) {
  iroha::protocol::Query protocol_query;
  if (!protocol_query.ParseFromArray(data, size)) {
    return serialize(makeErrorResponse(100, "Deserialization failed"));
  }

  if (auto maybe_error =
          shared_model::validation::ProtoQueryValidator().validate(
              protocol_query)) {
    return serialize(makeErrorResponse(200, maybe_error.value().toString()));
  }

  shared_model::proto::Query proto_query(protocol_query);

  if (auto maybe_error =
          shared_model::validation::QueryValidator<
              shared_model::validation::FieldValidator,
              shared_model::validation::QueryValidatorVisitor<
                  shared_model::validation::FieldValidator>>(
              std::make_shared<shared_model::validation::ValidatorsConfig>(0))
              .validate(proto_query)) {
    return serialize(makeErrorResponse(300, maybe_error.value().toString()));
  }

  auto response =
      reinterpret_cast<iroha::ametsuchi::SpecificQueryExecutor *>(executor)
          ->execute(proto_query);
  auto &proto_response =
      static_cast<shared_model::proto::QueryResponse *>(response.get())
          ->getTransport();

  return serialize(proto_response);
}
