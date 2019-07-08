/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_CONCRETE_ERROR_QUERY_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_CONCRETE_ERROR_QUERY_RESPONSE_HPP

#include "backend/protobuf/common_objects/proto_ref.hpp"
#include "interfaces/query_responses/error_responses/no_account_assets_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_account_detail_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_account_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_asset_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_roles_error_response.hpp"
#include "interfaces/query_responses/error_responses/no_signatories_error_response.hpp"
#include "interfaces/query_responses/error_responses/not_supported_error_response.hpp"
#include "interfaces/query_responses/error_responses/stateful_failed_error_response.hpp"
#include "interfaces/query_responses/error_responses/stateless_failed_error_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    using StatelessFailedErrorResponse =
        ProtoRef<interface::StatelessFailedErrorResponse,
                 iroha::protocol::ErrorResponse>;
    using StatefulFailedErrorResponse =
        ProtoRef<interface::StatefulFailedErrorResponse,
                 iroha::protocol::ErrorResponse>;
    using NoAccountErrorResponse = ProtoRef<interface::NoAccountErrorResponse,
                                            iroha::protocol::ErrorResponse>;
    using NoAccountAssetsErrorResponse =
        ProtoRef<interface::NoAccountAssetsErrorResponse,
                 iroha::protocol::ErrorResponse>;
    using NoAccountDetailErrorResponse =
        ProtoRef<interface::NoAccountDetailErrorResponse,
                 iroha::protocol::ErrorResponse>;
    using NoSignatoriesErrorResponse =
        ProtoRef<interface::NoSignatoriesErrorResponse,
                 iroha::protocol::ErrorResponse>;
    using NotSupportedErrorResponse =
        ProtoRef<interface::NotSupportedErrorResponse,
                 iroha::protocol::ErrorResponse>;
    using NoAssetErrorResponse = ProtoRef<interface::NoAssetErrorResponse,
                                          iroha::protocol::ErrorResponse>;
    using NoRolesErrorResponse = ProtoRef<interface::NoRolesErrorResponse,
                                          iroha::protocol::ErrorResponse>;
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_CONCRETE_ERROR_QUERY_RESPONSE_HPP
