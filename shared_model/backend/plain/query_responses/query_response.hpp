/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PLAIN_MODEL_QUERY_RESPONSE_HPP
#define IROHA_PLAIN_MODEL_QUERY_RESPONSE_HPP

#include "interfaces/query_responses/query_response.hpp"

#include <boost/variant/variant.hpp>
#include "common/variant_transform.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace plain {

    class QueryResponse final : public shared_model::interface::QueryResponse {
     public:
      using VariantHolder = iroha::TransformedVariant<
          QueryResponseVariantType,
          iroha::metafunctions::ConstrefToUniquePointer>;

      QueryResponse(VariantHolder specific_response,
                    shared_model::crypto::Hash query_hash);

      ~QueryResponse() override;

      const QueryResponseVariantType &get() const override;

      const interface::types::HashType &queryHash() const override;

      VariantHolder specific_response_holder;
      QueryResponseVariantType specific_response_constref;
      shared_model::crypto::Hash query_hash;
    };

  }  // namespace plain
}  // namespace shared_model

#endif
