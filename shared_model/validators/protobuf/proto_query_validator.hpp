/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_QUERY_VALIDATOR_HPP
#define IROHA_PROTO_QUERY_VALIDATOR_HPP

#include "validators/abstract_validator.hpp"

namespace iroha {
  namespace protocol {
    class BlocksQuery;
    class Query;
  }  // namespace protocol
}  // namespace iroha

namespace shared_model {
  namespace validation {

    class ProtoQueryValidator
        : public AbstractValidator<iroha::protocol::Query> {
     public:
      std::optional<ValidationError> validate(
          const iroha::protocol::Query &query) const override;
    };

    class ProtoBlocksQueryValidator
        : public AbstractValidator<iroha::protocol::BlocksQuery> {
     public:
      std::optional<ValidationError> validate(
          const iroha::protocol::BlocksQuery &) const override;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_PROTO_QUERY_VALIDATOR_HPP
