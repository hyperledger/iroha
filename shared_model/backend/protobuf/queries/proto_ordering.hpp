/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_QUERY_ORDERING_HPP
#define IROHA_SHARED_PROTO_MODEL_QUERY_ORDERING_HPP

#include "interfaces/queries/ordering.hpp"

#include "interfaces/common_objects/types.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {

    /// Provides ordering data for pagination
    class OrderingImpl final : public interface::Ordering {
     public:
      OrderingImpl &operator=(OrderingImpl const &) = delete;

      OrderingImpl();
      OrderingImpl(iroha::protocol::Ordering const &proto_ordering);
      OrderingImpl(OrderingImpl &&);
      OrderingImpl(OrderingImpl const &);

      bool append(ModelType::Field field,
                  ModelType::Direction direction) override;
      void reset() override;
      void get(ModelType::OrderingEntry const *&orderingEntry,
               size_t &count) const override;

     private:
      size_t count_;
      bool inserted_[(size_t)ModelType::Field::kMaxValueCount];
      ModelType::OrderingEntry
          ordering_[(size_t)ModelType::Field::kMaxValueCount];

      inline void copy(OrderingImpl const &src);
      inline void appendUnsafe(ModelType::Field field,
                               ModelType::Direction direction);
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_QUERY_ORDERING_HPP
