/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_PAYLOAD_META_HPP
#define IROHA_SHARED_MODEL_QUERY_PAYLOAD_META_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Class QueryPayloadMeta provides metadata of query payload
     * General note: this class is container for queries but not a base class.
     */
    class QueryPayloadMeta : public ModelPrimitive<QueryPayloadMeta> {
     public:
      /**
       * @return id of query creator
       */
      virtual const types::AccountIdType &creatorAccountId() const = 0;

      /**
       * Query counter - incremental variable reflect for number of sent to
       * system queries plus 1. Required for preventing replay attacks.
       * @return attached query counter
       */
      virtual types::CounterType queryCounter() const = 0;

      /**
       * @return time of creation
       */
      virtual types::TimestampType createdTime() const = 0;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_QUERY_PAYLOAD_META_HPP
