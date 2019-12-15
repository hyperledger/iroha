/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BATCH_META_HPP
#define IROHA_SHARED_MODEL_BATCH_META_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Representation of fixed point number
     */
    class BatchMeta : public ModelPrimitive<BatchMeta> {
     public:
      virtual types::BatchType type() const = 0;

      std::string toString() const override;

      /// type of hashes collection
      using ReducedHashesType = std::vector<interface::types::HashType>;

      /**
       * @return Hashes of transactions to fetch
       */
      virtual const ReducedHashesType &reducedHashes() const = 0;

      /**
       * Checks equality of objects inside
       * @param rhs - other wrapped value
       * @return true, if wrapped objects are same
       */
      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_BATCH_META_HPP
