/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/query_payload_meta.hpp"

namespace shared_model {
  namespace interface {

    bool QueryPayloadMeta::operator==(const ModelType &rhs) const {
      return creatorAccountId() == rhs.creatorAccountId()
          and queryCounter() == rhs.queryCounter()
          and createdTime() == rhs.createdTime();
    }

  }  // namespace interface
}  // namespace shared_model
