/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_WSV_QUERY_HPP
#define IROHA_MOCK_WSV_QUERY_HPP

#include "ametsuchi/wsv_query.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockWsvQuery : public WsvQuery {
     public:
      MOCK_METHOD1(getSignatories,
                   boost::optional<
                       std::vector<shared_model::interface::types::PubkeyType>>(
                       const std::string &account_id));
      MOCK_METHOD0(
          getPeers,
          boost::optional<
              std::vector<std::shared_ptr<shared_model::interface::Peer>>>());
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_WSV_QUERY_HPP
