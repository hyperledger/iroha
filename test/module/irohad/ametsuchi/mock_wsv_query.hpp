/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_WSV_QUERY_HPP
#define IROHA_MOCK_WSV_QUERY_HPP

#include "ametsuchi/wsv_query.hpp"

#include <gmock/gmock.h>

namespace testing {
  // iroha::TopBlockInfo is not default-constructible, so this provides a
  // default for getTopBlockInfo mock
  template <>
  class DefaultValue<
      iroha::expected::Result<iroha::TopBlockInfo, std::string>> {
   public:
    using ValueType = iroha::expected::Result<iroha::TopBlockInfo, std::string>;
    static bool Exists() {
      return true;
    }
    static ValueType &Get() {
      static ValueType val("default error value");
      return val;
    }
  };
}  // namespace testing

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
      MOCK_CONST_METHOD0(
          getTopBlockInfo,
          iroha::expected::Result<iroha::TopBlockInfo, std::string>());
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_WSV_QUERY_HPP
