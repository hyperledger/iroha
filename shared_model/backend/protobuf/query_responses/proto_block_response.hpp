/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCK_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCK_RESPONSE_HPP

#include "interfaces/query_responses/block_response.hpp"

#include "common/result_fwd.hpp"

namespace iroha {
  namespace protocol {
    class BlockQueryResponse;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class Block;

    class BlockResponse final : public interface::BlockResponse {
     public:
      static iroha::expected::Result<std::unique_ptr<BlockResponse>,
                                     std::string>
      create(const iroha::protocol::BlockQueryResponse &query_response);

      explicit BlockResponse(
          std::unique_ptr<shared_model::interface::Block> block);

      ~BlockResponse() override;

      const interface::Block &block() const override;

     private:
      std::unique_ptr<shared_model::interface::Block> block_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCK_RESPONSE_HPP
