/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_CREATE_ASSET_HPP
#define IROHA_PROTO_CREATE_ASSET_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/create_asset.hpp"

namespace shared_model {
  namespace proto {

    class CreateAsset final : public CopyableProto<interface::CreateAsset,
                                                   iroha::protocol::Command,
                                                   CreateAsset> {
     public:
      template <typename CommandType>
      explicit CreateAsset(CommandType &&command);

      CreateAsset(const CreateAsset &o);

      CreateAsset(CreateAsset &&o) noexcept;

      const interface::types::AssetNameType &assetName() const override;

      const interface::types::DomainIdType &domainId() const override;

      const PrecisionType &precision() const override;

     private:
      const iroha::protocol::CreateAsset &create_asset_;

      const PrecisionType precision_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_CREATE_ASSET_HPP
