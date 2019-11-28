/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_COMMAND_HPP
#define IROHA_SHARED_MODEL_PROTO_COMMAND_HPP

#include "interfaces/commands/command.hpp"

#include <memory>

#include "common/result_fwd.hpp"

namespace iroha {
  namespace protocol {
    class Command;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class Command final : public interface::Command {
     public:
      using TransportType = iroha::protocol::Command;

      static iroha::expected::Result<std::unique_ptr<Command>, std::string>
      create(TransportType &command);

      ~Command() override;

      /**
       * @return reference to const variant with concrete command
       */
      const CommandVariantType &get() const override;

     private:
      struct Impl;
      explicit Command(std::unique_ptr<Impl> impl);
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_COMMAND_HPP
