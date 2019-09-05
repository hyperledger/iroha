#ifndef IROHA_PROTO_ENGINE_CALL_HPP
#define IROHA_PROTO_ENGINE_CALL_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/engine_call.hpp"

namespace shared_model {
  namespace proto {

    class EngineCall final
        : public TrivialProto<interface::EngineCall, iroha::protocol::Command> {
     public:
      template <typename CommandType>
      explicit EngineCall(CommandType &&command);

      EngineCall(const EngineCall &o);

      EngineCall(EngineCall &&o) noexcept;

      const interface::types::AccountIdType &callee() const override;

      const interface::types::SmartContractCodeType &input() const override;

     private:
      const iroha::protocol::EngineCall &engine_call_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_ENGINE_CALL_HPP
