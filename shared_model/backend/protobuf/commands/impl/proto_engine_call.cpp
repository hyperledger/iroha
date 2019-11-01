#include "backend/protobuf/commands/proto_engine_call.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    EngineCall::EngineCall(CommandType &&command)
        : TrivialProto(std::forward<CommandType>(command)),
          engine_call_{proto_->engine_call()} {}

    template EngineCall::EngineCall(EngineCall::TransportType &);
    template EngineCall::EngineCall(const EngineCall::TransportType &);
    template EngineCall::EngineCall(EngineCall::TransportType &&);

    EngineCall::EngineCall(const EngineCall &o) : EngineCall(o.proto_) {}

    EngineCall::EngineCall(EngineCall &&o) noexcept
        : EngineCall(std::move(o.proto_)) {}

    const interface::types::AccountIdType &EngineCall::caller() const {
      return engine_call_.caller();
    }

    const interface::types::AccountIdType &EngineCall::callee() const {
      return engine_call_.callee();
    }

    const interface::types::SmartContractCodeType &EngineCall::code() const {
      return engine_call_.code();
    }

    const interface::types::SmartContractCodeType &EngineCall::input() const {
      return engine_call_.input();
    }

  }  // namespace proto
}  // namespace shared_model
