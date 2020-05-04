#include "backend/protobuf/commands/proto_add_smart_contract.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    AddSmartContract::AddSmartContract(CommandType &&command)
        : TrivialProto(std::forward<CommandType>(command)),
          add_smart_contract_{proto_->add_smart_contract()} {}

    template AddSmartContract::AddSmartContract(
        AddSmartContract::TransportType &);
    template AddSmartContract::AddSmartContract(
        const AddSmartContract::TransportType &);
    template AddSmartContract::AddSmartContract(
        AddSmartContract::TransportType &&);

    AddSmartContract::AddSmartContract(const AddSmartContract &o)
        : AddSmartContract(o.proto_) {}

    AddSmartContract::AddSmartContract(AddSmartContract &&o) noexcept
        : AddSmartContract(std::move(o.proto_)) {}

    const interface::types::AccountIdType &AddSmartContract::caller() const {
      return add_smart_contract_.caller();
    }

    const interface::types::AccountIdType &AddSmartContract::callee() const {
      return add_smart_contract_.callee();
    }

    const interface::types::SmartContractCodeType &AddSmartContract::code()
        const {
      return add_smart_contract_.code();
    }

    const interface::types::SmartContractCodeType &AddSmartContract::input()
        const {
      return add_smart_contract_.input();
    }

  }  // namespace proto
}  // namespace shared_model
