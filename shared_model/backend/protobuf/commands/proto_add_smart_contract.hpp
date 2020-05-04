#ifndef IROHA_PROTO_ADD_SMART_CONTRACT_HPP
#define IROHA_PROTO_ADD_SMART_CONTRACT_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/add_smart_contract.hpp"

namespace shared_model {
  namespace proto {

    class AddSmartContract final
        : public TrivialProto<interface::AddSmartContract,
                              iroha::protocol::Command> {
     public:
      template <typename CommandType>
      explicit AddSmartContract(CommandType &&command);

      AddSmartContract(const AddSmartContract &o);

      AddSmartContract(AddSmartContract &&o) noexcept;

      const interface::types::AccountIdType &caller() const override;

      const interface::types::AccountIdType &callee() const override;

      const interface::types::SmartContractCodeType &code() const override;

      const interface::types::SmartContractCodeType &input() const override;

     private:
      const iroha::protocol::AddSmartContract &add_smart_contract_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_ADD_SMART_CONTRACT_HPP
