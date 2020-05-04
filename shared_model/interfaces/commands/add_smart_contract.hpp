#ifndef IROHA_SHARED_MODEL_ADD_SMART_CONTRACT_HPP
#define IROHA_SHARED_MODEL_ADD_SMART_CONTRACT_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Smart contract code class
     */
    class AddSmartContract : public ModelPrimitive<AddSmartContract> {
      public:

        /**
         * @return Address of caller
         * TODO(IvanTyulyandin) It should be taken from transaction metadata
         */
        virtual const types::AccountIdType &caller() const = 0;

        /**
         * @return Address of callee
         */
        virtual const types::AccountIdType &callee() const = 0;

        /**
         * @return Bytecode of the smart contract
         */
        virtual const types::SmartContractCodeType &code() const = 0;

        /**
         * @return Input of the smart contract as bytecode in a special format
         */
        virtual const types::SmartContractCodeType &input() const = 0;

        std::string toString() const override;

        bool operator==(const ModelType &rhs) const override;
    };
  } // namespace interface
} // namespace shared_model

#endif  // IROHA_SHARED_MODEL_ADD_SMART_CONTRACT_HPP
