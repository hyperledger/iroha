#include "interfaces/commands/add_smart_contract.hpp"

namespace shared_model {
  namespace interface {

    std::string AddSmartContract::toString() const {
      return detail::PrettyStringBuilder()
          .init("AddSmartContract")
          .append("caller", caller())
          .append("callee", callee())
          .append("code", code())
          .append("input", input())
          .finalize();
    }

    bool AddSmartContract::operator==(const ModelType &rhs) const {
      return caller() == rhs.caller()
          && callee() == rhs.callee()
          && code() == rhs.code()
          && input() == rhs.input();
;
    }

  }  // namespace interface
}  // namespace shared_model
