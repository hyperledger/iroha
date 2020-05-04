#include "interfaces/commands/engine_call.hpp"

namespace shared_model {
  namespace interface {

    std::string EngineCall::toString() const {
      return detail::PrettyStringBuilder()
          .init("EngineCall")
          .append("caller", caller())
          .append("callee", callee())
          .append("code", code())
          .append("input", input())
          .finalize();
    }

    bool EngineCall::operator==(const ModelType &rhs) const {
      return caller() == rhs.caller()
          && callee() == rhs.callee()
          && code() == rhs.code()
          && input() == rhs.input();
;
    }

  }  // namespace interface
}  // namespace shared_model
