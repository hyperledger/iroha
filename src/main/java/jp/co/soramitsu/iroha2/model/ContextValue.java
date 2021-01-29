package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class ContextValue implements Expression {

  // Expression, which should evaluate to `Value`.
  @NonNull
  private String valueName;


  @Override
  public int getIndex() {
    return 14;
  }
}
