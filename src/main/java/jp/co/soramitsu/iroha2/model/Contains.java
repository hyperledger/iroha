package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Contains implements Expression {

  // Expression, which should evaluate to `Vec<Value>`.
  @NonNull
  private Expression collection;

  // Expression, which should evaluate to `Value`.
  @NonNull
  private Expression element;


  @Override
  public int getIndex() {
    return 11;
  }
}
