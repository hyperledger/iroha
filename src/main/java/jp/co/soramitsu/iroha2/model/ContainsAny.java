package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class ContainsAny implements Expression {

  // Expression, which should evaluate to `Value::Vec`.
  @NonNull
  private Expression collection;
  // Expression, which should evaluate to `Value::Vec`.
  @NonNull
  private Expression elements;


  @Override
  public int getIndex() {
    return 13;
  }
}
