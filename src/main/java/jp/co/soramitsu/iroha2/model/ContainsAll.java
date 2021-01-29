package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class ContainsAll implements Expression {

  // Expression, which should evaluate to `Vec<Value>`.
  @NonNull
  private Expression collection;
  
  // Expression, which should evaluate to `Vec<Value>`.
  @NonNull
  private Expression elements;


  @Override
  public int getIndex() {
    return 12;
  }
}
