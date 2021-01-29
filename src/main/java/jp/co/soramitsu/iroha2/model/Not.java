package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Not implements Expression {

  // Expression, which should evaluate to `bool`.
  @NonNull
  private Expression expression;


  @Override
  public int getIndex() {
    return 5;
  }
}
