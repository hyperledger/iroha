package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class If implements Expression {

  // Expression, which should evaluate to `bool`.
  @NonNull
  private Expression condition;

  // Expression, which should evaluate to `Value`.
  @NonNull
  private Expression thenExpression;

  // Expression, which should evaluate to `Value`.
  @NonNull
  private Expression elseExpression;


  @Override
  public int getIndex() {
    return 8;
  }
}
