package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Equal implements Expression {

  // Expression, which should evaluate to `U32`.
  @NonNull
  private Expression left;
  // Expression, which should evaluate to `U32`.
  @NonNull
  private Expression right;


  @Override
  public int getIndex() {
    return 4;
  }
}
