package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Raw implements Expression {

  @NonNull
  private Value value;

  @Override
  public int getIndex() {
    return 9;
  }
}
