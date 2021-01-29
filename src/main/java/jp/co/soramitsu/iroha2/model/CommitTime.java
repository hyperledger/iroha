package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class CommitTime implements ParameterBox {

  @NonNull
  private U128 value;

  @Override
  public int getIndex() {
    return 1;
  }
}
