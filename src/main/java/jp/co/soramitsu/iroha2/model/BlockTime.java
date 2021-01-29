package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class BlockTime implements ParameterBox {

  @NonNull
  private U128 value;

  @Override
  public int getIndex() {
    return 3;
  }
}
