package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Parameter implements ValueBox {

  @NonNull
  private ParameterBox value;

  @Override
  public int getIndex() {
    return 6;
  }
}
