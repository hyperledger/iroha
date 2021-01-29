package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Identifiable implements ValueBox {

  @NonNull
  private IdentifiableBox value;

  @Override
  public int getIndex() {
    return 4;
  }
}
