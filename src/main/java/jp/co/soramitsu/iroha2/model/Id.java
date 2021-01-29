package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Id implements ValueBox {

  @NonNull
  private IdBox id;

  @Override
  public int getIndex() {
    return 3;
  }
}
