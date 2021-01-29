package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class DomainName implements IdBox {

  @NonNull
  private String name;

  @Override
  public int getIndex() {
    return 3;
  }
}
