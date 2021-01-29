package jp.co.soramitsu.iroha2.model;

import java.util.List;
import lombok.Data;
import lombok.NonNull;

@Data
public class Vector implements ValueBox {

  @NonNull
  private List<Value> vector;

  @Override
  public int getIndex() {
    return 2;
  }
}
