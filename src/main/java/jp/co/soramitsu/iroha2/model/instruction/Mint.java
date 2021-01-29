package jp.co.soramitsu.iroha2.model.instruction;

import jp.co.soramitsu.iroha2.model.Expression;
import lombok.Data;
import lombok.NonNull;

@Data
public class Mint implements Instruction {

  @NonNull
  Expression object;
  @NonNull
  Expression destinationId;

  @Override
  public int getIndex() {
    return 2;
  }
}
