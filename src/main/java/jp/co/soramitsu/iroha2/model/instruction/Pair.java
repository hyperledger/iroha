package jp.co.soramitsu.iroha2.model.instruction;

import lombok.Data;
import lombok.NonNull;

@Data
public class Pair implements Instruction {

  @NonNull
  private Instruction left;
  @NonNull
  private Instruction right;

  @Override
  public int getIndex() {
    return 6;
  }
}
