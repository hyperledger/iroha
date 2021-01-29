package jp.co.soramitsu.iroha2.model.instruction;

import lombok.Data;
import lombok.NonNull;

@Data
public class Fail implements Instruction {

  @NonNull
  private String message;

  @Override
  public int getIndex() {
    return 8;
  }
}
