package jp.co.soramitsu.iroha2.model.instruction;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import lombok.NonNull;

@Data
public class Sequence implements Instruction {

  @NonNull
  private List<Instruction> instructions;

  public Sequence() {
    instructions = new ArrayList<>();
  }

  public Sequence(List<Instruction> instructions) {
    this.instructions = instructions;
  }

  @Override
  public int getIndex() {
    return 7;
  }
}
