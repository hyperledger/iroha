package jp.co.soramitsu.iroha2.model.instruction;

import jp.co.soramitsu.iroha2.model.Expression;
import lombok.Data;
import lombok.NonNull;

@Data
public class If implements Instruction {

  @NonNull
  private Expression condition; // EvaluatesTo<bool>
  @NonNull
  private Instruction then;
  // Null means not set
  private Instruction otherwise;   // optional

  public If(Expression condition, Instruction then) {
    this.condition = condition;
    this.then = then;
  }

  public If(Expression condition, Instruction then, Instruction otherwise) {
    this.condition = condition;
    this.then = then;
    this.otherwise = otherwise;
  }

  @Override
  public int getIndex() {
    return 5;
  }
}
