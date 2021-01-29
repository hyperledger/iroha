package jp.co.soramitsu.iroha2.model.instruction;

import jp.co.soramitsu.iroha2.model.Expression;
import lombok.Data;
import lombok.NonNull;

@Data
public class Transfer implements Instruction {

  @NonNull
  private Expression sourceId; // EvaluatesTo<IdBox>
  @NonNull
  private Expression object; // EvaluatesTo<Value>
  @NonNull
  private Expression destinationId; // valuatesTo<IdBox>

  @Override
  public int getIndex() {
    return 4;
  }
}
