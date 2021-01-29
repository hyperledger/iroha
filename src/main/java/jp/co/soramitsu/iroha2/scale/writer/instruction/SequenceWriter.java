package jp.co.soramitsu.iroha2.scale.writer.instruction;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.ListWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.instruction.Instruction;
import jp.co.soramitsu.iroha2.model.instruction.Sequence;

public class SequenceWriter implements ScaleWriter<Sequence> {

  private static final ListWriter<Instruction> INSTRUCTIONS_WRITER = new ListWriter<>(
      new InstructionWriter());

  @Override
  public void write(ScaleCodecWriter writer, Sequence value) throws IOException {
    writer.write(INSTRUCTIONS_WRITER, value.getInstructions());
  }
}
