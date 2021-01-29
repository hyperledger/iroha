package jp.co.soramitsu.iroha2.scale.writer.instruction;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.UnionWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.instruction.Instruction;
import jp.co.soramitsu.iroha2.scale.writer.EnumerationUnionValue;

public class InstructionWriter implements ScaleWriter<Instruction> {

  /**
   * Scale writers for queries, position in list must be an id in union.
   */
  private static UnionWriter<Instruction> INSTRUCTION_WRITER = new UnionWriter<>(
      new RegisterWriter(), // 0 - Register
      new UnregisterWriter(), // 1 - Unregister
      new MintWriter(),  // 2 - Mint
      new BurnWriter(), // 3 - Burn
      new TransferWriter(), // 4 - Transfer
      new IfWriter(), // 5 - If
      new PairWriter(), // 6 - Pair
      new SequenceWriter(), // 7 - Sequence
      new FailWriter() // 8 - Fail
  );


  @Override
  public void write(ScaleCodecWriter writer, Instruction value) throws IOException {
    writer.write(INSTRUCTION_WRITER, new EnumerationUnionValue<>(value));
  }

}
