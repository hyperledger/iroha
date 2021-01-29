package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.UnionWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.ValueBox;

public class ValueBoxWriter implements ScaleWriter<ValueBox> {

  private static UnionWriter<ValueBox> VALUE_WRITER = new UnionWriter<>(
      new U32Writer(), // 0 - U32
      new BoolWriter(), // 1 - Bool
      new VectorWriter(), // 2 - Vec
      new IdWriter(), // 3 - Id
      new IdentifiableWriter(), // 4 - Identifiable
      new PublicKeyWriter(), // 5 - PublicKey
      new ParameterWriter() // 6 - Parameter
  );

  @Override
  public void write(ScaleCodecWriter writer, ValueBox value) throws IOException {
    writer.write(VALUE_WRITER, new EnumerationUnionValue<>(value));
  }

}
