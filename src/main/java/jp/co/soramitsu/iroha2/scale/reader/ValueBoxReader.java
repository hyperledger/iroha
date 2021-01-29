package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.reader.UnionReader;
import jp.co.soramitsu.iroha2.model.ValueBox;

public class ValueBoxReader implements ScaleReader<ValueBox> {

  private static final UnionReader<ValueBox> VALUE_READER = new UnionReader<>(
      new U32Reader(), // 0 - U32
      new BoolReader(), // 1 - Bool
      new VectorReader(), // 2 - Vec<Value>
      new IdReader(), // 3 - IdBox
      new IdentifiableReader(), // 4 - Identifiable
      new PublicKeyReader(), // 5 - Public Key
      new ParameterReader() // 6 - Parameter
  );

  @Override
  public ValueBox read(ScaleCodecReader reader) {
    return VALUE_READER.read(reader).getValue();
  }

}
