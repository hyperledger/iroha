package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.If;

public class IfReader implements ScaleReader<If> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public If read(ScaleCodecReader reader) {
    return new If(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER),
        reader.read(EXPRESSION_READER));
  }
}
