package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Equal;

public class EqualReader implements ScaleReader<Equal> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public Equal read(ScaleCodecReader reader) {
    return new Equal(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
