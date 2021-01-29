package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Greater;

public class GreaterReader implements ScaleReader<Greater> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public Greater read(ScaleCodecReader reader) {
    return new Greater(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
