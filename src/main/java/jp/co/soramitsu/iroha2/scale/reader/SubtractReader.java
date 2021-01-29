package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.Subtract;

public class SubtractReader implements ScaleReader<Subtract> {

  private static final ExpressionReader EXPRESSION_READER = new ExpressionReader();

  @Override
  public Subtract read(ScaleCodecReader reader) {
    return new Subtract(reader.read(EXPRESSION_READER), reader.read(EXPRESSION_READER));
  }
}
