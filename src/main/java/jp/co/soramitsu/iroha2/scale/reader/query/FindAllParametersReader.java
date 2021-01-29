package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAllParameters;

public class FindAllParametersReader implements ScaleReader<FindAllParameters> {

  @Override
  public FindAllParameters read(ScaleCodecReader scaleCodecReader) {
    return new FindAllParameters();
  }
}
