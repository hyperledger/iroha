package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAllAssetsDefinitions;

public class FindAllAssetsDefinitionsReader implements ScaleReader<FindAllAssetsDefinitions> {

  @Override
  public FindAllAssetsDefinitions read(ScaleCodecReader scaleCodecReader) {
    return new FindAllAssetsDefinitions();
  }
}
