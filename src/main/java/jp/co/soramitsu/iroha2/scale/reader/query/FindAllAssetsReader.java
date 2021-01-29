package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAllAssets;

public class FindAllAssetsReader implements ScaleReader<FindAllAssets> {

  @Override
  public FindAllAssets read(ScaleCodecReader scaleCodecReader) {
    return new FindAllAssets();
  }
}
