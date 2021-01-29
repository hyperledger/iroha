package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByName;

public class FindAssetsByNameReader implements ScaleReader<FindAssetsByName> {

  @Override
  public FindAssetsByName read(ScaleCodecReader reader) {
    return new FindAssetsByName(reader.readString());
  }
}
