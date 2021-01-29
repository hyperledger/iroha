package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAssetById;
import jp.co.soramitsu.iroha2.scale.reader.AssetIdReader;

public class FindAssetByIdReader implements ScaleReader<FindAssetById> {

  private static final AssetIdReader ASSET_ID_READER = new AssetIdReader();

  @Override
  public FindAssetById read(ScaleCodecReader reader) {
    return new FindAssetById(reader.read(ASSET_ID_READER));
  }
}
