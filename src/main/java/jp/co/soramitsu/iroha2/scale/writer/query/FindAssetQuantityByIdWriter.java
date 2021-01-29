package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindAssetQuantityById;
import jp.co.soramitsu.iroha2.scale.writer.AssetIdWriter;

class FindAssetQuantityByIdWriter implements ScaleWriter<FindAssetQuantityById> {

  private static AssetIdWriter ASSET_ID_WRITER = new AssetIdWriter();

  @Override
  public void write(ScaleCodecWriter writer, FindAssetQuantityById value) throws IOException {
    writer.write(ASSET_ID_WRITER, value.getAssetId());
  }
}
