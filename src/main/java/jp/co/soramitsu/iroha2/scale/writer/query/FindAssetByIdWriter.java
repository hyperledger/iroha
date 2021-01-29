package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindAssetById;
import jp.co.soramitsu.iroha2.scale.writer.AssetIdWriter;

/**
 * Scale writer that writes nothing.
 */
class FindAssetByIdWriter implements ScaleWriter<FindAssetById> {

  private static AssetIdWriter ID_WRITER = new AssetIdWriter();

  @Override
  public void write(ScaleCodecWriter writer, FindAssetById value) throws IOException {
    writer.write(ID_WRITER, value.getId());
  }
}
