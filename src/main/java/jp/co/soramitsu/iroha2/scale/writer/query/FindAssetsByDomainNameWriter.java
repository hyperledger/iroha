package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByDomainName;

/**
 * Scale writer that writes nothing.
 */
class FindAssetsByDomainNameWriter implements ScaleWriter<FindAssetsByDomainName> {

  @Override
  public void write(ScaleCodecWriter writer, FindAssetsByDomainName value) throws IOException {
    writer.writeAsList(value.getDomainName().getBytes());
  }
}
