package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.FindAccountsByDomainName;

/**
 * Scale writer that writes nothing.
 */
class FindAccountsByDomainNameWriter implements ScaleWriter<FindAccountsByDomainName> {

  @Override
  public void write(ScaleCodecWriter writer, FindAccountsByDomainName value) throws IOException {
    writer.writeAsList(value.getDomainName().getBytes());
  }
}
