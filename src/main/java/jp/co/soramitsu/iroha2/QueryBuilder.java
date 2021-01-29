package jp.co.soramitsu.iroha2;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;
import jp.co.soramitsu.iroha2.model.AccountId;
import jp.co.soramitsu.iroha2.model.AssetId;
import jp.co.soramitsu.iroha2.model.DefinitionId;
import jp.co.soramitsu.iroha2.model.PublicKey;
import jp.co.soramitsu.iroha2.model.Signature;
import jp.co.soramitsu.iroha2.model.query.FindAssetQuantityById;
import jp.co.soramitsu.iroha2.model.query.Query;
import jp.co.soramitsu.iroha2.model.query.SignedQueryRequest;
import jp.co.soramitsu.iroha2.scale.writer.query.QueryWriter;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.bouncycastle.jcajce.provider.digest.Blake2b.Blake2b256;

public class QueryBuilder {

  private SignedQueryRequest query = new SignedQueryRequest();

  public QueryBuilder() {
    long timestamp = new Date().getTime();
    query.setTimestamp(Long.toString(timestamp));
  }

  public QueryBuilder setTimestamp(long timestamp) {
    query.setTimestamp(Long.toString(timestamp));
    return this;
  }

  public UnsignedQuery setQuery(Query query) {
    this.query.setQuery(query);
    return new UnsignedQuery(this.query);
  }

  public UnsignedQuery findAssetQuantityById(String assetName, String assetDomain,
      String accountName,
      String accountDomain) {
    AccountId accountId = new AccountId(accountName, accountDomain);
    DefinitionId definitionId = new DefinitionId(assetName, assetDomain);
    AssetId assetId = new AssetId(definitionId, accountId);
    FindAssetQuantityById request = new FindAssetQuantityById(assetId);
    query.setQuery(request);
    return new UnsignedQuery(this.query);
  }

}
