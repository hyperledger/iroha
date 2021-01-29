package jp.co.soramitsu.iroha2;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import jp.co.soramitsu.iroha2.model.PublicKey;
import jp.co.soramitsu.iroha2.model.Signature;
import jp.co.soramitsu.iroha2.model.query.SignedQueryRequest;
import jp.co.soramitsu.iroha2.scale.writer.query.QueryWriter;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.bouncycastle.jcajce.provider.digest.Blake2b.Blake2b256;

public class UnsignedQuery {

  private SignedQueryRequest query;

  public UnsignedQuery(SignedQueryRequest query) {
    this.query = query;
  }

  public SignedQueryRequest sign(KeyPair keyPair)
      throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    // get hash of query
    ByteArrayOutputStream hashBuf = new ByteArrayOutputStream();
    ScaleCodecWriter hashCodec = new ScaleCodecWriter(hashBuf);
    hashCodec.write(new QueryWriter(), query.getQuery());
    hashCodec.writeByteArray(query.getTimestamp().getBytes());
    Blake2b256 hash = new Blake2b256();
    byte[] checksum = hash.digest(hashBuf.toByteArray());

    // sign query SHA-512
    EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    java.security.Signature sgr = new EdDSAEngine(
        MessageDigest.getInstance(spec.getHashAlgorithm()));
    sgr.initSign(keyPair.getPrivate());
    sgr.update(checksum);
    byte[] rawSignature = sgr.sign();

    PublicKey publicKey = new PublicKey("ed25519",
        Utils.getActualPublicKey(keyPair.getPublic().getEncoded()));
    Signature signature = new Signature(publicKey, rawSignature);
    query.setSignature(signature);

    return query;
  }

}
