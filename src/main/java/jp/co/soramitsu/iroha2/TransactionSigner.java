package jp.co.soramitsu.iroha2;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;
import jp.co.soramitsu.iroha2.model.Payload;
import jp.co.soramitsu.iroha2.model.PublicKey;
import jp.co.soramitsu.iroha2.model.Signature;
import jp.co.soramitsu.iroha2.model.instruction.Transaction;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

public class TransactionSigner {

  private Transaction transaction;

  public TransactionSigner(Payload payload) {
    this.transaction = new Transaction(payload);
  }

  public TransactionSigner sign(KeyPair keyPair)
      throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    byte[] checksum = transaction.getHash();

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
    List<Signature> signatures = transaction.getSignatures();
    signatures.add(signature);
    transaction.setSignatures(signatures);
    return this;
  }

  public Transaction build() {
    return transaction;
  }

}
