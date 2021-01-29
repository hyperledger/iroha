package jp.co.soramitsu.iroha2;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import jp.co.soramitsu.iroha2.model.AccountId;
import jp.co.soramitsu.iroha2.model.instruction.Instruction;
import jp.co.soramitsu.iroha2.model.Payload;

public class TransactionBuilder {

  public static final long DEFAULT_TIME_TO_LIVE = 100_000;

  private Payload payload = new Payload();

  public TransactionBuilder() {
    long timestamp = new Date().getTime();
    payload.setCreationTime(BigInteger.valueOf(timestamp));
    payload.setTimeToLiveMs(BigInteger.valueOf(DEFAULT_TIME_TO_LIVE));
  }

  public TransactionBuilder setCreator(AccountId accountId) {
    payload.setAccountId(accountId);
    return this;
  }

  public TransactionBuilder setCreator(String name, String domain) {
    AccountId accountId = new AccountId(name, domain);
    payload.setAccountId(accountId);
    return this;
  }

  public TransactionBuilder addInstruction(Instruction instruction) {
    List<Instruction> instructions = payload.getInstructions();
    instructions.add(instruction);
    payload.setInstructions(instructions);
    return this;
  }

  public TransactionBuilder setCreationTime(long time) {
    payload.setCreationTime(BigInteger.valueOf(time));
    return this;
  }

  public TransactionBuilder setCreationTime(BigInteger time) {
    payload.setCreationTime(time);
    return this;
  }

  public TransactionBuilder setTimeToLive(long time) {
    payload.setTimeToLiveMs(BigInteger.valueOf(time));
    return this;
  }

  public TransactionBuilder setTimeToLive(BigInteger time) {
    payload.setTimeToLiveMs(time);
    return this;
  }

  public TransactionSigner build() {
    return new TransactionSigner(payload);
  }

}
