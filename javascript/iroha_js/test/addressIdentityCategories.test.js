import assert from "node:assert/strict";
import test from "node:test";
import { curveIdFromAlgorithm, curveIdToAlgorithm, AccountAddressErrorCode } from "../src/address.js";

test("canonical address identities and unknown categories are independent of native availability", () => {
  const entries = [["ed25519",1],["secp256k1",4],["bls_normal",3],["bls_small",5],["ml-dsa",2],
    ["gost3410-2012-256-paramset-a",10],["gost3410-2012-256-paramset-b",11],
    ["gost3410-2012-256-paramset-c",12],["gost3410-2012-512-paramset-a",13],
    ["gost3410-2012-512-paramset-b",14],["sm2",15]];
  for (const [algorithm, curve] of entries) {
    assert.equal(curveIdFromAlgorithm(algorithm), curve);
    assert.equal(curveIdToAlgorithm(curve), algorithm);
  }
  for (const alias of ["ED25519","ed","secp","bls-normal","mldsa","ML-DSA-65","gost256a","sm-2","future"]) {
    assert.throws(() => curveIdFromAlgorithm(alias), error => error.code === AccountAddressErrorCode.UNKNOWN_ALGORITHM);
  }
  assert.throws(() => curveIdToAlgorithm(255), error => error.code === AccountAddressErrorCode.UNKNOWN_CURVE);
  assert.equal(AccountAddressErrorCode.UNSUPPORTED_IMPLEMENTATION, "ERR_UNSUPPORTED_IMPLEMENTATION");
  assert.equal(Object.hasOwn(AccountAddressErrorCode, "UNSUPPORTED_ALGORITHM"), false);
});
