import test from "node:test";
import assert from "node:assert/strict";
import { normalizeIvmFault } from "../src/ivmFault.js";
import { ToriiError } from "../src/toriiErrors.js";

const fault = () => ({
  kind: { kind: "PointerAbi", value: { kind: "WrongType", value: null } },
  site: {
    code_hash: "12".repeat(32),
    selector: { kind: "Generic", value: null },
    position: { kind: "Initialization", value: null },
  },
});

test("HTTP errors preserve the canonical typed fault without diagnostic strings", () => {
  const value = fault();
  const error = new ToriiError("execution failed", { details: { ivm_fault: value } });
  assert.deepEqual(error.details.ivm_fault, value);
  value.kind.value.kind = "InvalidAddress";
  assert.equal(error.details.ivm_fault.kind.value.kind, "WrongType");
  assert.throws(() => new ToriiError("bad wire", { details: { ivm_fault: { ...fault(), trace: "unbounded" } } }), /exactly/);
});

test("fault fields reject getters and unsupported tags before interpretation", () => {
  const value = fault();
  let invoked = false;
  Object.defineProperty(value.site, "code_hash", { enumerable: true, get() { invoked = true; return "12".repeat(32); } });
  assert.throws(() => normalizeIvmFault(value, "fault"), /data property/);
  assert.equal(invoked, false);
  for (const tag of ["", "divisionbyzero", "0", "OutOfGas "]) {
    const value = fault();
    value.kind.kind = tag;
    assert.throws(() => normalizeIvmFault(value, "fault"), /category/);
  }
});
