"use strict";

import test from "node:test";
import assert from "node:assert/strict";

import {
  buildPacs008Message,
  buildPacs009Message,
  buildSamplePacs008Message,
  buildSamplePacs009Message,
  buildCamt052Message,
  buildCamt056Message,
  buildSampleCamt052Message,
  buildSampleCamt056Message,
} from "../src/isoBridge.js";
import { ValidationError, ValidationErrorCode } from "../src/index.js";

import { ISO_PAYMENT_INTENT } from "./fixtures/isoNativePayment.js";

const FIXED_CREATION = "2026-02-01T00:00:00Z";

test("buildPacs008Message renders minimal document", () => {
  const xml = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    messageId: "example-msg",
    creationDateTime: "2026-02-01T12:00:00Z",
    instructionId: "instr-001",
    endToEndId: "end-001",
    transactionId: "tx-001",
    settlementDate: "2026-02-02",
    amount: { currency: "EUR", value: "25.00" },
    instigatingAgent: { bic: "DEUTDEFF", lei: "529900ODI3047E2LIV03" },
    instructedAgent: { bic: "COBADEFF" },
    debtorAccount: { iban: "DE89370400440532013000" },
    creditorAccount: { otherId: "ALICE-ACC-01" },
    purposeCode: "SECU",
    supplementaryData: { account_id: "34mSYnDgbaJM58rbLoif4Tkp7G4LTcGTWkBnWUGuYYFogLyNhhuq386y2zQoSXk5oi1iY4YYx", leg: "delivery" },
  });

  assert.match(xml, /<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs\.008\.001\.08">/);
  assert.match(xml, /<MsgId>example-msg<\/MsgId>/);
  assert.match(xml, /<EndToEndId>end-001<\/EndToEndId>/);
  assert.match(xml, /<IntrBkSttlmAmt Ccy="EUR">25\.00<\/IntrBkSttlmAmt>/);
  assert.match(xml, /<IntrBkSttlmDt>2026-02-02<\/IntrBkSttlmDt>/);
  assert.match(xml, /<IBAN>DE89370400440532013000<\/IBAN>/);
  assert.match(xml, /<Othr><Id>ALICE-ACC-01<\/Id><\/Othr>/);
  assert.match(xml, /<Purp><Cd>SECU<\/Cd><\/Purp>/);
  assert.ok(
    xml.includes("&quot;account_id&quot;:&quot;34mSYnDgbaJM58rbLoif4Tkp7G4LTcGTWkBnWUGuYYFogLyNhhuq386y2zQoSXk5oi1iY4YYx&quot;"),
    "supplementary data should encode account_id",
  );
  assert.ok(
    xml.includes("&quot;leg&quot;:&quot;delivery&quot;"),
    "supplementary data should encode leg metadata",
  );
});

test("creationDateTime must include a timezone offset", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "tz-missing",
        creationDateTime: "2026-02-01T12:00:00",
        instructionId: "instr-tz",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
      }),
    /creationDateTime must be an ISO-8601 datetime string with timezone offset/,
  );
});

test("ISO builders surface ValidationError metadata for invalid datetimes", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "invalid-tz",
        creationDateTime: "2026-02-01T12:00:00",
        instructionId: "instr-tz",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
      }),
    (error) => {
      assert.ok(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_STRING);
      assert.equal(error.path, "creationDateTime");
      return true;
    },
  );
});

test("creationDateTime is required for ISO builders", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "missing-creation-008",
        instructionId: "instr-008",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
      }),
    /creationDateTime is required/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr-009",
        amount: { currency: "USD", value: "1.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
      }),
    /creationDateTime is required/,
  );
});

test("creationDateTime with offsets normalises to UTC", () => {
  const xml = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    messageId: "tz-offset",
    creationDateTime: "2026-02-01T12:34:56+02:30",
    instructionId: "instr-offset",
    amount: { currency: "USD", value: "10.00" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
  });
  assert.match(xml, /<CreDtTm>2026-02-01T10:04:56\.000Z<\/CreDtTm>/);
});

test("settlementDate validates calendar dates", () => {
  const base = {
    messageId: "date-valid",
    creationDateTime: "2026-02-01T00:00:00Z",
    instructionId: "instr-date",
    amount: { currency: "EUR", value: "5.00" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
  };

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        ...base,
        settlementDate: "2026-13-01",
      }),
    /settlementDate must be a valid calendar date/,
  );
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        ...base,
        settlementDate: "2026-02-30",
      }),
    /settlementDate must be a valid calendar date/,
  );

  const leapYearXml = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    ...base,
    settlementDate: "2024-02-29",
  });
  assert.match(leapYearXml, /<IntrBkSttlmDt>2024-02-29<\/IntrBkSttlmDt>/);
});

test("remittanceInformation renders unstructured remittance lines and enforces Max140Text", () => {
  const xml = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    messageId: "remit-008",
    creationDateTime: FIXED_CREATION,
    instructionId: "instr-remit-008",
    amount: { currency: "EUR", value: "18.00" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
    remittanceInformation: ["First remittance line", "Second remittance line"],
  });
  assert.match(
    xml,
    /<RmtInf><Ustrd>First remittance line<\/Ustrd><Ustrd>Second remittance line<\/Ustrd><\/RmtInf>/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr-remit-009",
        amount: { currency: "USD", value: "5.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: FIXED_CREATION,
        remittanceInformation: "x".repeat(141),
      }),
    /remittanceInformation must be <= 140 characters/,
  );

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "remit-empty",
        creationDateTime: FIXED_CREATION,
        instructionId: "instr-remit-empty",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
        remittanceInformation: [],
      }),
    /remittanceInformation must not be empty/,
  );
});

test("amount enforces ISO 4217 minor units", () => {
  const jpyXml = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    messageId: "minor-jpy",
    instructionId: "instr-jpy",
    amount: { currency: "JPY", value: "1250" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
    creationDateTime: FIXED_CREATION,
  });
  assert.match(jpyXml, /<IntrBkSttlmAmt Ccy="JPY">1250<\/IntrBkSttlmAmt>/);

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "minor-jpy-zero-fractional",
        instructionId: "instr-jpy-zero-fractional",
        amount: { currency: "JPY", value: "1250.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
        creationDateTime: FIXED_CREATION,
      }),
    /fractional digits for JPY/,
  );

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "minor-jpy-fractional",
        instructionId: "instr-jpy-fractional",
        amount: { currency: "JPY", value: "1250.10" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
        creationDateTime: FIXED_CREATION,
      }),
    /fractional digits for JPY/,
  );

  const bhdXml = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    instructionId: "instr-bhd",
    amount: { currency: "BHD", value: "42.5" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    creationDateTime: "2026-02-01T00:00:00Z",
  });
  assert.match(bhdXml, /<IntrBkSttlmAmt Ccy="BHD">42\.500<\/IntrBkSttlmAmt>/);

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr-bhd-invalid",
        amount: { currency: "BHD", value: "1.2345" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /decimal places for BHD/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr-eur-invalid",
        amount: { currency: "EUR", value: "1.234" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /decimal places for EUR/,
  );

  const clfXml = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    messageId: "clf-minor",
    instructionId: "instr-clf",
    amount: { currency: "CLF", value: "12.3456" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
    creationDateTime: FIXED_CREATION,
  });
  assert.match(clfXml, /<IntrBkSttlmAmt Ccy="CLF">12\.3456<\/IntrBkSttlmAmt>/);

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "clf-invalid",
        instructionId: "instr-clf-invalid",
        amount: { currency: "CLF", value: "12.34567" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
        creationDateTime: FIXED_CREATION,
      }),
    /decimal places for CLF/,
  );

  const uywXml = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    instructionId: "instr-uyw",
    amount: { currency: "UYW", value: "0.1234" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    creationDateTime: "2026-02-01T00:00:00Z",
  });
  assert.match(uywXml, /<IntrBkSttlmAmt Ccy="UYW">0\.1234<\/IntrBkSttlmAmt>/);

  const uywPadded = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    instructionId: "instr-uyw-pad",
    amount: { currency: "UYW", value: "0.123" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    creationDateTime: "2026-02-01T00:00:00Z",
  });
  assert.match(uywPadded, /<IntrBkSttlmAmt Ccy="UYW">0\.1230<\/IntrBkSttlmAmt>/);

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr-uyw-invalid",
        amount: { currency: "UYW", value: "0.12345" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /decimal places for UYW/,
  );
});

test("accounts render proxy aliases alongside IBAN when provided", () => {
  const xml = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    messageId: "proxy-008",
    instructionId: "instr-proxy-008",
    creationDateTime: FIXED_CREATION,
    amount: { currency: "EUR", value: "12.00" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
    debtorAccount: {
      iban: "DE89370400440532013000",
      proxy: { id: "alice-proxy-handle", typeCode: "MSIS" },
    },
    creditorAccount: {
      iban: "FR7630006000011234567890189",
      proxy: { id: "bob@example.com", typeProprietary: "EMAIL" },
    },
  });

  assert.match(
    xml,
    /<DbtrAcct><Id><IBAN>DE89370400440532013000<\/IBAN><\/Id><Prxy><Tp><Cd>MSIS<\/Cd><\/Tp><Id>alice-proxy-handle<\/Id><\/Prxy><\/DbtrAcct>/,
  );
  assert.match(
    xml,
    /<CdtrAcct><Id><IBAN>FR7630006000011234567890189<\/IBAN><\/Id><Prxy><Tp><Prtry>EMAIL<\/Prtry><\/Tp><Id>bob@example.com<\/Id><\/Prxy><\/CdtrAcct>/,
  );
});

test("proxy aliases enforce IBAN presence and validation constraints", () => {
  const base = {
    messageId: "proxy-validation",
    instructionId: "instr-proxy-validation",
    creationDateTime: FIXED_CREATION,
    amount: { currency: "EUR", value: "5.00" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
  };

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        ...base,
        debtorAccount: { otherId: "debtor-other", proxy: { id: "alias" } },
      }),
    /proxy requires iban alongside proxy identifiers/,
  );

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        ...base,
        debtorAccount: {
          iban: "DE89370400440532013000",
          proxy: { id: "x".repeat(2050) },
        },
      }),
    /proxy\.id must be at most 2048 characters/,
  );

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        ...base,
        debtorAccount: {
          iban: "DE89370400440532013000",
          proxy: { id: "alice", typeCode: "ABCDE" },
        },
      }),
    /typeCode must be 1-4 uppercase letters or digits/,
  );

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        ...base,
        debtorAccount: {
          iban: "DE89370400440532013000",
          proxy: { id: "alice", typeCode: "MSIS", typeProprietary: "EMAIL" },
        },
      }),
    /must not set both typeCode and typeProprietary/,
  );
});

test("buildPacs008Message renders debtor/creditor parties and agents", () => {
  const xml = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    messageId: "parties-demo",
    instructionId: "instr-demo",
    amount: { currency: "EUR", value: "10.00" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
    creationDateTime: FIXED_CREATION,
    debtorAgent: { bic: "DEUTDEFF500" },
    creditorAgent: { bic: "COBADEFF500", lei: "529900ODI3047E2LIV03" },
    debtor: {
      name: "Wonderland Asset Manager",
      lei: "529900ODI3047E2LIV03",
      identifier: "ALICE-ACCOUNT-01",
      identifierScheme: "NORITO_ACCOUNT_ID",
    },
    creditor: {
      name: "White Rabbit Custody",
      identifier: "WR-ACC-42",
    },
  });

  assert.match(xml, /<DbtrAgt><FinInstnId><BICFI>DEUTDEFF500<\/BICFI><\/FinInstnId><\/DbtrAgt>/);
  assert.match(
    xml,
    /<CdtrAgt><FinInstnId><BICFI>COBADEFF500<\/BICFI><Othr><Id>529900ODI3047E2LIV03<\/Id><SchmeNm><Prtry>LEI<\/Prtry><\/SchmeNm><\/Othr><\/FinInstnId><\/CdtrAgt>/,
  );
  assert.match(
    xml,
    /<Dbtr><Nm>Wonderland Asset Manager<\/Nm><Id><OrgId><LEI>529900ODI3047E2LIV03<\/LEI><Othr><Id>ALICE-ACCOUNT-01<\/Id><SchmeNm><Prtry>NORITO_ACCOUNT_ID<\/Prtry><\/SchmeNm><\/Othr><\/OrgId><\/Id><\/Dbtr>/,
  );
  assert.match(
    xml,
    /<Cdtr><Nm>White Rabbit Custody<\/Nm><Id><OrgId><Othr><Id>WR-ACC-42<\/Id><SchmeNm><Prtry>NORITO_PARTY_ID<\/Prtry><\/SchmeNm><\/Othr><\/OrgId><\/Id><\/Cdtr>/,
  );
});

test("buildPacs009Message renders minimal document", () => {
  const xml = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    messageId: "msg-009",
    businessMessageId: "biz-abc",
    messageDefinitionId: "pacs.009.001.08",
    creationDateTime: new Date("2026-02-03T09:30:00Z"),
    instructionId: "instr-xyz",
    transactionId: "tx-xyz",
    settlementDate: "2026-02-04",
    amount: { currency: "USD", value: 1250.5 },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    purposeCode: "SECU",
    supplementaryData: { alias: "pvp-demo" },
  });

  assert.match(xml, /<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs\.009\.001\.08">/);
  assert.match(xml, /<BizMsgIdr>biz-abc<\/BizMsgIdr>/);
  assert.match(xml, /<MsgDefIdr>pacs\.009\.001\.08<\/MsgDefIdr>/);
  assert.match(xml, /<InstrId>instr-xyz<\/InstrId>/);
  assert.match(xml, /<TxId>tx-xyz<\/TxId>/);
  assert.match(xml, /<IntrBkSttlmAmt Ccy="USD">1250\.50<\/IntrBkSttlmAmt>/);
  assert.ok(
    xml.includes("&quot;alias&quot;:&quot;pvp-demo&quot;"),
    "supplementary data should encode alias metadata",
  );
});

test("buildPacs009Message infers defaults when optional headers are omitted", () => {
  const xml = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    instructionId: "instr-default",
    amount: { currency: "USD", value: "42.00" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    creationDateTime: "2026-02-01T00:00:00Z",
  });

  assert.match(xml, /<MsgId>instr-default<\/MsgId>/);
  assert.match(xml, /<BizMsgIdr>instr-default<\/BizMsgIdr>/);
  assert.match(xml, /<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs\.009\.001\.08">/);
  assert.match(xml, /<MsgDefIdr>pacs\.009\.001\.08<\/MsgDefIdr>/);
});

test("buildPacs009Message enforces pacs.009 messageDefinitionId shape", () => {
  const base = {
    instructionId: "msg-009",
    amount: { currency: "USD", value: "1250.5" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    creationDateTime: FIXED_CREATION,
  };

  const xml = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    ...base,
    messageDefinitionId: "PACS.009.001.09",
  });
  assert.match(xml, /<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs\.009\.001\.09">/);
  assert.match(xml, /<MsgDefIdr>pacs\.009\.001\.09<\/MsgDefIdr>/);

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        ...base,
        messageDefinitionId: "pacs.008.001.10",
      }),
    /messageDefinitionId must match pacs\.009/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        ...base,
        messageDefinitionId: "pacs.009",
      }),
    /messageDefinitionId must match pacs\.009/,
  );
});

test("buildPacs009Message defaults Purp to SECU and validates overrides", () => {
  const xml = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    instructionId: "instr-default-purpose",
    amount: { currency: "USD", value: "5.00" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    creationDateTime: "2026-02-01T00:00:00Z",
  });
  assert.match(xml, /<Purp><Cd>SECU<\/Cd><\/Purp>/);

  const explicit = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    instructionId: "instr-explicit-purpose",
    amount: { currency: "USD", value: "1.00" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    purposeCode: "secu",
    creationDateTime: "2026-02-01T00:00:00Z",
  });
  assert.match(explicit, /<Purp><Cd>SECU<\/Cd><\/Purp>/);

  const cashPurpose = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    instructionId: "instr-explicit-purpose",
    amount: { currency: "USD", value: "1.00" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    purposeCode: "cash",
    creationDateTime: "2026-02-01T00:00:00Z",
  });
  assert.match(cashPurpose, /<Purp><Cd>CASH<\/Cd><\/Purp>/);

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr-bad-purpose",
        amount: { currency: "USD", value: "1.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        purposeCode: "too-long-to-send",
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /purposeCode must be 3-8 uppercase alphanumeric characters/,
  );
});

test("buildPacs009Message supports debtor/creditor metadata", () => {
  const xml = buildPacs009Message({
    ...ISO_PAYMENT_INTENT,
    instructionId: "instr-advanced",
    amount: { currency: "USD", value: "50.00" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "CHASUS33" },
    debtorAgent: { bic: "BOFAUS3NXXX" },
    creditorAgent: { bic: "CHASUS33XXX" },
    debtor: { name: "Primary Clearing Bank", lei: "213800D1EI4B9WTWWD28" },
    creditor: { name: "Counterparty Bank", identifier: "CP-123" },
    debtorAccount: { otherId: "PB-USD-NOSTRO" },
    creditorAccount: { iban: "GB82WEST12345698765432" },
    creationDateTime: "2026-02-01T00:00:00Z",
  });

  assert.match(xml, /<DbtrAgt><FinInstnId><BICFI>BOFAUS3NXXX<\/BICFI>/);
  assert.match(xml, /<CdtrAgt><FinInstnId><BICFI>CHASUS33XXX<\/BICFI>/);
  assert.match(xml, /<Dbtr><Nm>Primary Clearing Bank<\/Nm><Id><OrgId><LEI>213800D1EI4B9WTWWD28<\/LEI>/);
  assert.match(xml, /<Cdtr><Nm>Counterparty Bank<\/Nm><Id><OrgId><Othr><Id>CP-123<\/Id>/);
  assert.match(xml, /<DbtrAcct><Id><Othr><Id>PB-USD-NOSTRO<\/Id><\/Othr><\/Id><\/DbtrAcct>/);
  assert.match(xml, /<CdtrAcct><Id><IBAN>GB82WEST12345698765432<\/IBAN><\/Id><\/CdtrAcct>/);
});

test("supplementary data is canonicalised deterministically", () => {
  const baseFields = {
    messageId: "canonical-msg",
    creationDateTime: "2026-02-05T10:00:00Z",
    instructionId: "instr-canon",
    amount: { currency: "JPY", value: "1000" },
    instigatingAgent: { bic: "BOTKJPJT" },
    instructedAgent: { bic: "DEUTDEFF" },
  };

  const xmlA = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    ...baseFields,
    supplementaryData: {
      zeta: 1,
      alpha: { nestedB: "two", nestedA: "one" },
    },
  });
  const xmlB = buildPacs008Message({
    ...ISO_PAYMENT_INTENT,
    ...baseFields,
    supplementaryData: {
      alpha: { nestedA: "one", nestedB: "two" },
      zeta: 1,
    },
  });

  assert.equal(xmlA, xmlB, "supplementary data JSON should be identical regardless of key order");
  assert.ok(
    xmlA.includes(
      "&quot;alpha&quot;:{&quot;nestedA&quot;:&quot;one&quot;,&quot;nestedB&quot;:&quot;two&quot;},&quot;zeta&quot;:1",
    ),
    "canonical JSON should sort keys recursively",
  );
});

test("supplementary data rejects unsupported primitives", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "reject-bigint",
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "DEUTDEFF" },
        supplementaryData: { amount: 1n },
        creationDateTime: FIXED_CREATION,
      }),
    /must not contain BigInt/,
  );

  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr",
        amount: { currency: "USD", value: "2.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        supplementaryData: cyclic,
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /must not contain circular references/,
  );
});

test("supplementary data emits ValidationError metadata when unsupported", () => {
  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "invalid-supplementary",
        amount: { currency: "USD", value: "5.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: FIXED_CREATION,
        supplementaryData: { amount: 1n },
      }),
    (error) => {
      assert.ok(error instanceof ValidationError);
      assert.equal(error.code, ValidationErrorCode.INVALID_JSON_VALUE);
      assert.equal(error.path, "supplementaryData");
      return true;
    },
  );
});

test("ISO messages enforce Max35Text on identifier fields", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "x".repeat(36),
        instructionId: "instr-008",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "COBADEFF" },
        creationDateTime: FIXED_CREATION,
      }),
    /messageId must be ≤ 35 characters/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg-009",
        businessMessageId: "b".repeat(36),
        instructionId: "instr-009",
        amount: { currency: "USD", value: "1.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /businessMessageId must be ≤ 35 characters/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg-009",
        instructionId: "y".repeat(40),
        amount: { currency: "USD", value: "1.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /instructionId must be ≤ 35 characters/,
  );
});

test("invalid agent identifiers raise errors", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg",
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "INVALID" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: FIXED_CREATION,
      }),
    /valid BIC/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "DEUTDEFF" },
        purposeCode: "invalid-purpose-code",
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /purposeCode/,
  );
});

test("party metadata validation rejects malformed inputs", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg",
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "DEUTDEFF" },
        debtor: { name: "", identifier: "abc" },
        creationDateTime: FIXED_CREATION,
      }),
    /debtor.name must be a non-empty string/,
  );

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg",
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "DEUTDEFF" },
        creditor: { name: "Receiver Bank", lei: "INVALID-LEI" },
        creationDateTime: FIXED_CREATION,
      }),
    /creditor\.lei must be a valid LEI/,
  );

  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg",
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "DEUTDEFF" },
        debtor: {
          name: "Entity",
          identifier: "foo",
          identifierScheme: "X".repeat(36),
        },
        creationDateTime: FIXED_CREATION,
      }),
    /identifierScheme must be ≤ 35 characters/,
  );
});

test("LEI checksum validation rejects invalid check digits", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg",
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF", lei: "529900ODI3047E2LIV00" },
        instructedAgent: { bic: "DEUTDEFF" },
        creationDateTime: FIXED_CREATION,
      }),
    /mod-97/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr",
        amount: { currency: "USD", value: "2.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        debtor: { name: "Primary Clearing Bank", lei: "529900ODI3047E2LIV00" },
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /mod-97/,
  );
});

test("IBAN checksum validation rejects invalid accounts", () => {
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg",
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "DEUTDEFF" },
        debtorAccount: { iban: "GB00WEST12345698765432" },
        creationDateTime: FIXED_CREATION,
      }),
    /mod-97/,
  );
});

test("account otherId and party identifiers enforce Max35Text", () => {
  const longId = "X".repeat(36);
  assert.throws(
    () =>
      buildPacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageId: "msg",
        instructionId: "instr",
        amount: { currency: "EUR", value: "1.00" },
        instigatingAgent: { bic: "DEUTDEFF" },
        instructedAgent: { bic: "DEUTDEFF" },
        debtorAccount: { otherId: longId },
        creationDateTime: FIXED_CREATION,
      }),
    /debtorAccount\.otherId must be ≤ 35 characters/,
  );

  assert.throws(
    () =>
      buildPacs009Message({
        ...ISO_PAYMENT_INTENT,
        instructionId: "instr",
        amount: { currency: "USD", value: "2.00" },
        instigatingAgent: { bic: "BOFAUS3N" },
        instructedAgent: { bic: "DEUTDEFF" },
        creditor: { name: "Receiver", identifier: longId },
        creationDateTime: "2026-02-01T00:00:00Z",
      }),
    /creditor\.identifier must be ≤ 35 characters/,
  );
});

test("buildSamplePacs008Message emits schema-compliant demo payload", () => {
  const xml = buildSamplePacs008Message({
    ...ISO_PAYMENT_INTENT,
    messageSuffix: "demo",
    creationDateTime: "2026-01-26T12:00:00Z",
  });

  assert.match(xml, /<MsgId>sample-demo<\/MsgId>/);
  assert.match(xml, /<CreDtTm>2026-01-26T12:00:00\.000Z<\/CreDtTm>/);
  assert.match(xml, /<IntrBkSttlmDt>2026-01-27<\/IntrBkSttlmDt>/);
  assert.match(xml, /<InstgAgt><FinInstnId><BICFI>DEUTDEFF<\/BICFI><\/FinInstnId><\/InstgAgt>/);
  assert.match(xml, /<InstdAgt><FinInstnId><BICFI>COBADEFF<\/BICFI><\/FinInstnId><\/InstdAgt>/);
  assert.match(xml, /<DbtrAgt><FinInstnId><BICFI>DEUTDEFF500<\/BICFI><\/FinInstnId><\/DbtrAgt>/);
  assert.match(xml, /<CdtrAgt><FinInstnId><BICFI>COBADEFF500<\/BICFI><\/FinInstnId><\/CdtrAgt>/);
  assert.match(xml, /<DbtrAcct><Id><IBAN>DE89370400440532013000<\/IBAN><\/Id><\/DbtrAcct>/);
  assert.match(xml, /<CdtrAcct><Id><IBAN>FR7630006000011234567890189<\/IBAN><\/Id><\/CdtrAcct>/);
  assert.match(xml, /<Purp><Cd>SECU<\/Cd><\/Purp>/);
});

test("buildSamplePacs009Message includes agents, purpose code, and demo metadata", () => {
  const xml = buildSamplePacs009Message({
    ...ISO_PAYMENT_INTENT,
    messageSuffix: "demo",
    creationDateTime: "2026-01-26T12:00:00Z",
  });

  assert.match(xml, /<MsgId>sample-demo-msg<\/MsgId>/);
  assert.match(xml, /<BizMsgIdr>sample-demo-biz<\/BizMsgIdr>/);
  assert.match(xml, /<CreDtTm>2026-01-26T12:00:00\.000Z<\/CreDtTm>/);
  assert.match(xml, /<IntrBkSttlmDt>2026-01-27<\/IntrBkSttlmDt>/);
  assert.match(xml, /<InstgAgt><FinInstnId><BICFI>BOFAUS3N<\/BICFI><\/FinInstnId><\/InstgAgt>/);
  assert.match(xml, /<InstdAgt><FinInstnId><BICFI>DEUTDEFF<\/BICFI><\/FinInstnId><\/InstdAgt>/);
  assert.match(xml, /<DbtrAgt><FinInstnId><BICFI>BOFAUS3NXXX<\/BICFI><\/FinInstnId><\/DbtrAgt>/);
  assert.match(xml, /<CdtrAgt><FinInstnId><BICFI>DEUTDEFF500<\/BICFI><\/FinInstnId><\/CdtrAgt>/);
  assert.match(xml, /<Purp><Cd>SECU<\/Cd><\/Purp>/);
  assert.match(
    xml,
    /demo pacs\.009 Global payment/,
    "supplementary metadata note should appear in demo payload",
  );
});

test("sample ISO message builders reject unsupported options", () => {
  assert.throws(
    () =>
      buildSamplePacs008Message({
        ...ISO_PAYMENT_INTENT,
        messageSuffix: "demo",
        extra: true,
      }),
    /buildSamplePacs008Message options\.extra is not supported/,
  );

  assert.throws(
    () =>
      buildSamplePacs009Message({
        ...ISO_PAYMENT_INTENT,
        creationDateTime: new Date(),
        settlementDate: "2026-01-27",
        unexpected: "value",
      }),
    /buildSamplePacs009Message options\.unexpected is not supported/,
  );
});

test("buildCamt052Message renders account reports", () => {
  const xml = buildCamt052Message({
    messageId: "camt052-001",
    creationDateTime: "2026-02-01T00:00:00Z",
    reportId: "camt052-report",
    pagination: { pageNumber: 1, lastPage: true },
    account: { otherId: "ledger-account" },
    accountCurrency: "USD",
    balances: [
      {
        typeCode: "ITBD",
        amount: { currency: "USD", value: "100.00" },
        creditDebitIndicator: "CRDT",
        asOfDateTime: "2026-02-01T00:00:00Z",
      },
    ],
    entries: [
      {
        amount: { currency: "USD", value: "10.00" },
        creditDebitIndicator: "DBIT",
        status: "BOOK",
        bookingDate: "2026-02-01",
        valueDate: "2026-02-01",
        reference: "acct-ref-001",
      },
    ],
    summary: {
      entryCount: 1,
      sum: "10.00",
      netAmount: "10.00",
      netCreditDebitIndicator: "DBIT",
    },
  });
  assert.match(xml, /<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt\.052\.001\.08">/);
  assert.match(xml, /<RptPgntn>/);
  assert.match(xml, /<Acct><Id><Othr><Id>ledger-account<\/Id><\/Othr><\/Id><\/Acct>/);
  assert.match(xml, /<Bal>[\s\S]*<CdtDbtInd>CRDT<\/CdtDbtInd>[\s\S]*<\/Bal>/);
  assert.match(xml, /<Ntry>[\s\S]*acct-ref-001[\s\S]*<\/Ntry>/);
  assert.match(xml, /<TxsSummry>/);
});

test("buildCamt052Message rejects non-integer pagination and sequence values", () => {
  const base = {
    messageId: "camt052-invalid",
    creationDateTime: "2026-02-01T00:00:00Z",
    reportId: "camt052-invalid-report",
    account: { otherId: "ledger-account" },
  };

  assert.throws(
    () =>
      buildCamt052Message({
        ...base,
        pagination: { pageNumber: "1.5", lastPage: true },
      }),
    /pagination\.pageNumber must be a positive integer/,
  );

  assert.throws(
    () =>
      buildCamt052Message({
        ...base,
        sequenceNumber: "12abc",
      }),
    /sequenceNumber must be a positive integer/,
  );
});

test("buildCamt052Message enforces chronological report ranges", () => {
  assert.throws(
    () =>
      buildCamt052Message({
        messageId: "camt052-chronology",
        creationDateTime: "2026-02-01T00:00:00Z",
        reportId: "chronology-report",
        fromDateTime: "2026-02-02T00:00:00Z",
        toDateTime: "2026-02-01T00:00:00Z",
        account: { iban: "DE89370400440532013000" },
      }),
    (error) => {
      assert.equal(error.code, ValidationErrorCode.VALUE_OUT_OF_RANGE);
      assert.equal(error.path, "fromDateTime");
      assert.match(error.message, /fromDateTime must be on or before toDateTime/);
      return true;
    },
  );
});

test("buildCamt052Message validates credit/debit indicators", () => {
  assert.throws(
    () =>
      buildCamt052Message({
        messageId: "bad-camt052",
        creationDateTime: "2026-02-01T00:00:00Z",
        reportId: "bad",
        account: { iban: "DE89370400440532013000" },
        balances: [
          {
            amount: { currency: "EUR", value: "1.00" },
            creditDebitIndicator: "invalid",
          },
        ],
      }),
    /creditDebitIndicator must be CRDT or DBIT/,
  );
});

test("buildCamt056Message renders cancellation requests", () => {
  const xml = buildCamt056Message({
    assignmentId: "cancel-001",
    creationDateTime: "2026-02-01T10:00:00Z",
    cancellationId: "cancel-001-tx",
    assignerAgent: { bic: "ALPHGB2L" },
    assigneeAgent: { bic: "OMEGGB2L" },
    debtorAgent: { bic: "ALPHGB2L" },
    creditorAgent: { bic: "OMEGGB2L" },
    originalMessageId: "pacs008-001",
    originalMessageNameId: "pacs.008.001.08",
    originalInstructionId: "instr-001",
    originalEndToEndId: "e2e-001",
    originalTransactionId: "tx-001",
    originalUetr: "123e4567-e89b-12d3-a456-426614174000",
    interbankSettlementAmount: { currency: "USD", value: "25.00" },
    interbankSettlementDate: "2026-02-01",
    debtor: { name: "Sender" },
    debtorAccount: { iban: "GB33ALPH12345612345678" },
    creditor: { name: "Receiver" },
    creditorAccount: { iban: "GB80OMEG65432187654321" },
    serviceLevelCode: "STANDARD",
    caseId: "case-001",
    caseCreatorName: "ALPHBANK",
  });
  assert.match(xml, /<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt\.056\.001\.08">/);
  assert.match(xml, /<Assgnmt>[\s\S]*<Id>cancel-001<\/Id>[\s\S]*<\/Assgnmt>/);
  assert.match(xml, /<OrgnlMsgId>pacs008-001<\/OrgnlMsgId>/);
  assert.match(xml, /<OrgnlTxRef>[\s\S]*<IntrBkSttlmAmt Ccy="USD">25\.00<\/IntrBkSttlmAmt>/);
  assert.match(xml, /<Case>[\s\S]*<Id>case-001<\/Id>[\s\S]*ALPHBANK[\s\S]*<\/Case>/);
});

test("sample camt builders emit demo payloads", () => {
  assert.match(buildSampleCamt052Message(), /camt\.052/);
  assert.match(buildSampleCamt056Message(), /camt\.056/);
});

for (const builder of [buildPacs008Message, buildPacs009Message]) {
  test(`${builder.name} retains native intent across different gateway envelopes`, () => {
    const fields = {
      ...ISO_PAYMENT_INTENT,
      messageId: "gateway-a",
      instructionId: "payer-instruction",
      creationDateTime: FIXED_CREATION,
      amount: { currency: "EUR", value: "25.00" },
      instigatingAgent: { bic: "DEUTDEFF" },
      instructedAgent: { bic: "COBADEFF" },
      supplementaryData: { memo: "unrelated <metadata>" },
    };
    const first = builder(fields);
    const second = builder({ ...fields, messageId: "gateway-b", transactionId: "carrier-b" });
    for (const xml of [first, second]) {
      assert.ok(xml.includes(`<UETR>${fields.uetr}</UETR>`));
      assert.match(xml, /<\/CdtTrfTxInf>\s*<SplmtryData><Envlp><nx:NexusSettlement xmlns:nx="urn:iroha:iso20022:nexus:v1">/u);
      for (const [field, value] of Object.entries(fields.nexusSettlement)) {
        const tag = field[0].toUpperCase() + field.slice(1);
        assert.ok(xml.includes(`<nx:${tag}>${value}</nx:${tag}>`), tag);
      }
      assert.ok(xml.includes("&quot;memo&quot;:&quot;unrelated &lt;metadata&gt;&quot;"));
    }
    assert.equal(
      first.match(/<nx:NexusSettlement[^]*?<\/nx:NexusSettlement>/u)[0],
      second.match(/<nx:NexusSettlement[^]*?<\/nx:NexusSettlement>/u)[0],
    );
  });
}

const NATIVE_BUILDER_FIELDS = {
  ...ISO_PAYMENT_INTENT,
  messageId: "native-controls",
  instructionId: "payer-controls",
  creationDateTime: FIXED_CREATION,
  amount: { currency: "EUR", value: "1.00" },
  instigatingAgent: { bic: "DEUTDEFF" },
  instructedAgent: { bic: "COBADEFF" },
};

for (const builder of [buildPacs008Message, buildPacs009Message]) {
  test(`${builder.name} rejects missing or malformed native intent before address admission`, () => {
    for (const uetr of [undefined, null, "", "random-gateway-id", " " + ISO_PAYMENT_INTENT.uetr, "0".repeat(37)]) {
      assert.throws(() => builder({ ...NATIVE_BUILDER_FIELDS, uetr }), /uetr/u);
    }
    for (const nexusSettlement of [undefined, null, [], Object.assign([], ISO_PAYMENT_INTENT.nexusSettlement), {}]) {
      assert.throws(() => builder({ ...NATIVE_BUILDER_FIELDS, nexusSettlement }), /nexusSettlement/u);
    }
    for (const field of Object.keys(ISO_PAYMENT_INTENT.nexusSettlement)) {
      const terms = { ...ISO_PAYMENT_INTENT.nexusSettlement };
      delete terms[field];
      assert.throws(() => builder({ ...NATIVE_BUILDER_FIELDS, nexusSettlement: terms }), new RegExp(field, "u"));
    }
    const invalidTerms = [
      { unknown: "not a term" },
      { networkId: ISO_PAYMENT_INTENT.nexusSettlement.networkId.toString() },
      { networkId: { toString: () => ISO_PAYMENT_INTENT.nexusSettlement.networkId.toString() } },
      ...[0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, "01", "+1", "1e3", " 1", "1 ", "1".repeat(21), "18446744073709551616", false, {}]
        .map((expiresAtHeight) => ({ expiresAtHeight })),
      { assetDefinitionId: "usd#wonderland" },
      { assetDefinitionId: " " + ISO_PAYMENT_INTENT.nexusSettlement.assetDefinitionId },
      { assetDefinitionId: ISO_PAYMENT_INTENT.nexusSettlement.assetDefinitionId + "1" },
      { sourceAccountId: " " + ISO_PAYMENT_INTENT.nexusSettlement.sourceAccountId },
    ];
    for (const invalid of invalidTerms) {
      assert.throws(() => builder({
        ...NATIVE_BUILDER_FIELDS,
        nexusSettlement: { ...ISO_PAYMENT_INTENT.nexusSettlement, ...invalid },
      }), TypeError, Object.keys(invalid).join(","));
    }
  });

  test(`${builder.name} preserves exact maximum expiry and canonical UETR`, () => {
    for (const expiresAtHeight of [1, "1", 1n, "18446744073709551615", 18_446_744_073_709_551_615n]) {
      const xml = builder({
        ...NATIVE_BUILDER_FIELDS,
        uetr: ISO_PAYMENT_INTENT.uetr.toUpperCase(),
        nexusSettlement: { ...ISO_PAYMENT_INTENT.nexusSettlement, expiresAtHeight },
      });
      assert.ok(xml.includes(`<UETR>${ISO_PAYMENT_INTENT.uetr}</UETR>`));
      assert.ok(xml.includes(`<nx:ExpiresAtHeight>${expiresAtHeight}</nx:ExpiresAtHeight>`));
    }
  });

  test(`${builder.name} refuses aliases and corrupted canonical accounts`, () => {
    for (const field of ["sourceAccountId", "targetAccountId"]) {
      for (const value of ["payer@bank.sora", "0x001122", ISO_PAYMENT_INTENT.nexusSettlement[field].slice(0, -1) + "!"]) {
        assert.throws(() => builder({
          ...NATIVE_BUILDER_FIELDS,
          nexusSettlement: { ...ISO_PAYMENT_INTENT.nexusSettlement, [field]: value },
        }), (error) => {
          assert.ok(error instanceof ValidationError);
          assert.equal(error.code, ValidationErrorCode.INVALID_ACCOUNT_ID);
          assert.equal(error.path, `nexusSettlement.${field}`);
          return true;
        });
      }
    }
  });
}

test("payment sample builders require caller-retained intent", () => {
  for (const builder of [buildSamplePacs008Message, buildSamplePacs009Message]) {
    assert.throws(() => builder(), /options/u);
    assert.throws(() => builder({ messageSuffix: "envelope-only" }), /uetr/u);
  }
});
