import { AccountAddress, AccountAddressError } from "./address.js";
import { networkIdBytes } from "./networkId.js";
import { normalizeAssetDefinitionId } from "./normalizers.js";
import { normalizeIban } from "./identifiers.js";
import { createValidationError, ValidationErrorCode } from "./validationError.js";

const ISO20022_XSD_NAMESPACE_PREFIX = "urn:iso:std:iso:20022:tech:xsd:";
const DEFAULT_PACS009_MESSAGE_DEFINITION_ID = "pacs.009.001.08";
const PACS008_NAMESPACE = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08";
const CAMT052_NAMESPACE = "urn:iso:std:iso:20022:tech:xsd:camt.052.001.08";
const CAMT056_NAMESPACE = "urn:iso:std:iso:20022:tech:xsd:camt.056.001.08";

const CURRENCY_REGEX = /^[A-Z]{3}$/;
const BIC_REGEX = /^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/;
const LEI_REGEX = /^[A-Z0-9]{18}[0-9]{2}$/;
const PURPOSE_REGEX = /^[A-Z0-9]{3,8}$/;
const AMOUNT_REGEX = /^\d+(\.\d+)?$/;
const DATETIME_WITH_TZ_REGEX =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/i;
const PACS009_MESSAGE_DEFINITION_REGEX = /^pacs\.009\.\d{3}\.\d{2}$/;
const CURRENCY_MINOR_UNITS = {
  // Zero-decimal ISO 4217 currencies
  BIF: 0,
  CLP: 0,
  DJF: 0,
  GNF: 0,
  JPY: 0,
  KMF: 0,
  KRW: 0,
  PYG: 0,
  RWF: 0,
  UGX: 0,
  VND: 0,
  VUV: 0,
  XAF: 0,
  XOF: 0,
  XPF: 0,
  // Three-decimal ISO 4217 currencies
  BHD: 3,
  IQD: 3,
  JOD: 3,
  KWD: 3,
  LYD: 3,
  OMR: 3,
  TND: 3,
  // Four-decimal ISO 4217 currencies
  CLF: 4,
  UYW: 4,
};

function fail(code, message, path, cause) {
  throw createValidationError(code, message, path, cause);
}

/**
 * Build a minimal ISO 20022 pacs.008 document from structured fields.
 * @param {import("./index").BuildPacs008Options} options
 * @returns {string} XML payload
 */
export function buildPacs008Message(options) {
  const opts = requireObject(options, "options");
  const messageId = requireMax35Text(opts.messageId, "messageId");
  const instructionId = requireMax35Text(opts.instructionId, "instructionId");
  const endToEndId = opts.endToEndId
    ? requireMax35Text(opts.endToEndId, "endToEndId")
    : undefined;
  const transactionId = opts.transactionId
    ? requireMax35Text(opts.transactionId, "transactionId")
    : undefined;
  const groupHeader = buildGroupHeader({
    messageId,
    creationDateTime: requireCreationDateTime(opts.creationDateTime, "creationDateTime"),
  });
  const paymentIds = buildPaymentIds({
    instructionId,
    endToEndId,
    transactionId,
    uetr: requireUetr(opts.uetr),
  });
  const amount = encodeAmount(opts.amount, "amount");
  const settlementDate = opts.settlementDate
      ? `<IntrBkSttlmDt>${normalizeDate(opts.settlementDate, "settlementDate")}</IntrBkSttlmDt>`
      : "";
  const instgAgent = renderAgent("InstgAgt", requireAgent(opts.instigatingAgent, "instigatingAgent"));
  const instdAgent = renderAgent("InstdAgt", requireAgent(opts.instructedAgent, "instructedAgent"));
  const debtorAgent = opts.debtorAgent
    ? renderAgent("DbtrAgt", requireAgent(opts.debtorAgent, "debtorAgent"))
    : "";
  const creditorAgent = opts.creditorAgent
    ? renderAgent("CdtrAgt", requireAgent(opts.creditorAgent, "creditorAgent"))
    : "";
  const debtorParty = opts.debtor ? renderParty("Dbtr", requireParty(opts.debtor, "debtor")) : "";
  const creditorParty = opts.creditor
    ? renderParty("Cdtr", requireParty(opts.creditor, "creditor"))
    : "";
  const debtorAccount = opts.debtorAccount
    ? renderAccount("DbtrAcct", requireAccount(opts.debtorAccount, "debtorAccount"))
    : "";
  const creditorAccount = opts.creditorAccount
    ? renderAccount("CdtrAcct", requireAccount(opts.creditorAccount, "creditorAccount"))
    : "";
  const purpose = opts.purposeCode ? renderPurpose(opts.purposeCode) : "";
  const remittance = opts.remittanceInformation
    ? renderRemittanceInformation(opts.remittanceInformation)
    : "";
  const supplementary = opts.supplementaryData
    ? renderSupplementaryData(opts.supplementaryData)
    : "";

  return [
    `<Document xmlns="${PACS008_NAMESPACE}">`,
    "  <FIToFICstmrCdtTrf>",
    `    ${groupHeader}`,
    "    <CdtTrfTxInf>",
    `      ${paymentIds}`,
    `      ${amount}`,
    settlementDate && `      ${settlementDate}`,
    `      ${instgAgent}`,
    `      ${instdAgent}`,
    debtorAgent && `      ${debtorAgent}`,
    creditorAgent && `      ${creditorAgent}`,
    debtorParty && `      ${debtorParty}`,
    debtorAccount && `      ${debtorAccount}`,
    creditorParty && `      ${creditorParty}`,
    creditorAccount && `      ${creditorAccount}`,
    purpose && `      ${purpose}`,
    remittance && `      ${remittance}`,
    supplementary && `      ${supplementary}`,
    "    </CdtTrfTxInf>",
    `    ${renderNexusSettlement(opts.nexusSettlement)}`,
    "  </FIToFICstmrCdtTrf>",
    "</Document>",
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Build a minimal ISO 20022 pacs.009 document from structured fields.
 * @param {import("./index").BuildPacs009Options} options
 * @returns {string} XML payload
 */
export function buildPacs009Message(options) {
  const opts = requireObject(options, "options");
  const headerMessageId = requireMax35Text(
    opts.messageId ?? opts.instructionId,
    "messageId",
  );
  const businessMessageId = requireMax35Text(
    opts.businessMessageId ?? headerMessageId,
    "businessMessageId",
  );
  const messageDefinitionId = requirePacs009MessageDefinitionId(
    opts.messageDefinitionId ?? DEFAULT_PACS009_MESSAGE_DEFINITION_ID,
    "messageDefinitionId",
  );
  const instructionId = requireMax35Text(opts.instructionId, "instructionId");
  const transactionId = opts.transactionId
    ? requireMax35Text(opts.transactionId, "transactionId")
    : undefined;
  const groupHeader = [
    "<GrpHdr>",
    `  <MsgId>${escapeXml(headerMessageId)}</MsgId>`,
    `  <CreDtTm>${requireCreationDateTime(opts.creationDateTime, "creationDateTime")}</CreDtTm>`,
    `  <BizMsgIdr>${escapeXml(businessMessageId)}</BizMsgIdr>`,
    `  <MsgDefIdr>${escapeXml(messageDefinitionId)}</MsgDefIdr>`,
    "</GrpHdr>",
  ].join("");
  const paymentIds = buildPaymentIds({
    instructionId,
    endToEndId: undefined,
    transactionId,
    uetr: requireUetr(opts.uetr),
  });
  const amount = encodeAmount(opts.amount, "amount");
  const settlementDate = opts.settlementDate
    ? `<IntrBkSttlmDt>${normalizeDate(opts.settlementDate, "settlementDate")}</IntrBkSttlmDt>`
    : "";
  const instgAgent = renderAgent("InstgAgt", requireAgent(opts.instigatingAgent, "instigatingAgent"));
  const instdAgent = renderAgent("InstdAgt", requireAgent(opts.instructedAgent, "instructedAgent"));
  const debtorAgent = opts.debtorAgent
    ? renderAgent("DbtrAgt", requireAgent(opts.debtorAgent, "debtorAgent"))
    : "";
  const creditorAgent = opts.creditorAgent
    ? renderAgent("CdtrAgt", requireAgent(opts.creditorAgent, "creditorAgent"))
    : "";
  const debtorParty = opts.debtor ? renderParty("Dbtr", requireParty(opts.debtor, "debtor")) : "";
  const creditorParty = opts.creditor
    ? renderParty("Cdtr", requireParty(opts.creditor, "creditor"))
    : "";
  const debtorAccount = opts.debtorAccount
    ? renderAccount("DbtrAcct", requireAccount(opts.debtorAccount, "debtorAccount"))
    : "";
  const creditorAccount = opts.creditorAccount
    ? renderAccount("CdtrAcct", requireAccount(opts.creditorAccount, "creditorAccount"))
    : "";
  const purpose = renderPurpose(opts.purposeCode ?? "SECU");
  const remittance = opts.remittanceInformation
    ? renderRemittanceInformation(opts.remittanceInformation)
    : "";
  const supplementary = opts.supplementaryData
    ? renderSupplementaryData(opts.supplementaryData)
    : "";

  return [
    `<Document xmlns="${namespaceForMessageDefinitionId(messageDefinitionId)}">`,
    "  <FICdtTrf>",
    `    ${groupHeader}`,
    "    <CdtTrfTxInf>",
    `      ${paymentIds}`,
    `      ${amount}`,
    settlementDate && `      ${settlementDate}`,
    `      ${instgAgent}`,
    `      ${instdAgent}`,
    debtorAgent && `      ${debtorAgent}`,
    creditorAgent && `      ${creditorAgent}`,
    debtorParty && `      ${debtorParty}`,
    debtorAccount && `      ${debtorAccount}`,
    creditorParty && `      ${creditorParty}`,
    creditorAccount && `      ${creditorAccount}`,
    purpose && `      ${purpose}`,
    remittance && `      ${remittance}`,
    supplementary && `      ${supplementary}`,
    "    </CdtTrfTxInf>",
    `    ${renderNexusSettlement(opts.nexusSettlement)}`,
    "  </FICdtTrf>",
    "</Document>",
  ]
    .filter(Boolean)
    .join("\n");
}

function namespaceForMessageDefinitionId(messageDefinitionId) {
  return `${ISO20022_XSD_NAMESPACE_PREFIX}${messageDefinitionId}`;
}

/**
 * Build a schema-compliant pacs.008 demo payload for ISO bridge walkthroughs.
 * @param {import("./index").SamplePacsMessageOptions} options
 * @returns {string}
 */
export function buildSamplePacs008Message(options) {
  const { uetr, nexusSettlement, ...sampleOptions } = requireObject(options, "options");
  const sample = normalizeSampleOptions(sampleOptions, "buildSamplePacs008Message");
  return buildPacs008Message({
    uetr,
    nexusSettlement,
    messageId: `sample-${sample.suffix}`,
    creationDateTime: sample.creationDateTime,
    instructionId: `sample-${sample.suffix}-instr`,
    endToEndId: `sample-${sample.suffix}-e2e`,
    transactionId: `sample-${sample.suffix}-tx`,
    settlementDate: sample.settlementDate,
    amount: { currency: "EUR", value: "10.00" },
    instigatingAgent: { bic: "DEUTDEFF" },
    instructedAgent: { bic: "COBADEFF" },
    debtorAgent: { bic: "DEUTDEFF500" },
    creditorAgent: { bic: "COBADEFF500" },
    debtorAccount: { iban: "DE89370400440532013000" },
    creditorAccount: { iban: "FR7630006000011234567890189" },
    purposeCode: "SECU",
    supplementaryData: {
      note: "demo pacs.008 settlement",
    },
  });
}

/**
 * Build a schema-compliant pacs.009 demo payload for ISO bridge walkthroughs.
 * @param {import("./index").SamplePacsMessageOptions} options
 * @returns {string}
 */
export function buildSamplePacs009Message(options) {
  const { uetr, nexusSettlement, ...sampleOptions } = requireObject(options, "options");
  const sample = normalizeSampleOptions(sampleOptions, "buildSamplePacs009Message");
  return buildPacs009Message({
    uetr,
    nexusSettlement,
    messageId: `sample-${sample.suffix}-msg`,
    businessMessageId: `sample-${sample.suffix}-biz`,
    messageDefinitionId: "pacs.009.001.08",
    creationDateTime: sample.creationDateTime,
    instructionId: `sample-${sample.suffix}-instr`,
    transactionId: `sample-${sample.suffix}-tx`,
    settlementDate: sample.settlementDate,
    amount: { currency: "USD", value: "1000.00" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    debtorAgent: { bic: "BOFAUS3NXXX" },
    creditorAgent: { bic: "DEUTDEFF500" },
    debtorAccount: { iban: "DE89370400440532013000" },
    creditorAccount: { iban: "GB82WEST12345698765432" },
    purposeCode: "SECU",
    supplementaryData: {
      note: "demo pacs.009 Global payment",
    },
  });
}

/**
 * Build a minimal ISO 20022 camt.052 account report from structured fields.
 * @param {import("./index").BuildCamt052Options} options
 * @returns {string}
 */
export function buildCamt052Message(options) {
  const opts = requireObject(options, "options");
  const messageId = requireMax35Text(opts.messageId, "messageId");
  const creationDateTime = requireCreationDateTime(opts.creationDateTime, "creationDateTime");
  const reportId = requireMax35Text(opts.reportId, "reportId");
  const pagination = opts.pagination ? normalizeReportPagination(opts.pagination) : null;
  const sequenceNumber =
    opts.sequenceNumber === undefined || opts.sequenceNumber === null
      ? null
      : requirePositiveInteger(opts.sequenceNumber, "sequenceNumber");
  const range = normalizeReportRange(opts.fromDateTime, opts.toDateTime);
  const account = requireAccount(opts.account ?? {}, "account");
  const accountCurrency = opts.accountCurrency
    ? requireCurrency(opts.accountCurrency, "accountCurrency")
    : null;
  const balances = (opts.balances ?? []).map((entry, index) =>
    renderReportBalance(entry, index),
  );
  const entries = (opts.entries ?? []).map((entry, index) => renderReportEntry(entry, index));
  const summary = opts.summary ? renderReportSummary(opts.summary) : "";

  return [
    `<Document xmlns="${CAMT052_NAMESPACE}">`,
    "  <BkToCstmrAcctRpt>",
    "    <GrpHdr>",
    `      <MsgId>${escapeXml(messageId)}</MsgId>`,
    `      <CreDtTm>${creationDateTime}</CreDtTm>`,
    "    </GrpHdr>",
    "    <Rpt>",
    `      <Id>${escapeXml(reportId)}</Id>`,
    pagination,
    sequenceNumber ? `      <ElctrncSeqNb>${sequenceNumber}</ElctrncSeqNb>` : "",
    range,
    indentBlock(renderReportAccount(account, accountCurrency), "    "),
    ...balances.map((block) => indentBlock(block, "    ")),
    ...entries.map((block) => indentBlock(block, "    ")),
    summary ? indentBlock(summary, "    ") : "",
    "    </Rpt>",
    "  </BkToCstmrAcctRpt>",
    "</Document>",
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Build a sample camt.052 account report for documentation/tests.
 * @param {import("./index").SampleCamtMessageOptions} [options]
 * @returns {string}
 */
export function buildSampleCamt052Message(options = {}) {
  const sample = normalizeSampleOptions(options, "buildSampleCamt052Message");
  return buildCamt052Message({
    messageId: `sample-camt052-${sample.suffix}`,
    creationDateTime: sample.creationDateTime,
    reportId: `sample-camt052-${sample.suffix}-rpt`,
    pagination: { pageNumber: 1, lastPage: true },
    sequenceNumber: 1,
    fromDateTime: sample.creationDateTime,
    toDateTime: sample.creationDateTime,
    account: { otherId: "ALPHBANK-USD-ACCOUNT-001" },
    accountCurrency: "USD",
    balances: [
      {
        typeCode: "ITBD",
        amount: { currency: "USD", value: "100.00" },
        creditDebitIndicator: "CRDT",
        asOfDateTime: sample.creationDateTime,
      },
    ],
    entries: [
      {
        amount: { currency: "USD", value: "10.00" },
        creditDebitIndicator: "DBIT",
        status: "BOOK",
        bookingDate: sample.settlementDate,
        valueDate: sample.settlementDate,
        reference: "sample-entry-001",
      },
      {
        amount: { currency: "USD", value: "20.00" },
        creditDebitIndicator: "CRDT",
        status: "BOOK",
        bookingDate: sample.settlementDate,
        valueDate: sample.settlementDate,
        reference: "sample-entry-002",
      },
    ],
    summary: {
      entryCount: 2,
      sum: "30.00",
      netAmount: "10.00",
      netCreditDebitIndicator: "CRDT",
    },
  });
}

/**
 * Build a minimal ISO 20022 camt.056 cancellation request from structured fields.
 * @param {import("./index").BuildCamt056Options} options
 * @returns {string}
 */
export function buildCamt056Message(options) {
  const opts = requireObject(options, "options");
  const assignmentId = requireMax35Text(opts.assignmentId, "assignmentId");
  const creationDateTime = requireCreationDateTime(opts.creationDateTime, "creationDateTime");
  const cancellationId = requireMax35Text(opts.cancellationId, "cancellationId");
  const assignerAgent = requireAgent(opts.assignerAgent, "assignerAgent");
  const assigneeAgent = requireAgent(opts.assigneeAgent, "assigneeAgent");
  const debtorAgent = requireAgent(opts.debtorAgent, "debtorAgent");
  const creditorAgent = requireAgent(opts.creditorAgent, "creditorAgent");
  const originalMessageId = requireMax35Text(opts.originalMessageId, "originalMessageId");
  const originalMessageNameId = requireMax35Text(
    opts.originalMessageNameId,
    "originalMessageNameId",
  );
  const originalInstructionId = opts.originalInstructionId
    ? requireMax35Text(opts.originalInstructionId, "originalInstructionId")
    : null;
  const originalEndToEndId = opts.originalEndToEndId
    ? requireMax35Text(opts.originalEndToEndId, "originalEndToEndId")
    : null;
  const originalTransactionId = opts.originalTransactionId
    ? requireMax35Text(opts.originalTransactionId, "originalTransactionId")
    : null;
  const originalUetr = opts.originalUetr
    ? requireId(opts.originalUetr, "originalUetr")
    : null;
  const serviceLevel = opts.serviceLevelCode
    ? renderServiceLevel(opts.serviceLevelCode)
    : "";
  const amount = renderCurrencyAmountElement(
    "IntrBkSttlmAmt",
    opts.interbankSettlementAmount,
    "interbankSettlementAmount",
  );
  const settlementDate = normalizeDate(
    opts.interbankSettlementDate,
    "interbankSettlementDate",
  );
  const debtorParty = opts.debtor ? renderParty("Dbtr", requireParty(opts.debtor, "debtor")) : "";
  const debtorAccount = opts.debtorAccount
    ? renderAccount("DbtrAcct", requireAccount(opts.debtorAccount, "debtorAccount"))
    : "";
  const creditorParty = opts.creditor
    ? renderParty("Cdtr", requireParty(opts.creditor, "creditor"))
    : "";
  const creditorAccount = opts.creditorAccount
    ? renderAccount("CdtrAcct", requireAccount(opts.creditorAccount, "creditorAccount"))
    : "";
  const caseSection = renderOptionalCase(opts.caseId, opts.caseCreatorName);

  return [
    `<Document xmlns="${CAMT056_NAMESPACE}">`,
    "  <FIToFIPmtCxlReq>",
    "    <Assgnmt>",
    `      <Id>${escapeXml(assignmentId)}</Id>`,
    `      ${renderAgent("Assgnr", assignerAgent)}`,
    `      ${renderAgent("Assgne", assigneeAgent)}`,
    `      <CreDtTm>${creationDateTime}</CreDtTm>`,
    "    </Assgnmt>",
    "    <Undrlyg>",
    "      <TxInf>",
    `        <CxlId>${escapeXml(cancellationId)}</CxlId>`,
    caseSection,
    "        <OrgnlGrpInf>",
    `          <OrgnlMsgId>${escapeXml(originalMessageId)}</OrgnlMsgId>`,
    `          <OrgnlMsgNmId>${escapeXml(originalMessageNameId)}</OrgnlMsgNmId>`,
    "        </OrgnlGrpInf>",
    originalInstructionId ? `        <OrgnlInstrId>${escapeXml(originalInstructionId)}</OrgnlInstrId>` : "",
    originalEndToEndId ? `        <OrgnlEndToEndId>${escapeXml(originalEndToEndId)}</OrgnlEndToEndId>` : "",
    originalTransactionId
      ? `        <OrgnlTxId>${escapeXml(originalTransactionId)}</OrgnlTxId>`
      : "",
    originalUetr ? `        <OrgnlUETR>${escapeXml(originalUetr)}</OrgnlUETR>` : "",
    "        <OrgnlTxRef>",
    serviceLevel,
    `          ${amount}`,
    `          <IntrBkSttlmDt>${settlementDate}</IntrBkSttlmDt>`,
    `          ${renderAgent("DbtrAgt", debtorAgent)}`,
    debtorParty ? `          ${debtorParty}` : "",
    debtorAccount ? `          ${debtorAccount}` : "",
    `          ${renderAgent("CdtrAgt", creditorAgent)}`,
    creditorParty ? `          ${creditorParty}` : "",
    creditorAccount ? `          ${creditorAccount}` : "",
    "        </OrgnlTxRef>",
    "      </TxInf>",
    "    </Undrlyg>",
    "  </FIToFIPmtCxlReq>",
    "</Document>",
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Build a sample camt.056 cancellation request.
 * @param {import("./index").SampleCamtMessageOptions} [options]
 * @returns {string}
 */
export function buildSampleCamt056Message(options = {}) {
  const sample = normalizeSampleOptions(options, "buildSampleCamt056Message");
  return buildCamt056Message({
    assignmentId: `sample-camt056-${sample.suffix}-asg`,
    creationDateTime: sample.creationDateTime,
    cancellationId: `sample-camt056-${sample.suffix}-cxl`,
    assignerAgent: { bic: "ALPHGB2L" },
    assigneeAgent: { bic: "OMEGGB2L" },
    debtorAgent: { bic: "ALPHGB2L" },
    creditorAgent: { bic: "OMEGGB2L" },
    debtor: { name: "ALPHBANK CUSTOMER" },
    debtorAccount: { iban: "GB33ALPH12345612345678" },
    creditor: { name: "OMEGBANK CUSTOMER" },
    creditorAccount: { iban: "GB80OMEG65432187654321" },
    originalMessageId: `sample-camt056-${sample.suffix}-orig`,
    originalMessageNameId: "pacs.008.001.08",
    originalInstructionId: `sample-camt056-${sample.suffix}-instr`,
    originalEndToEndId: `sample-camt056-${sample.suffix}-e2e`,
    originalTransactionId: `sample-camt056-${sample.suffix}-tx`,
    originalUetr: "123e4567-e89b-12d3-a456-426614174000",
    serviceLevelCode: "STANDARD",
    interbankSettlementAmount: { currency: "USD", value: "25.00" },
    interbankSettlementDate: sample.settlementDate,
    caseId: `sample-case-${sample.suffix}`,
    caseCreatorName: "ALPHBANK",
  });
}

function requireObject(value, label) {
  if (value == null || typeof value !== "object") {
    fail(ValidationErrorCode.INVALID_OBJECT, `${label} must be an object`, label);
  }
  return value;
}

function requireId(value, label) {
  const text = typeof value === "string" ? value.trim() : "";
  if (!text) {
    fail(ValidationErrorCode.INVALID_STRING, `${label} must be a non-empty string`, label);
  }
  return text;
}

function requireCreationDateTime(value, label) {
  if (value === undefined || value === null) {
    fail(ValidationErrorCode.INVALID_STRING, `${label} is required`, label);
  }
  return normalizeDateTime(value, label);
}

function normalizeDateTime(value, label) {
  if (value == null) {
    return new Date().toISOString();
  }
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      fail(ValidationErrorCode.INVALID_STRING, `${label} Date is invalid`, label);
    }
    return value.toISOString();
  }
  const text = requireId(value, label);
  if (!DATETIME_WITH_TZ_REGEX.test(text)) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${label} must be an ISO-8601 datetime string with timezone offset`,
      label,
    );
  }
  const parsed = Date.parse(text);
  if (Number.isNaN(parsed)) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${label} must be an ISO-8601 datetime string with timezone offset`,
      label,
    );
  }
  return new Date(parsed).toISOString();
}

function normalizeDate(value, label) {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      fail(ValidationErrorCode.INVALID_STRING, `${label} Date is invalid`, label);
    }
    return value.toISOString().slice(0, 10);
  }
  const text = requireId(value, label);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) {
    fail(ValidationErrorCode.INVALID_STRING, `${label} must use YYYY-MM-DD format`, label);
  }
  const parsed = new Date(`${text}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime()) || toIsoDate(parsed) !== text) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${label} must be a valid calendar date in YYYY-MM-DD format`,
      label,
    );
  }
  return text;
}

function normalizeSampleOptions(options, context) {
  if (options !== undefined && (options === null || typeof options !== "object")) {
    fail(ValidationErrorCode.INVALID_OBJECT, `${context} options must be an object`, context);
  }
  const resolved = options ?? {};
  const allowedKeys = new Set(["messageSuffix", "creationDateTime", "settlementDate"]);
  for (const key of Object.keys(resolved)) {
    if (!allowedKeys.has(key)) {
      fail(
        ValidationErrorCode.INVALID_OBJECT,
        `${context} options.${key} is not supported`,
        `${context}.options.${key}`,
      );
    }
  }
  const suffix = resolved.messageSuffix ?? Math.floor(Date.now() / 1000).toString(16);
  const normalizedSuffix = requireId(String(suffix), `${context}.messageSuffix`);
  const creationDateTime = normalizeDateTime(
    resolved.creationDateTime ?? new Date(),
    `${context}.creationDateTime`,
  );
  const creationDate = new Date(creationDateTime);
  const settlementDate =
    resolved.settlementDate !== undefined && resolved.settlementDate !== null
      ? normalizeDate(resolved.settlementDate, `${context}.settlementDate`)
      : toIsoDate(addDays(creationDate, 1));
  return {
    suffix: normalizedSuffix,
    creationDateTime,
    settlementDate,
  };
}

function normalizeRemittanceInformation(value, label) {
  if (value === undefined || value === null) {
    return null;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `${label} must not be empty`, label);
    }
    return value.map((entry, index) =>
      normalizeRemittanceLine(entry, `${label}[${index}]`),
    );
  }
  return [normalizeRemittanceLine(value, label)];
}

function normalizeRemittanceLine(value, label) {
  const text = requireId(value, label);
  if (text.length > 140) {
    fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `${label} must be <= 140 characters`, label);
  }
  return text;
}

function normalizeLei(value, label) {
  const text = requireId(value, label).toUpperCase();
  if (!LEI_REGEX.test(text)) {
    fail(ValidationErrorCode.INVALID_STRING, `${label} must be a valid LEI`, label);
  }
  if (!leiHasValidChecksum(text)) {
    fail(ValidationErrorCode.INVALID_STRING, `${label} failed the LEI mod-97 check`, label);
  }
  return text;
}

function leiHasValidChecksum(lei) {
  let remainder = 0;
  for (const ch of lei) {
    const digits =
      ch >= "A" && ch <= "Z"
        ? String(ch.charCodeAt(0) - 55)
        : ch;
    for (const digit of digits) {
      remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

function addDays(date, days) {
  const result = new Date(date.getTime());
  result.setUTCDate(result.getUTCDate() + days);
  return result;
}

function toIsoDate(date) {
  return date.toISOString().slice(0, 10);
}

function buildGroupHeader({ messageId, creationDateTime }) {
  return [
    "<GrpHdr>",
    `  <MsgId>${escapeXml(messageId)}</MsgId>`,
    `  <CreDtTm>${creationDateTime}</CreDtTm>`,
    "</GrpHdr>",
  ].join("");
}

function buildPaymentIds({ instructionId, endToEndId, transactionId, uetr }) {
  const resolvedEndToEnd = endToEndId ?? instructionId;
  const resolvedTransaction = transactionId ?? instructionId;
  return [
    "<PmtId>",
    `  <InstrId>${escapeXml(instructionId)}</InstrId>`,
    resolvedEndToEnd ? `  <EndToEndId>${escapeXml(resolvedEndToEnd)}</EndToEndId>` : "",
    `  <TxId>${escapeXml(resolvedTransaction)}</TxId>`,
    `  <UETR>${uetr}</UETR>`,
    "</PmtId>",
  ]
    .filter(Boolean)
    .join("\n");
}

/** The payer retains this reference; gateway envelope IDs never replace it. */
function requireUetr(value) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/u.test(value)) {
    fail(ValidationErrorCode.INVALID_STRING, "uetr must be an explicit 36-character UUID", "uetr");
  }
  return value.toLowerCase();
}

function requireSettlementExpiry(value) {
  const label = "nexusSettlement.expiresAtHeight";
  if ((typeof value === "number" && !Number.isSafeInteger(value)) ||
      !["string", "number", "bigint"].includes(typeof value)) {
    fail(ValidationErrorCode.INVALID_NUMERIC, `${label} must be an exact positive u64`, label);
  }
  const text = String(value);
  if (!/^[1-9][0-9]{0,19}$/u.test(text) || BigInt(text) > 18_446_744_073_709_551_615n) {
    fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `${label} must be an exact positive u64`, label);
  }
  return text;
}

function requireSettlementAccount(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    fail(ValidationErrorCode.INVALID_ACCOUNT_ID, `${label} must be an exact canonical AccountId`, label);
  }
  try {
    // Rust owns address parsing and checksums. Canonical AccountId display uses
    // the default account prefix; a gateway cannot substitute a routing alias.
    if (AccountAddress.parseEncoded(value).address.toString() !== value) {
      fail(ValidationErrorCode.INVALID_ACCOUNT_ID, `${label} must be an exact canonical AccountId`, label);
    }
  } catch (cause) {
    if (!(cause instanceof AccountAddressError)) throw cause;
    fail(ValidationErrorCode.INVALID_ACCOUNT_ID, `${label} must be an exact canonical AccountId`, label, cause);
  }
  return value;
}

/** Native payment identity and terms have one owned extension, separate from metadata. */
function renderNexusSettlement(value) {
  const label = "nexusSettlement";
  const terms = requireObject(value, label);
  if (Array.isArray(terms)) {
    fail(ValidationErrorCode.INVALID_OBJECT, `${label} must be an object`, label);
  }
  const fields = ["networkId", "expiresAtHeight", "sourceAccountId", "targetAccountId", "assetDefinitionId"];
  for (const field of fields) {
    if (!Object.hasOwn(terms, field) || terms[field] === undefined || terms[field] === null) {
      fail(ValidationErrorCode.INVALID_OBJECT, `${label}.${field} is required`, `${label}.${field}`);
    }
  }
  for (const field of Object.keys(terms)) {
    if (!fields.includes(field)) {
      fail(ValidationErrorCode.INVALID_OBJECT, `${label}.${field} is not supported`, `${label}.${field}`);
    }
  }
  // Closed-world NetworkId validation prevents a duck-typed toString authority.
  networkIdBytes(terms.networkId, `${label}.networkId`);
  const expiry = requireSettlementExpiry(terms.expiresAtHeight);
  const asset = normalizeAssetDefinitionId(terms.assetDefinitionId, `${label}.assetDefinitionId`);
  if (asset !== terms.assetDefinitionId) {
    fail(ValidationErrorCode.INVALID_ASSET_DEFINITION_ID, `${label}.assetDefinitionId must be exact`, `${label}.assetDefinitionId`);
  }
  const source = requireSettlementAccount(terms.sourceAccountId, `${label}.sourceAccountId`);
  const target = requireSettlementAccount(terms.targetAccountId, `${label}.targetAccountId`);
  return [
    '<SplmtryData><Envlp><nx:NexusSettlement xmlns:nx="urn:iroha:iso20022:nexus:v1">',
    `<nx:NetworkId>${escapeXml(terms.networkId.toString())}</nx:NetworkId>`,
    `<nx:ExpiresAtHeight>${expiry}</nx:ExpiresAtHeight>`,
    `<nx:SourceAccountId>${escapeXml(source)}</nx:SourceAccountId>`,
    `<nx:TargetAccountId>${escapeXml(target)}</nx:TargetAccountId>`,
    `<nx:AssetDefinitionId>${escapeXml(asset)}</nx:AssetDefinitionId>`,
    "</nx:NexusSettlement></Envlp></SplmtryData>",
  ].join("");
}

function encodeAmount(amount, label) {
  return renderCurrencyAmountElement("IntrBkSttlmAmt", amount, label);
}

function renderCurrencyAmountElement(elementName, amount, label) {
  const data = requireObject(amount, label);
  const currency = requireCurrency(data.currency, `${label}.currency`);
  const rawValue = data.value ?? data.amount;
  const value = formatAmount(rawValue, `${label}.value`, currencyMinorUnits(currency), currency);
  return `<${elementName} Ccy="${currency}">${value}</${elementName}>`;
}

function requireCurrency(value, label) {
  const text = requireId(value, label).toUpperCase();
  if (!CURRENCY_REGEX.test(text)) {
    fail(ValidationErrorCode.INVALID_STRING, `${label} must be an ISO 4217 code`, label);
  }
  return text;
}

function currencyMinorUnits(currency) {
  return CURRENCY_MINOR_UNITS[currency] ?? 2;
}

function formatAmount(value, label, minorUnits, currency) {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value < 0) {
      fail(ValidationErrorCode.INVALID_NUMERIC, `${label} must be a positive finite number`, label);
    }
    if (minorUnits === 0 && !Number.isInteger(value)) {
      fail(
        ValidationErrorCode.VALUE_OUT_OF_RANGE,
        `${label} must not include fractional digits for ${currency}`,
        label,
      );
    }
    return value.toFixed(minorUnits);
  }
  const text = requireId(String(value), label);
  if (!AMOUNT_REGEX.test(text)) {
    fail(ValidationErrorCode.INVALID_NUMERIC, `${label} must be a positive decimal string`, label);
  }
  const [intPart, rawFrac = ""] = text.split(".");
  if (minorUnits === 0) {
    if (rawFrac.length > 0) {
      fail(
        ValidationErrorCode.VALUE_OUT_OF_RANGE,
        `${label} must not include fractional digits for ${currency}`,
        label,
      );
    }
    return intPart;
  }
  if (rawFrac.length > minorUnits) {
    fail(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${label} must have at most ${minorUnits} decimal places for ${currency}`,
      label,
    );
  }
  const paddedFrac = rawFrac.padEnd(minorUnits, "0");
  return `${intPart}.${paddedFrac}`;
}

function requireAgent(value, label) {
  const agent = requireObject(value, label);
  const bic = requireId(agent.bic, `${label}.bic`).toUpperCase();
  if (!BIC_REGEX.test(bic)) {
    fail(ValidationErrorCode.INVALID_STRING, `${label}.bic must be a valid BIC`, `${label}.bic`);
  }
  let lei;
  if (agent.lei) {
    lei = normalizeLei(agent.lei, `${label}.lei`);
  }
  return { bic, lei };
}

function renderAgent(elementName, agent) {
  const leiFragment = agent.lei
    ? `<Othr><Id>${escapeXml(agent.lei)}</Id><SchmeNm><Prtry>LEI</Prtry></SchmeNm></Othr>`
    : "";
  return `<${elementName}><FinInstnId><BICFI>${escapeXml(
    agent.bic,
  )}</BICFI>${leiFragment}</FinInstnId></${elementName}>`;
}

function normalizeProxy(value, label) {
  const proxy = requireObject(value, label);
  const id = requireId(proxy.id ?? proxy.identifier, `${label}.id`);
  if (id.length > 2048) {
    fail(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${label}.id must be at most 2048 characters`,
      `${label}.id`,
    );
  }
  const typeCode = proxy.typeCode ?? proxy.type;
  const proprietary = proxy.typeProprietary ?? proxy.proprietaryType;
  if (typeCode && proprietary) {
    fail(
      ValidationErrorCode.INVALID_OBJECT,
      `${label} must not set both typeCode and typeProprietary`,
      label,
    );
  }
  let normalizedTypeCode;
  if (typeCode != null) {
    normalizedTypeCode = requireId(typeCode, `${label}.typeCode`).toUpperCase();
    if (!/^[A-Z0-9]{1,4}$/.test(normalizedTypeCode)) {
      fail(
        ValidationErrorCode.INVALID_STRING,
        `${label}.typeCode must be 1-4 uppercase letters or digits`,
        `${label}.typeCode`,
      );
    }
  }
  let normalizedProprietary;
  if (proprietary != null) {
    normalizedProprietary = requireMax35Text(proprietary, `${label}.typeProprietary`);
  }
  return {
    id,
    typeCode: normalizedTypeCode,
    typeProprietary: normalizedProprietary,
  };
}

function requireAccount(value, label) {
  const account = requireObject(value, label);
  const proxy = account.proxy ? normalizeProxy(account.proxy, `${label}.proxy`) : null;
  if (account.iban) {
    const iban = normalizeIban(account.iban, `${label}.iban`);
    return { iban, proxy };
  }
  if (account.otherId) {
    const other = requireMax35Text(account.otherId, `${label}.otherId`);
    if (proxy) {
      fail(
        ValidationErrorCode.INVALID_OBJECT,
        `${label}.proxy requires iban alongside proxy identifiers`,
        `${label}.proxy`,
      );
    }
    return { otherId: other };
  }
  if (proxy) {
    fail(
      ValidationErrorCode.INVALID_OBJECT,
      `${label}.proxy requires iban alongside proxy identifiers`,
      `${label}.proxy`,
    );
  }
  fail(
    ValidationErrorCode.INVALID_OBJECT,
    `${label} must include iban or otherId`,
    `${label}.otherId`,
  );
}

function renderAccount(elementName, account) {
  const inner = account.iban
    ? `<IBAN>${escapeXml(account.iban)}</IBAN>`
    : `<Othr><Id>${escapeXml(account.otherId)}</Id></Othr>`;
  const proxy = account.proxy ? renderProxy(account.proxy) : "";
  return `<${elementName}><Id>${inner}</Id>${proxy}</${elementName}>`;
}

function renderProxy(proxy) {
  const type = proxy.typeCode
    ? `<Tp><Cd>${escapeXml(proxy.typeCode)}</Cd></Tp>`
    : proxy.typeProprietary
      ? `<Tp><Prtry>${escapeXml(proxy.typeProprietary)}</Prtry></Tp>`
      : "";
  return `<Prxy>${type}<Id>${escapeXml(proxy.id)}</Id></Prxy>`;
}

function requireParty(value, label) {
  const party = requireObject(value, label);
  const name = requireId(party.name, `${label}.name`);
  let lei;
  if (party.lei) {
    lei = normalizeLei(party.lei, `${label}.lei`);
  }
  let identifier;
  if (party.identifier) {
    identifier = requireMax35Text(party.identifier, `${label}.identifier`);
  }
  let scheme = party.identifierScheme;
  if (scheme != null) {
    scheme = requireId(scheme, `${label}.identifierScheme`);
  } else if (identifier) {
    scheme = "NORITO_PARTY_ID";
  }
  if (scheme && scheme.length > 35) {
    fail(
      ValidationErrorCode.VALUE_OUT_OF_RANGE,
      `${label}.identifierScheme must be ≤ 35 characters`,
      `${label}.identifierScheme`,
    );
  }
  return {
    name,
    lei,
    identifier,
    identifierScheme: scheme,
  };
}

function requireMax35Text(value, label) {
  const text = requireId(value, label);
  if (text.length > 35) {
    fail(ValidationErrorCode.VALUE_OUT_OF_RANGE, `${label} must be ≤ 35 characters`, label);
  }
  return text;
}

function requirePacs009MessageDefinitionId(value, label) {
  const normalized = requireMax35Text(value, label).toLowerCase();
  if (!PACS009_MESSAGE_DEFINITION_REGEX.test(normalized)) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${label} must match pacs.009.<variant> (for example pacs.009.001.08)`,
      label,
    );
  }
  return normalized;
}

function renderParty(elementName, party) {
  const idFragments = [];
  if (party.lei) {
    idFragments.push(`<LEI>${escapeXml(party.lei)}</LEI>`);
  }
  if (party.identifier) {
    const schemeName = party.identifierScheme
      ? `<SchmeNm><Prtry>${escapeXml(party.identifierScheme)}</Prtry></SchmeNm>`
      : "";
    idFragments.push(`<Othr><Id>${escapeXml(party.identifier)}</Id>${schemeName}</Othr>`);
  }
  const idBlock = idFragments.length > 0 ? `<Id><OrgId>${idFragments.join("")}</OrgId></Id>` : "";
  return `<${elementName}><Nm>${escapeXml(party.name)}</Nm>${idBlock}</${elementName}>`;
}

function renderPurpose(code) {
  const normalized = requireId(code, "purposeCode").toUpperCase();
  if (!PURPOSE_REGEX.test(normalized)) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      "purposeCode must be 3-8 uppercase alphanumeric characters",
      "purposeCode",
    );
  }
  return `<Purp><Cd>${normalized}</Cd></Purp>`;
}

function renderRemittanceInformation(remittance) {
  const lines = normalizeRemittanceInformation(remittance, "remittanceInformation");
  if (!lines || lines.length === 0) {
    return "";
  }
  const renderedLines = lines.map((line) => `<Ustrd>${escapeXml(line)}</Ustrd>`).join("");
  return `<RmtInf>${renderedLines}</RmtInf>`;
}

function renderSupplementaryData(data) {
  const json = canonicalJSONStringify(data, "supplementaryData");
  return `<SplmtryData><Envlp><Any>${escapeXml(json)}</Any></Envlp></SplmtryData>`;
}

function normalizeReportPagination(pagination) {
  const data = requireObject(pagination, "pagination");
  const pageNumber = requirePositiveInteger(data.pageNumber ?? data.page, "pagination.pageNumber");
  const lastPage = requireBooleanLike(
    data.lastPage ?? data.lastPageIndicator ?? data.last,
    "pagination.lastPage",
  );
  return [
    "      <RptPgntn>",
    `        <PgNb>${pageNumber}</PgNb>`,
    `        <LastPgInd>${lastPage}</LastPgInd>`,
    "      </RptPgntn>",
  ].join("\n");
}

function normalizeReportRange(from, to) {
  if (!from && !to) {
    return "";
  }
  const fromValue = from ? normalizeDateTime(from, "fromDateTime") : null;
  const toValue = to ? normalizeDateTime(to, "toDateTime") : null;
  if (fromValue && toValue) {
    const fromInstant = Date.parse(fromValue);
    const toInstant = Date.parse(toValue);
    if (toInstant < fromInstant) {
      fail(
        ValidationErrorCode.VALUE_OUT_OF_RANGE,
        "fromDateTime must be on or before toDateTime",
        "fromDateTime",
      );
    }
  }
  return [
    "      <FrToDt>",
    fromValue ? `        <FrDtTm>${fromValue}</FrDtTm>` : "",
    toValue ? `        <ToDtTm>${toValue}</ToDtTm>` : "",
    "      </FrToDt>",
  ]
    .filter(Boolean)
    .join("\n");
}

function renderReportAccount(account, currency) {
  const inner = renderAccount("Acct", account);
  const currencyBlock = currency ? `<Ccy>${currency}</Ccy>` : "";
  return [inner, currencyBlock].filter(Boolean).join("\n");
}

function renderReportBalance(balance, index) {
  const entry = requireObject(balance, `balances[${index}]`);
  const typeCode = requireMax35Text(entry.typeCode ?? entry.code ?? entry.type ?? "ITBD", `balances[${index}].typeCode`);
  const amount = renderCurrencyAmountElement(
    "Amt",
    entry.amount,
    `balances[${index}].amount`,
  );
  const indicator = requireCreditDebitIndicator(
    entry.creditDebitIndicator ?? entry.indicator,
    `balances[${index}].creditDebitIndicator`,
  );
  const asOf = entry.asOfDateTime
    ? normalizeDateTime(entry.asOfDateTime, `balances[${index}].asOfDateTime`)
    : null;
  return [
    "<Bal>",
    "  <Tp>",
    "    <CdOrPrtry>",
    `      <Cd>${escapeXml(typeCode.toUpperCase())}</Cd>`,
    "    </CdOrPrtry>",
    "  </Tp>",
    `  ${amount}`,
    `  <CdtDbtInd>${indicator}</CdtDbtInd>`,
    asOf ? `  <Dt><DtTm>${asOf}</DtTm></Dt>` : "",
    "</Bal>",
  ]
    .filter(Boolean)
    .join("\n");
}

function renderReportEntry(entry, index) {
  const data = requireObject(entry, `entries[${index}]`);
  const amount = renderCurrencyAmountElement("Amt", data.amount, `entries[${index}].amount`);
  const indicator = requireCreditDebitIndicator(
    data.creditDebitIndicator ?? data.indicator,
    `entries[${index}].creditDebitIndicator`,
  );
  const status = data.status
    ? requireReportStatus(data.status, `entries[${index}].status`)
    : "BOOK";
  const bookingDate = data.bookingDate
    ? normalizeDate(data.bookingDate, `entries[${index}].bookingDate`)
    : null;
  const valueDate = data.valueDate
    ? normalizeDate(data.valueDate, `entries[${index}].valueDate`)
    : null;
  const reference = data.reference
    ? requireMax35Text(data.reference, `entries[${index}].reference`)
    : null;
  return [
    "<Ntry>",
    `  ${amount}`,
    `  <CdtDbtInd>${indicator}</CdtDbtInd>`,
    `  <Sts>${status}</Sts>`,
    bookingDate ? `  <BookgDt><Dt>${bookingDate}</Dt></BookgDt>` : "",
    valueDate ? `  <ValDt><Dt>${valueDate}</Dt></ValDt>` : "",
    reference ? `  <AcctSvcrRef>${escapeXml(reference)}</AcctSvcrRef>` : "",
    "</Ntry>",
  ]
    .filter(Boolean)
    .join("\n");
}

function renderReportSummary(summary) {
  const data = requireObject(summary, "summary");
  const entryCount = data.entryCount ?? data.entries ?? 0;
  const sum = data.sum ?? data.total ?? null;
  const netAmount = data.netAmount ?? null;
  const indicator = data.netCreditDebitIndicator
    ? requireCreditDebitIndicator(data.netCreditDebitIndicator, "summary.netCreditDebitIndicator")
    : null;
  return [
    "      <TxsSummry>",
    "        <TtlNtries>",
    `          <NbOfNtries>${entryCount}</NbOfNtries>`,
    sum != null ? `          <Sum>${escapeXml(String(sum))}</Sum>` : "",
    netAmount != null
      ? [
          "          <TtlNetNtry>",
          `            <Amt>${escapeXml(String(netAmount))}</Amt>`,
          indicator ? `            <CdtDbtInd>${indicator}</CdtDbtInd>` : "",
          "          </TtlNetNtry>",
        ].join("\n")
      : "",
    "        </TtlNtries>",
    "      </TxsSummry>",
  ]
    .filter(Boolean)
    .join("\n");
}

function renderOptionalCase(caseId, creatorName) {
  if (!caseId && !creatorName) {
    return "";
  }
  const normalizedId = caseId ? requireMax35Text(caseId, "caseId") : null;
  const creator = creatorName ? requireId(creatorName, "caseCreatorName") : null;
  return [
    "        <Case>",
    normalizedId ? `          <Id>${escapeXml(normalizedId)}</Id>` : "",
    creator ? `          <Cretr><Pty><Nm>${escapeXml(creator)}</Nm></Pty></Cretr>` : "",
    "        </Case>",
  ]
    .filter(Boolean)
    .join("\n");
}

function renderServiceLevel(code) {
  const normalized = requireId(code, "serviceLevelCode").toUpperCase();
  return [
    "          <PmtTpInf>",
    "            <SvcLvl>",
    `              <Prtry>${escapeXml(normalized)}</Prtry>`,
    "            </SvcLvl>",
    "          </PmtTpInf>",
  ].join("\n");
}

function requireCreditDebitIndicator(value, label) {
  const text = requireId(value, label).toUpperCase();
  if (text !== "CRDT" && text !== "DBIT") {
    fail(ValidationErrorCode.INVALID_STRING, `${label} must be CRDT or DBIT`, label);
  }
  return text;
}

function requireReportStatus(value, label) {
  const text = requireId(value, label).toUpperCase();
  if (!/^[A-Z]{4}$/.test(text)) {
    fail(
      ValidationErrorCode.INVALID_STRING,
      `${label} must be a four-letter uppercase status code`,
      label,
    );
  }
  return text;
}

function requirePositiveInteger(value, label) {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value) || value <= 0) {
      fail(ValidationErrorCode.INVALID_NUMERIC, `${label} must be a positive integer`, label);
    }
    return value;
  }
  if (typeof value === "bigint") {
    if (value <= 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(ValidationErrorCode.INVALID_NUMERIC, `${label} must be a positive integer`, label);
    }
    return Number(value);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!/^[1-9]\d*$/.test(trimmed)) {
      fail(ValidationErrorCode.INVALID_NUMERIC, `${label} must be a positive integer`, label);
    }
    const parsed = Number.parseInt(trimmed, 10);
    if (!Number.isSafeInteger(parsed)) {
      fail(ValidationErrorCode.INVALID_NUMERIC, `${label} must be a positive integer`, label);
    }
    return parsed;
  }
  fail(ValidationErrorCode.INVALID_NUMERIC, `${label} must be a positive integer`, label);
}

function requireBooleanLike(value, label) {
  if (value === true || value === false) {
    return value;
  }
  if (value === 1 || value === "1" || value === "true") {
    return true;
  }
  if (value === 0 || value === "0" || value === "false") {
    return false;
  }
  fail(ValidationErrorCode.INVALID_JSON_VALUE, `${label} must be a boolean`, label);
}

function canonicalJSONStringify(value, label) {
  const normalized = canonicalizeJsonValue(value, label, new Set());
  return JSON.stringify(normalized);
}

function canonicalizeJsonValue(value, label, stack) {
  if (typeof value === "bigint") {
    fail(ValidationErrorCode.INVALID_JSON_VALUE, `${label} must not contain BigInt values`, label);
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value === "function" || typeof value === "symbol") {
    return undefined;
  }
  if (value && typeof value === "object") {
    if (typeof value.toJSON === "function") {
      return canonicalizeJsonValue(value.toJSON(), label, stack);
    }
    if (stack.has(value)) {
      fail(
        ValidationErrorCode.INVALID_JSON_VALUE,
        `${label} must not contain circular references`,
        label,
      );
    }
    stack.add(value);
    try {
      if (Array.isArray(value)) {
        return value.map((entry) => {
          if (entry === undefined || typeof entry === "function" || typeof entry === "symbol") {
            return null;
          }
          return canonicalizeJsonValue(entry, label, stack);
        });
      }
      const result = {};
      const keys = Object.keys(value).sort();
      for (const key of keys) {
        const entry = value[key];
        if (entry === undefined || typeof entry === "function" || typeof entry === "symbol") {
          continue;
        }
        result[key] = canonicalizeJsonValue(entry, label, stack);
      }
      return result;
    } finally {
      stack.delete(value);
    }
  }
  // Undefined falls through to here, mirror JSON.stringify behaviour by omitting the key.
  return undefined;
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function indentBlock(block, indent) {
  if (!block) {
    return "";
  }
  const prefix = indent ?? "";
  return block
    .split("\n")
    .map((line) => `${prefix}${line}`)
    .join("\n");
}
