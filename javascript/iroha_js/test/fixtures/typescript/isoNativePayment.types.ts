import {
  buildPacs008Message,
  buildPacs009Message,
  buildSamplePacs008Message,
  buildSamplePacs009Message,
  type BuildPacs008Options,
  type BuildPacs009Options,
  type IsoNexusSettlement,
} from "../../../index.js";

declare const terms: IsoNexusSettlement;
declare const customer: BuildPacs008Options;
declare const bank: BuildPacs009Options;
buildPacs008Message(customer);
buildPacs009Message(bank);
buildSamplePacs008Message({ uetr: customer.uetr, nexusSettlement: terms });
buildSamplePacs009Message({ uetr: bank.uetr, nexusSettlement: terms });
const { uetr: _uetr, ...missingUetr } = customer;
// @ts-expect-error A gateway envelope cannot supply a missing business reference.
buildPacs008Message(missingUetr);
const { nexusSettlement: _terms, ...missingTerms } = bank;
// @ts-expect-error Every native term is mandatory.
buildPacs009Message(missingTerms);
// @ts-expect-error Demo defaults cannot synthesize business authority.
buildSamplePacs008Message();
// @ts-expect-error Demo envelope-only options are incomplete.
buildSamplePacs009Message({ messageSuffix: "envelope" });
// @ts-expect-error NetworkId is an explicit identity, not a string label.
const wrongNetwork: IsoNexusSettlement = { ...terms, networkId: "network" };
// @ts-expect-error A renamed term cannot substitute for exact absolute expiry.
const wrongTerms: IsoNexusSettlement = { ...terms, expiry: "100" };
void wrongNetwork;
void wrongTerms;
