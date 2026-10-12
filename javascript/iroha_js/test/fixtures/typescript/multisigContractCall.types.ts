import {
  buildMultisigContractCallProposeRequest,
  type MultisigContractCallProposeRequest,
  type MultisigContractCallDraftIntent,
  type ToriiClient,
} from "../../../index.js";

declare const client: ToriiClient;
declare const body: Omit<MultisigContractCallProposeRequest, "draftIntent">;
declare const reviewed: MultisigContractCallDraftIntent;

client.proposeMultisigContractCall({ ...body, draftIntent: reviewed });
buildMultisigContractCallProposeRequest({ ...body, trigger: "reviewed_action" });

// @ts-expect-error A local proposal requires an independently reviewed native draft.
client.proposeMultisigContractCall(body);
// @ts-expect-error The removed wire-style alias cannot supply the local draft.
client.proposeMultisigContractCall({ ...body, draft_intent: reviewed });
// @ts-expect-error The alias is invalid even alongside the canonical local draft.
client.proposeMultisigContractCall({ ...body, draftIntent: reviewed, draft_intent: reviewed });
// @ts-expect-error Executable bytes alone do not bind the separately returned content hash.
client.proposeMultisigContractCall({ ...body, draftIntent: { executableB64: "AQ==", metadataB64: "AQ==" } });
