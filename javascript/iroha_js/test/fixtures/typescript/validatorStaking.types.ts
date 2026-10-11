import {
  ToriiClient,
  type ToriiBrowserClient,
  LocalSigningContext,
  encodeValidatorStakingPreparationFrameV1,
  decodeValidatorStakingPreparationFrameV1,
  validateValidatorStakingPreparationV1,
  type NetworkId,
  type StakingPreparationRequestV1,
  type StakingPreparationV1,
  type StakingPreparationOperationV1,
  encodeValidatorStakingValueV1,
  decodeValidatorStakingValueV1,
  type StakingMonetaryPlanV1,
  type StakingMonetaryPreconditionV1,
  type StakingRewardClaimPlanV1,
  type StakingEpochAuthorizationV1,
  type StakingValidatorGenerationV1,
  type StakingUnsignedV1,
} from "../../../index.js";
import {
  encodeValidatorStakingPreparationFrameV1 as encodePreparationNorito,
  decodeValidatorStakingPreparationFrameV1 as decodePreparationNorito,
  validateValidatorStakingPreparationV1 as validatePreparationNorito,
  encodeValidatorStakingValueV1 as encodeNorito,
  decodeValidatorStakingValueV1 as decodeNorito,
} from "../../../norito.js";

declare const plan: StakingMonetaryPlanV1;
declare const claim: StakingRewardClaimPlanV1;
declare const withoutFee: Omit<StakingRewardClaimPlanV1, "fee_claim">;
declare const bytes: Uint8Array;

const operations: StakingMonetaryPreconditionV1[] = [
  { kind: "registration", value: { activation_height: 201n } },
  { kind: "bond", value: { activation_height: 201n, peer_id: { public_key: "canonical-key" } } },
  { kind: "unbond", value: { activation_height: 201n, request_hash: "canonical-hash" } },
  { kind: "slash", value: { activation_height: 201n, slashable_exposure: "1500" } },
];
for (const precondition of operations) {
  const encoded: Buffer = encodeValidatorStakingValueV1("MonetaryPlan", { ...plan, precondition });
  const decoded: StakingMonetaryPlanV1 = decodeNorito("MonetaryPlan", encoded);
  void decoded;
}
const feeOnly: Buffer = encodeNorito("RewardClaimPlan", claim);
// @ts-expect-error Automatic entitlement consent is mandatory.
const noFee: Buffer = encodeNorito("RewardClaimPlan", { ...claim, fee_claim: null });
const authorization: StakingEpochAuthorizationV1 = decodeValidatorStakingValueV1("EpochAuthorization", bytes);
const epoch: StakingUnsignedV1 = authorization.epoch;
const generation: StakingUnsignedV1 = authorization.authority_generation;
const validatorGeneration: StakingValidatorGenerationV1 = decodeNorito("ValidatorGeneration", bytes);
const generationBytes: Buffer = encodeNorito("ValidatorGeneration", validatorGeneration);
const peerKey: string = validatorGeneration.validators[0].public_key;

// @ts-expect-error the retired monetary-authority generation is not an exported layout
decodeValidatorStakingValueV1("AuthorityGeneration", bytes);
// @ts-expect-error validator generations have no separate serialized version field
encodeNorito("ValidatorGeneration", { ...validatorGeneration, version: 1 });
// @ts-expect-error generation seats are peer identities without retired proof-key wrappers
encodeNorito("ValidatorGeneration", { ...validatorGeneration, validators: [{ validator: validatorGeneration.validators[0] }] });

// @ts-expect-error each operation carries its typed precondition, never opaque bytes
encodeValidatorStakingValueV1("MonetaryPlan", { ...plan, precondition: bytes });
// @ts-expect-error the canonical claim layout requires the exact automatic entitlement
encodeNorito("RewardClaimPlan", withoutFee);
// @ts-expect-error unbonding binds the exact withdrawal request hash
const incompleteUnbond: StakingMonetaryPreconditionV1 = { kind: "unbond", value: { activation_height: 201n } };
// @ts-expect-error epoch authorization and monetary plans are distinct records
const confusedPlan: StakingMonetaryPlanV1 = authorization;
// @ts-expect-error protocol counters must not be rounded to a JavaScript number
const roundedEpoch: number = authorization.epoch;
// @ts-expect-error no obsolete epoch-coupled authority layout is exported
decodeValidatorStakingValueV1("EpochAuthority", bytes);

void [feeOnly, noFee, epoch, generation, generationBytes, peerKey, incompleteUnbond, confusedPlan, roundedEpoch];


declare const networkId: NetworkId;
declare const preparationRequest: StakingPreparationRequestV1;
declare const prepared: StakingPreparationV1;
const localSigningContext = new LocalSigningContext(networkId, 753);
const client = new ToriiClient("https://staking.invalid", { localSigningContext });
const pinnedXor = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
const requestFrame: Buffer = encodeValidatorStakingPreparationFrameV1("PreparationRequest", preparationRequest);
const responseFrame: Buffer = encodePreparationNorito("Preparation", prepared);
const exactRequest: StakingPreparationRequestV1 = decodePreparationNorito("PreparationRequest", requestFrame);
const exactResponse: StakingPreparationV1 = decodeValidatorStakingPreparationFrameV1("Preparation", responseFrame);
const checked: StakingPreparationV1 = validateValidatorStakingPreparationV1(exactResponse, exactRequest, networkId, pinnedXor);
const checkedViaNorito: StakingPreparationV1 = validatePreparationNorito(prepared, preparationRequest, networkId, pinnedXor);
const observation: Promise<StakingPreparationV1> = client.preparePublicLanePlan(exactRequest, pinnedXor, { signal: new AbortController().signal });
const largeHeight: StakingPreparationRequestV1 = { ...preparationRequest, valid_for_blocks: 18446744073709551615n };
const claimIntent: StakingPreparationOperationV1 = { kind: "claim_rewards", value: { recipient: "canonical-account" } };

// @ts-expect-error the route requires the caller's explicit genesis-pinned XOR definition
client.preparePublicLanePlan(preparationRequest);
// @ts-expect-error a signal is not an XOR pin and cannot occupy that argument
client.preparePublicLanePlan(preparationRequest, { signal: new AbortController().signal });
// @ts-expect-error validation requires both network identity and XOR definition pins
validateValidatorStakingPreparationV1(prepared, preparationRequest);
// @ts-expect-error network identity alone cannot establish the XOR pin
validatePreparationNorito(prepared, preparationRequest, networkId);
// @ts-expect-error LocalSigningContext requires a typed genesis-derived NetworkId
new LocalSigningContext("network-label", 753);
// @ts-expect-error LocalSigningContext cannot omit network identity
new LocalSigningContext();
// @ts-expect-error a client signing context must include network identity
new ToriiClient("https://staking.invalid", { localSigningContext: { chainDiscriminant: 753 } });
// @ts-expect-error network labels are not authenticated NetworkId values
validatePreparationNorito(prepared, preparationRequest, "network-label", pinnedXor);
// @ts-expect-error observed u64 heights cannot be treated as rounded JavaScript numbers
const roundedObservedHeight: number = exactResponse.observed_height;
// @ts-expect-error assumed u64 execution heights cannot be treated as rounded JavaScript numbers
const roundedExecutionHeight: number = exactResponse.assumed_execution_height;
// @ts-expect-error retired epoch cuts are not an automatic entitlement intent
const retiredEpochCut: StakingPreparationOperationV1 = { kind: "claim_rewards", value: { recipient: "canonical-account", upto_epoch: null } };
// @ts-expect-error prepared response and request have distinct complete frame schemas
encodePreparationNorito("Preparation", preparationRequest);
// @ts-expect-error bare monetary DTOs are not preparation frames
decodePreparationNorito("MonetaryPlan", bytes);
// @ts-expect-error the obsolete epoch-coupled authority format is not a preparation frame
decodeValidatorStakingPreparationFrameV1("EpochAuthority", bytes);
// @ts-expect-error finalization uses the canonical exact request-id operation
const retiredWithdrawal: StakingPreparationOperationV1 = { kind: "unbond", value: { validator: "account", staker: "account", amount: "1" } };
// @ts-expect-error this observation API has no signing or arbitrary transport options
client.preparePublicLanePlan(preparationRequest, pinnedXor, { canonicalAuth: {} });

void [checked, checkedViaNorito, observation, largeHeight, claimIntent, roundedObservedHeight,
  roundedExecutionHeight, retiredEpochCut, retiredWithdrawal];

declare const browserClient: ToriiBrowserClient;
// @ts-expect-error preparation belongs to the canonical native ToriiClient owner
browserClient.preparePublicLanePlan(preparationRequest, pinnedXor);
