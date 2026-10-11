import { readFileSync } from "node:fs";
// Governance and protected-namespace Torii client regression registrations.

export function buildIntegrationGovernancePlainBallotPayload(
  overrides,
  { defaultAuthority, networkId },
) {
  if (overrides === null || typeof overrides !== "object" || Array.isArray(overrides)) {
    return null;
  }
  const normalizeString = (value) => {
    if (typeof value !== "string") {
      return null;
    }
    const trimmed = value.trim();
    return trimmed.length === 0 ? null : trimmed;
  };
  const referendumId = normalizeString(overrides.referendumId);
  if (!referendumId) {
    return null;
  }
  const authority = normalizeString(overrides.authority) ?? defaultAuthority;
  const owner = normalizeString(overrides.owner) ?? defaultAuthority;
  if (Object.prototype.hasOwnProperty.call(overrides, "chainId")) {
    throw new Error(
      "governance ballot chainId is retired; configure exact NETWORK_ID instead",
    );
  }
  const durationBlocksRaw = overrides.durationBlocks ?? 10;
  const durationBlocks =
    typeof durationBlocksRaw === "number"
      ? durationBlocksRaw
      : Number.parseInt(String(durationBlocksRaw), 10);
  if (!Number.isFinite(durationBlocks) || durationBlocks <= 0) {
    throw new Error("governance ballot durationBlocks must be a positive integer");
  }
  const amountRaw = overrides.amount ?? "1";
  const amountText =
    typeof amountRaw === "number" && Number.isFinite(amountRaw)
      ? amountRaw.toString()
      : normalizeString(String(amountRaw));
  if (!amountText) {
    throw new Error("governance ballot amount must be a non-empty string or number");
  }
  const direction = normalizeString(overrides.direction ?? "Aye") ?? "Aye";
  return {
    authority,
    networkId,
    referendumId,
    owner,
    amount: amountText,
    durationBlocks,
    direction,
  };
}

function mlDsaManifestSigner(keyLength, fill = 0x5a) {
  const lengthVarint = [];
  let remaining = keyLength;
  do {
    const byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 0x80);
    lengthVarint.push(remaining === 0 ? byte : byte | 0x80);
  } while (remaining !== 0);
  const multihash = Buffer.concat([
    Buffer.from([0xee, 0x01, ...lengthVarint]),
    Buffer.alloc(keyLength, fill),
  ]);
  return `ml-dsa:${multihash.toString("hex")}`;
}

export function registerToriiClientGovernanceTests({
  assert,
  BASE_URL,
  FIXTURE_ALICE_ID,
  FIXTURE_ALICE_TEST_ID,
  FIXTURE_BOB_ID,
  FIXTURE_BOB_NARNIA_ID,
  FIXTURE_CAROL_ID,
  GOVERNANCE_NETWORK_ID,
  GOVERNANCE_LOCAL_SIGNING_CONTEXT,
  GOVERNANCE_PROPOSAL_ID,
  LocalSigningContext,
  NetworkId,
  SAMPLE_ACCOUNT_FORMS,
  SEED_11_ED25519_PUBLIC_KEY_HEX,
  ToriiClient,
  ValidationError,
  ValidationErrorCode,
  assertRequestSignal,
  cloneFixture,
  createResponse,
  parseStrictLosslessIntegerJson,
  readFileSync,
  test,
  toriiFixtures,
}) {
  test("governance helpers validate options", async () => {
    const client = new ToriiClient(BASE_URL);

    const optionTypeCases = [
      [
        "getGovernanceProposal",
        () => client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID, "invalid"),
        /getGovernanceProposal options must be an object/,
      ],
      [
        "getGovernanceReferendum",
        () => client.getGovernanceReferendum("ref-1", "invalid"),
        /getGovernanceReferendum options must be an object/,
      ],
      [
        "getGovernanceTally",
        () => client.getGovernanceTally("ref-1", "invalid"),
        /getGovernanceTally options must be an object/,
      ],
    ];
    for (const [_label, invoke, error] of optionTypeCases) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(invoke, error);
    }
    const invalidSignalCases = [
      [
        "getGovernanceProposal",
        () => client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID, { signal: "nope" }),
        /getGovernanceProposal options.signal must be an AbortSignal/,
      ],
      [
        "getGovernanceReferendum",
        () => client.getGovernanceReferendum("ref-1", { signal: "nope" }),
        /getGovernanceReferendum options.signal must be an AbortSignal/,
      ],
      [
        "getGovernanceTally",
        () => client.getGovernanceTally("ref-1", { signal: "nope" }),
        /getGovernanceTally options.signal must be an AbortSignal/,
      ],
    ];
    for (const [_label, invoke, error] of invalidSignalCases) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(invoke, error);
    }
    const extraFieldCases = [
      [
        "getGovernanceProposal",
        () => client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID, { extra: true }),
        /getGovernanceProposal options contains unsupported fields: extra/,
      ],
      [
        "getGovernanceReferendum",
        () => client.getGovernanceReferendum("ref-1", { extra: true }),
        /getGovernanceReferendum options contains unsupported fields: extra/,
      ],
      [
        "getGovernanceTally",
        () => client.getGovernanceTally("ref-1", { extra: true }),
        /getGovernanceTally options contains unsupported fields: extra/,
      ],
    ];
    for (const [_label, invoke, error] of extraFieldCases) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(invoke, error);
    }
  });

  test("governance id validation surfaces structured errors", async () => {
    const client = new ToriiClient(BASE_URL);
    const cases = [
      [
        "getGovernanceProposal",
        () => client.getGovernanceProposal("  "),
        "proposalId",
      ],
      [
        "getGovernanceReferendum",
        // @ts-expect-error intentionally invalid type for validation path
        () => client.getGovernanceReferendum(null),
        "referendumId",
      ],
      [
        "getGovernanceTally",
        () => client.getGovernanceTally(undefined),
        "referendumId",
      ],
    ];
    for (const [label, invoke, path] of cases) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(invoke, (error) => {
        assert.ok(error instanceof ValidationError, `${label} should surface ValidationError`);
        assert.equal(error.code, ValidationErrorCode.INVALID_STRING);
        assert.equal(error.path, path);
        return true;
      });
    }
  });

  test("governance GET identifiers use canonical unreserved path segments", async () => {
    const capturedUrls = [];
    const fetchImpl = async (url) => {
      capturedUrls.push(url);
      return createResponse({ status: 404 });
    };
    const client = new ToriiClient(BASE_URL, { fetchImpl });

    assert.equal(
      await client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID, governanceReadOptions()),
      null,
    );
    assert.equal(
      await client.getGovernanceReferendum("ref.one~1", governanceReadOptions()),
      null,
    );
    assert.equal(
      await client.getGovernanceTally("ref_two-2", governanceReadOptions()),
      null,
    );
    assert.equal(
      await client.getGovernanceLocks("Ref3", governanceReadOptions()),
      null,
    );
    assert.deepEqual(capturedUrls, [
      `${BASE_URL}/v1/gov/proposals/${GOVERNANCE_PROPOSAL_ID}`,
      `${BASE_URL}/v1/gov/referenda/ref.one~1`,
      `${BASE_URL}/v1/gov/tally/ref_two-2`,
      `${BASE_URL}/v1/gov/locks/Ref3`,
    ]);
  });

  test("governance GET identifiers reject aliases before transport", async () => {
    let dispatched = false;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        dispatched = true;
        throw new Error("invalid governance identifier reached transport");
      },
    });
    const invalidCalls = [
      () => client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID.toUpperCase()),
      () => client.getGovernanceProposal(`0x${GOVERNANCE_PROPOSAL_ID}`),
      () => client.getGovernanceProposal(` ${GOVERNANCE_PROPOSAL_ID}`),
      () => client.getGovernanceProposal("proposal/segment"),
      () => client.getGovernanceReferendum(" ref-1"),
      () => client.getGovernanceReferendum("ref 1"),
      () => client.getGovernanceReferendum("ref/1"),
      () => client.getGovernanceReferendum(".hidden"),
      () => client.getGovernanceReferendum("ref%31"),
      () => client.getGovernanceReferendum("投票"),
      () => client.getGovernanceTally("ref\t1"),
      () => client.getGovernanceTally("a".repeat(129)),
      () => client.getGovernanceLocks("ref\u00001"),
    ];

    for (const invoke of invalidCalls) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(invoke, ValidationError);
    }
    assert.equal(dispatched, false);
  });

  test("governance draft identifiers reject noncanonical selector aliases", async () => {
    let dispatched = false;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        dispatched = true;
        throw new Error("invalid governance selector reached transport");
      },
    });
    const invalidSelectors = [
      "ref/1",
      ".hidden",
      "ref%31",
      "投票",
      "a".repeat(129),
    ];
    for (const selector of invalidSelectors) {
      const calls = [
        () =>
          client.governanceSubmitPlainBallot({
            authority: FIXTURE_ALICE_ID,
            networkId: GOVERNANCE_NETWORK_ID,
            referendumId: selector,
            owner: FIXTURE_ALICE_ID,
            amount: "1",
            durationBlocks: 1,
            direction: "Aye",
          }),
        () =>
          client.governanceSubmitZkBallotV1({
            authority: FIXTURE_ALICE_ID,
            networkId: GOVERNANCE_NETWORK_ID,
            electionId: selector,
            backend: "pipa-r/pasta",
            envelope: [1],
          }),
        () =>
          client.governanceSubmitZkBallotProofV1({
            authority: FIXTURE_ALICE_ID,
            networkId: GOVERNANCE_NETWORK_ID,
            electionId: selector,
            ballot: { backend: "pipa-r/pasta", envelopeBytes: "AQ==" },
          }),
      ];
      for (const invoke of calls) {
        // eslint-disable-next-line no-await-in-loop
        await assert.rejects(invoke, /RFC 3986/u);
      }
    }
    assert.equal(dispatched, false);
  });

  test("integration governance ballot support pins the exact NetworkId", () => {
    const payload = buildIntegrationGovernancePlainBallotPayload(
      { referendumId: "ref-1" },
      {
        defaultAuthority: FIXTURE_ALICE_ID,
        networkId: GOVERNANCE_NETWORK_ID,
      },
    );
    assert.deepEqual(payload, {
      authority: FIXTURE_ALICE_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      referendumId: "ref-1",
      owner: FIXTURE_ALICE_ID,
      amount: "1",
      durationBlocks: 10,
      direction: "Aye",
    });
    assert.throws(
      () => buildIntegrationGovernancePlainBallotPayload(
        { referendumId: "ref-1", chainId: "retired" },
        {
          defaultAuthority: FIXTURE_ALICE_ID,
          networkId: GOVERNANCE_NETWORK_ID,
        },
      ),
      /chainId is retired/u,
    );
  });

  const governanceBallotOptions = (authority, options = {}) => ({
    ...options,
    canonicalAuth: {
      accountId: authority,
      privateKey: Buffer.alloc(32, 0x33),
    },
  });
  const governanceReadOptions = (options = {}) =>
    governanceBallotOptions(FIXTURE_ALICE_ID, options);
  const plainFixtureRoot = new URL("../../../fixtures/governance/plain_v1/", import.meta.url);
  const plainFixture = (name) => readFileSync(new URL(name, plainFixtureRoot), "utf8");
  for (const [method, file, verify] of [
    ["getGovernanceReferendum", "referendum-max.json", (value) => {
      assert.equal(value.referendum.plain_result.content.approve, (1n << 128n) - 1n);
      assert.equal(value.referendum.plain_result.content.approved, true);
    }],
    ["getGovernanceReferendumTyped", "referendum-max.json", (value) => {
      assert.equal(value.referendum.plain_result.content.approve, (1n << 128n) - 1n);
    }],
    ["getGovernanceTally", "tally-large.json", (value) => {
      assert.equal(value.approve, 18446744073709551617n);
      assert.equal(value.evaluated_block_height, 9007199254740993n);
      assert.equal(value.evaluated_block_hash, "12".repeat(32));
    }],
    ["getGovernanceTallyTyped", "tally-max.json", (value) => {
      assert.equal(value.tally.approve, (1n << 128n) - 1n);
      assert.equal(value.tally.evaluated_block_height, (1n << 64n) - 1n);
      assert.equal(value.tally.evaluated_block_hash, "12".repeat(32));
    }],
    ["getGovernanceLocks", "locks.json", (value) => {
      assert.equal(Object.values(value.locks.locks)[0].expiry_height, (1n << 64n) - 1n);
    }],
    ["getGovernanceLocksTyped", "locks.json", (value) => {
      const lock = Object.values(value.locks)[0];
      assert.equal(lock.duration_blocks, (1n << 64n) - 2n);
      assert.equal(lock.amount, "18446744073709551616.25");
      assert.equal(lock.custody.escrowed, true);
    }],
  ]) {
    test(`${method} retains exact authoritative integers through authenticated response reads`, async () => {
      const controller = new AbortController();
      let captured;
      const client = new ToriiClient(BASE_URL, { fetchImpl: async (url, options) => {
        captured = { url, options };
        return createResponse({ status: 200, textBody: plainFixture(file),
          headers: { "content-type": "application/json" } });
      } });
      verify(await client[method]("ref-1", governanceReadOptions({ signal: controller.signal })));
      assert.match(captured.url, /\/v1\/gov\/(referenda|tally|locks)\/ref-1$/u);
      assertRequestSignal(captured.options.signal, controller.signal);
      const headers = new Headers(captured.options.headers);
      assert.ok(headers.get("X-Iroha-Account"));
      assert.ok(headers.get("X-Iroha-Signature"));
      assert.ok(headers.get("X-Iroha-Nonce"));
    });
  }
  for (const suffix of ["", "Typed"]) {
    for (const entry of JSON.parse(plainFixture("cases.json")).cases.filter((c) => !c.valid)) {
      test(`getGovernanceTally${suffix} refuses raw negative vector ${entry.file}`, async () => {
        const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({
          status: 200, textBody: plainFixture(entry.file),
          headers: { "content-type": "application/json" },
        }) });
        await assert.rejects(() => client[`getGovernanceTally${suffix}`]("ref-1", governanceReadOptions()),
          /governance|unsigned/u);
      });
    }
  }
  const governanceBallotClient = (options = {}) => new ToriiClient(BASE_URL, {
    ...options,
    localSigningContext: GOVERNANCE_LOCAL_SIGNING_CONTEXT,
  });
  const governanceProposalFixture = (kind, payload) => ({
    found: true,
    proposal: {
      proposer: payload.proposal_operator ?? FIXTURE_ALICE_ID,
      kind: { kind, payload },
      created_height: 42,
      status: "Enacted",
    },
  });
  const readGovernanceProposalFixture = async (fixture) => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({
        status: 200,
        jsonData: fixture,
        headers: { "content-type": "application/json" },
      }),
    });
    return client.getGovernanceProposalTyped(
      GOVERNANCE_PROPOSAL_ID,
      governanceReadOptions(),
    );
  };
  test("getGovernanceProposalTyped parses DeployContract variant", async () => {
    const fetchImpl = async (url) => {
      assert.equal(url, `${BASE_URL}/v1/gov/proposals/${GOVERNANCE_PROPOSAL_ID}`);
      return createResponse({
        status: 200,
        jsonData: cloneFixture(toriiFixtures.governance.proposalDeployContract),
        headers: { "content-type": "application/json" },
      });
    };
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    const result = await client.getGovernanceProposalTyped(
      GOVERNANCE_PROPOSAL_ID,
      governanceReadOptions(),
    );
    assert.equal(result.found, true);
    assert.ok(result.proposal);
    assert.equal(result.proposal?.status, "Enacted");
    assert.equal(result.proposal?.kind.variant, "DeployContract");
    assert.equal(
      result.proposal?.kind.deploy_contract?.contract_address,
      "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    );
    assert.equal(result.proposal?.kind.deploy_contract?.code_hash, "aa".repeat(32));
    assert.equal(result.proposal?.kind.deploy_contract?.abi_hash, "bb".repeat(32));
    assert.equal(result.proposal?.kind.deploy_contract?.abi_version, 1);
    assert.deepEqual(result.proposal?.kind.deploy_contract?.manifest_provenance, {
      signer:
        "ed012017CB79FB2B4120F2B1EC65E4198D6E08B28E813FEB01E4A400839B85E18080CE",
      signature:
        "C74557F062FDC5799D64FD2561103F6B13263B1FCE11F3148D48A34781F43D6C3ACB87C885BA666624A98D848AF3BF48A0A0C79FB3F28B244703269A52128809",
    });

    const notFoundClient = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status: 404 }),
    });
    const missing = await notFoundClient.getGovernanceProposal(
      GOVERNANCE_PROPOSAL_ID,
      governanceReadOptions(),
    );
    assert.equal(missing, null);

    const missingTyped = await notFoundClient.getGovernanceProposalTyped(
      GOVERNANCE_PROPOSAL_ID,
      governanceReadOptions(),
    );
    assert.deepEqual(missingTyped, { found: false, proposal: null });
  });

  test("getGovernanceProposalTyped closes over all eleven V1 proposal kinds", async () => {
    const contractAddress =
      "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
    const payoutBinding = JSON.parse(readFileSync(new URL("./fixtures/retail_fee_native_conversion_v1.json", import.meta.url), "utf8"));
    const retailPolicy = JSON.parse(readFileSync(new URL("./fixtures/retail_fee_native_policy_v1.json", import.meta.url), "utf8"));
    retailPolicy.network_id = GOVERNANCE_NETWORK_ID.toString();
    const packageId = {
      home_dataspace: 7,
      scope: { kind: "DataspaceRoot", value: null },
      name: ["governed-package"],
    };
    const variants = [
      [
        "DeployContract",
        {
          ...cloneFixture(
            toriiFixtures.governance.proposalDeployContract,
          ).proposal.kind.payload,
          proposal_operator: FIXTURE_ALICE_ID,
        },
        "deploy_contract",
      ],
      [
        "RuntimeUpgrade",
        {
          proposal_operator: FIXTURE_ALICE_ID,
          manifest: {
            name: "runtime-v1-refresh",
            description: "Canonical V1 runtime image",
            abi_version: 1,
            abi_hash: Array(32).fill(0x11),
            added_syscalls: [],
            added_pointer_types: [],
            start_height: 100,
            end_height: 120,
            sbom_digests: [{ algorithm: "sha256", digest: "AQID" }],
            slsa_attestation: "BAUG",
            provenance: [],
          },
        },
        "runtime_upgrade",
      ],
      [
        "SccpRouteGovernance",
        {
          proposal: {
            network_id: GOVERNANCE_NETWORK_ID.toString(),
            base_revisions: [{
              subject: { subject: "route", key: { network: "bsc_mainnet", profile: null } },
              revision: 1,
            }],
            actions: [{
              action: "remove_staged",
              payload: { network: { network: "bsc_mainnet", profile: null }, revision: 1 },
            }],
          },
        },
        "sccp_route_governance",
      ],
      [
        "ValidationFeePolicy",
        {
          proposal_operator: FIXTURE_ALICE_ID,
          policy: retailPolicy,
        },
        "validation_fee_policy",
      ],
      [
        "ValidationFeePayoutLifecycle",
        { proposal_operator: FIXTURE_ALICE_ID, payout_binding: payoutBinding },
        "validation_fee_payout_lifecycle",
      ],
      [
        "MusubiRegistryGovernance",
        {
          kind: "RetargetAlias",
          value: { alias: ["stable-alias"], target: packageId, expected_revision: 1 },
        },
        "musubi_registry_governance",
      ],
      [
        "SorafsProviderGovernance",
        {
          action: {
            action: "establish",
            value: { provider_id: [Array(32).fill(0x31)], owner: FIXTURE_ALICE_ID },
          },
        },
        "sorafs_provider_governance",
      ],
      [
        "ContractLifecycleGovernance",
        {
          proposal_operator: FIXTURE_ALICE_ID,
          contract_address: contractAddress,
          expected_revision: 3,
          action: {
            action: "CompleteEmergencyHoldRetrospective",
            payload: {
              hold_proposal_content_id: Array(32).fill(0x51),
              hold_governance_attempt_id: Array(32).fill(0x52),
              incident_digest: Array(32).fill(0x53),
              retrospective_finding_root: Array(32).fill(0x54),
            },
          },
        },
        "contract_lifecycle_governance",
      ],
      [
        "ContractEmergencyHold",
        {
          contract_address: contractAddress,
          expected_revision: 2,
          expected_code_hash: "33".repeat(32),
          incident_digest: Array(32).fill(0x55),
          reason: "contain active exploit",
          duration_blocks: 3_600,
        },
        "contract_emergency_hold",
      ],
      [
        "GlobalDataTriggerPermissionGovernance",
        {
          authority: FIXTURE_ALICE_ID,
          action: { action: "grant", value: null },
        },
        "global_data_trigger_permission_governance",
      ],
    ];
    for (const [variant, payload, resultField] of variants) {
      // eslint-disable-next-line no-await-in-loop
      const result = await readGovernanceProposalFixture(
        governanceProposalFixture(variant, payload),
      );
      assert.equal(result.proposal?.kind.variant, variant);
      assert.ok(result.proposal?.kind[resultField]);
      assert.equal(Object.hasOwn(result.proposal?.kind ?? {}, "raw"), false);
    }

    const directProviderId = governanceProposalFixture("SorafsProviderGovernance", {
      action: {
        action: "establish",
        value: { provider_id: Array(32).fill(0x31), owner: FIXTURE_ALICE_ID },
      },
    });
    await assert.rejects(
      readGovernanceProposalFixture(directProviderId),
      /exact one-field ProviderId tuple/u,
    );

    const scalarMusubiNewtypes = governanceProposalFixture("MusubiRegistryGovernance", {
      kind: "RetargetAlias",
      value: {
        alias: "stable-alias",
        target: packageId,
        expected_revision: 1,
      },
    });
    await assert.rejects(
      readGovernanceProposalFixture(scalarMusubiNewtypes),
      /exact one-field string tuple/u,
    );
  });

  test("getGovernanceProposalTyped rejects open, legacy, and inexact proposal shapes", async () => {
    const canonical = cloneFixture(toriiFixtures.governance.proposalDeployContract);
    for (const status of [
      "Proposed",
      "Rejected",
      "Enacted",
      "Superseded",
      "ExecutionFailed",
    ]) {
      const fixture = cloneFixture(canonical);
      fixture.proposal.status = status;
      // eslint-disable-next-line no-await-in-loop
      const result = await readGovernanceProposalFixture(fixture);
      assert.equal(result.proposal?.status, status);
    }
    const cases = [
      ["unknown proposal kind", (fixture) => {
        fixture.proposal.kind.kind = "FutureProposal";
      }],
      ["legacy externally tagged kind", (fixture) => {
        fixture.proposal.kind = { DeployContract: fixture.proposal.kind.payload };
      }],
      ["kind wrapper field", (fixture) => {
        fixture.proposal.kind.raw = {};
      }],
      ["legacy record pipeline", (fixture) => {
        fixture.proposal.pipeline = { stage: "retired" };
      }],
      ["missing record status", (fixture) => {
        delete fixture.proposal.status;
      }],
      ["retired Approved status", (fixture) => {
        fixture.proposal.status = "Approved";
      }],
      ["unknown SoraFS action", (fixture) => {
        fixture.proposal.kind = {
          kind: "SorafsProviderGovernance",
          payload: { action: { action: "rotate", value: {} } },
        };
      }],
      ["unknown Musubi action", (fixture) => {
        fixture.proposal.kind = {
          kind: "MusubiRegistryGovernance",
          payload: { kind: "RestoreArtifact", value: {} },
        };
      }],
    ];
    for (const [label, mutate] of cases) {
      const fixture = cloneFixture(canonical);
      mutate(fixture);
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () => readGovernanceProposalFixture(fixture),
        undefined,
        label,
      );
    }
  });

  test("getGovernanceProposalTyped rejects every retired deploy layout", async () => {
    const canonical = cloneFixture(toriiFixtures.governance.proposalDeployContract);
    const parse = async (mutate) => {
      const fixture = cloneFixture(canonical);
      mutate(fixture.proposal.kind.payload);
      const client = new ToriiClient(BASE_URL, {
        fetchImpl: async () => createResponse({
          status: 200,
          jsonData: fixture,
          headers: { "content-type": "application/json" },
        }),
      });
      return client.getGovernanceProposalTyped(
        GOVERNANCE_PROPOSAL_ID,
        governanceReadOptions(),
      );
    };

    const nullable = await parse((deploy) => {
      deploy.manifest_provenance = null;
    });
    assert.equal(nullable.proposal?.kind.deploy_contract?.manifest_provenance, null);

    const cases = [
      ["legacy hash names", (deploy) => {
        deploy.code_hash_hex = deploy.code_hash;
        deploy.abi_hash_hex = deploy.abi_hash;
        delete deploy.code_hash;
        delete deploy.abi_hash;
      }],
      ["string ABI", (deploy) => {
        deploy.abi_version = "1";
      }],
      ["uppercase code hash", (deploy) => {
        deploy.code_hash = deploy.code_hash.toUpperCase();
      }],
      ["prefixed ABI hash", (deploy) => {
        deploy.abi_hash = `0x${deploy.abi_hash}`;
      }],
      ["missing provenance", (deploy) => {
        delete deploy.manifest_provenance;
      }],
      ["unknown deploy field", (deploy) => {
        deploy.mode = "retired";
      }],
      ["unknown provenance field", (deploy) => {
        deploy.manifest_provenance.key_id = "retired";
      }],
      ["missing provenance signer", (deploy) => {
        delete deploy.manifest_provenance.signer;
      }],
    ];
    for (const [label, mutate] of cases) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => parse(mutate), undefined, label);
    }
  });

  test("getGovernanceProposal forwards AbortSignal option", async () => {
    const controller = new AbortController();
    let captured;
    const fetchImpl = async (url, init) => {
      captured = { url, init };
      return createResponse({
        status: 200,
        jsonData: cloneFixture(toriiFixtures.governance.proposalDeployContract),
        headers: { "content-type": "application/json" },
      });
    };
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    await client.getGovernanceProposal(
      GOVERNANCE_PROPOSAL_ID,
      governanceReadOptions({ signal: controller.signal }),
    );
    assert.equal(captured.url, `${BASE_URL}/v1/gov/proposals/${GOVERNANCE_PROPOSAL_ID}`);
    assert.ok(captured.init.signal instanceof AbortSignal);
  });

  test("getGovernanceProposal enforces options shape", async () => {
    const client = new ToriiClient(BASE_URL, { fetchImpl: async () => createResponse({ status: 404 }) });
    await assert.rejects(
      () => client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID, "oops"),
      (error) => {
        assert(error instanceof TypeError);
        assert.match(error.message, /getGovernanceProposal options must be an object/);
        return true;
      },
    );
    await assert.rejects(
      () =>
        client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID, {
          // @ts-expect-error invalid signal for runtime validation test
          signal: "nope",
        }),
      (error) => {
        assert(error instanceof TypeError);
        assert.match(error.message, /options\.signal must be an AbortSignal/);
        return true;
      },
    );
  });

  test("getGovernanceProposal rejects empty payloads", async () => {
    const fetchImpl = async () =>
      createResponse({
        status: 200,
        jsonData: null,
        headers: { "content-type": "application/json" },
      });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    await assert.rejects(
      () => client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID, governanceReadOptions()),
      /governance proposal endpoint returned no payload/,
    );
  });

  test("getGovernanceReferendum rejects empty payloads", async () => {
    const fetchImpl = async () =>
      createResponse({
        status: 200,
        jsonData: null,
        headers: { "content-type": "application/json" },
      });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    await assert.rejects(
      () => client.getGovernanceReferendum("ref-1", governanceReadOptions()),
      /governance referendum endpoint returned no payload/,
    );
  });

  test("governance query wrappers reject unknown option fields", async () => {
    const fetchImpl = async () => {
      throw new Error("fetch should not be called when options are invalid");
    };
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    const badOptions = { signal: new AbortController().signal, extra: "nope" };
    const cases = [
      ["getGovernanceProposal", () =>
        client.getGovernanceProposal(GOVERNANCE_PROPOSAL_ID, badOptions)],
      ["getGovernanceReferendum", () =>
        client.getGovernanceReferendum("ref-1", badOptions)],
      ["getGovernanceTally", () => client.getGovernanceTally("ref-1", badOptions)],
      ["getGovernanceLocks", () => client.getGovernanceLocks("ref-1", badOptions)],
      ["getGovernanceUnlockStats", () => client.getGovernanceUnlockStats(badOptions)],
    ];
    for (const [label, invoke] of cases) {
      await assert.rejects(invoke, (error) => {
        assert(error instanceof TypeError);
        assert.match(
          error.message,
          new RegExp(`${label} options contains unsupported fields: extra`),
        );
        return true;
      });
    }
  });

  test("getGovernanceLocks rejects empty payloads", async () => {
    const fetchImpl = async () =>
      createResponse({
        status: 200,
        jsonData: null,
        headers: { "content-type": "application/json" },
      });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    await assert.rejects(
      () => client.getGovernanceLocks("ref-1", governanceReadOptions()),
      /governance locks endpoint returned no payload/,
    );
  });

  test("getGovernanceUnlockStats rejects empty payloads", async () => {
    const fetchImpl = async () => createResponse({
      status: 200,
      jsonData: null,
      headers: { "content-type": "application/json" },
    });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    await assert.rejects(
      () => client.getGovernanceUnlockStats(governanceReadOptions()),
      /governance unlock stats endpoint returned no payload/,
    );
  });

  test("getGovernanceReferendumTyped tolerates missing referendum payloads", async () => {
    const fetchImpl = async () =>
      createResponse({
        status: 200,
        jsonData: cloneFixture(toriiFixtures.governance.referendumMissing),
        headers: { "content-type": "application/json" },
      });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    const result = await client.getGovernanceReferendumTyped(
      "ref-1",
      governanceReadOptions(),
    );
    assert.equal(result.found, false);
    assert.equal(result.referendum, null);
  });

  test("getGovernanceReferendum treats 404 as not found", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status: 404 }),
    });
    const raw = await client.getGovernanceReferendum("missing-ref", governanceReadOptions());
    assert.equal(raw, null);
    const typed = await client.getGovernanceReferendumTyped(
      "missing-ref",
      governanceReadOptions(),
    );
    assert.equal(typed.found, false);
    assert.equal(typed.referendum, null);
  });

  test("getGovernanceLocksTyped parses lock records and synthesizes not-found result on 404", async () => {
    const locksFixture = cloneFixture(toriiFixtures.governance.locks);
    const [lock] = Object.values(locksFixture.locks.locks);
    lock.amount = "18446744073709551616.25";
    lock.slashed = "0.25";
    const fetchImpl = async () =>
      createResponse({
        status: 200,
        jsonData: locksFixture,
        headers: { "content-type": "application/json" },
      });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    const result = await client.getGovernanceLocksTyped("ref-1", governanceReadOptions());
    assert.equal(result.found, true);
    assert.equal(Object.keys(result.locks).length, 1);
    const [firstLock] = Object.values(result.locks);
    assert.ok(firstLock);
    assert.equal(firstLock.amount, "18446744073709551616.25");
    assert.equal(firstLock.slashed, "0.25");
    assert.equal(firstLock.duration_blocks, 5);
    assert.deepEqual(firstLock.custody, lock.custody);

    const missingClient = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status: 404 }),
    });
    const raw = await missingClient.getGovernanceLocks("ref-2", governanceReadOptions());
    assert.equal(raw, null);
    const missing = await missingClient.getGovernanceLocksTyped(
      "ref-2",
      governanceReadOptions(),
    );
    assert.deepEqual(missing, {
      found: false,
      locks: {},
      referendum_id: "ref-2",
    });
  });

  test("getGovernanceLocksTyped rejects null, missing and malformed custody", async () => {
    const parseCustody = async (mutate) => {
      const fixture = cloneFixture(toriiFixtures.governance.locks);
      const [lock] = Object.values(fixture.locks.locks);
      mutate(lock);
      const client = new ToriiClient(BASE_URL, {
        fetchImpl: async () =>
          createResponse({
            status: 200,
            jsonData: fixture,
            headers: { "content-type": "application/json" },
          }),
      });
      return client.getGovernanceLocksTyped("ref-1", governanceReadOptions());
    };

    await assert.rejects(
      () => parseCustody((lock) => { lock.custody = null; }),
      /custody must be an object/u,
    );

    for (const fixture of [
      {
        label: "missing custody",
        mutate(lock) {
          delete lock.custody;
        },
        error: /must contain exactly.*custody/u,
      },
      {
        label: "missing custody field",
        mutate(lock) {
          delete lock.custody.bond_escrow_account;
        },
        error: /custody must contain exactly/u,
      },
      {
        label: "extra custody field",
        mutate(lock) {
          lock.custody.asset_id = lock.custody.asset_definition_id;
        },
        error: /custody must contain exactly/u,
      },
      {
        label: "wrong custody field type",
        mutate(lock) {
          lock.custody.escrowed = "true";
        },
        error: /custody\.escrowed must be a boolean/u,
      },
    ]) {
      await assert.rejects(
        () => parseCustody(fixture.mutate),
        fixture.error,
        fixture.label,
      );
    }
  });

  test("getGovernanceLocksTyped rejects noncanonical and numeric JSON quantities", async () => {
    for (const field of ["amount", "slashed"]) {
      for (const value of [
        1,
        "+1",
        "01",
        "1.0",
        "1.2300",
        "1amt",
        "1qty",
        " 1",
        "1 ",
        "-1",
        "9".repeat(155),
      ]) {
        const fixture = cloneFixture(toriiFixtures.governance.locks);
        const [lock] = Object.values(fixture.locks.locks);
        lock[field] = value;
        const client = new ToriiClient(BASE_URL, {
          fetchImpl: async () =>
            createResponse({
              status: 200,
              jsonData: fixture,
              headers: { "content-type": "application/json" },
            }),
        });
        await assert.rejects(
          () => client.getGovernanceLocksTyped("ref-1", governanceReadOptions()),
          /canonical non-negative Kotodama V1 quantity|canonical Kotodama V1 quantity/u,
          `${field} ${String(value)} must be rejected`,
        );
      }
    }
  });

  test("getGovernanceUnlockStatsTyped normalizes numeric fields", async () => {
    const fetchImpl = async () =>
      createResponse({
        status: 200,
        jsonData: cloneFixture(toriiFixtures.governance.unlockStats),
        headers: { "content-type": "application/json" },
      });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    const stats = await client.getGovernanceUnlockStatsTyped(governanceReadOptions());
    assert.equal(stats.height_current, 100);
    assert.equal(stats.expired_locks_now, 2);
    assert.equal(stats.referenda_with_expired, 1);
    assert.equal(stats.last_sweep_height, 95);
  });

  test("getGovernanceTallyTyped parses referendum votes for an exact selector", async () => {
    let capturedUrl;
    const fetchImpl = async (url) => {
      capturedUrl = url;
      return createResponse({
        status: 200,
        jsonData: cloneFixture(toriiFixtures.governance.tally),
        headers: { "content-type": "application/json" },
      });
    };
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    const tally = await client.getGovernanceTallyTyped("ref-1", governanceReadOptions());
    assert.equal(capturedUrl, `${BASE_URL}/v1/gov/tally/ref-1`);
    assert.deepEqual(tally, {
      found: true,
      referendum_id: "ref-1",
      tally: {
        referendum_id: "ref-1",
        evaluated_block_height: 42,
        evaluated_block_hash: "12".repeat(32),
        approve: 7,
        reject: 3,
        abstain: 1,
      },
    });
  });

  test("getGovernanceTallyTyped rejects empty tally payloads", async () => {
    const fetchImpl = async () =>
      createResponse({
        status: 200,
        jsonData: null,
        headers: { "content-type": "application/json" },
      });
    const client = new ToriiClient(BASE_URL, { fetchImpl });
    await assert.rejects(
      () => client.getGovernanceTallyTyped("ref-1", governanceReadOptions()),
      /governance tally endpoint returned no payload/,
    );
  });

  test("getGovernanceTallyTyped returns empty result for missing referendum", async () => {
    const missingClient = new ToriiClient(BASE_URL, {
      fetchImpl: async () => createResponse({ status: 404 }),
    });
    const raw = await missingClient.getGovernanceTally("ref-2", governanceReadOptions());
    assert.equal(raw, null);
    const missing = await missingClient.getGovernanceTallyTyped(
      "ref-2",
      governanceReadOptions(),
    );
    assert.deepEqual(missing, {
      found: false,
      referendum_id: "ref-2",
      tally: null,
    });
  });

  test("draftMinistryAgendaProposal normalizes the draft response payload", async () => {
    let capturedBody;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async (url, init) => {
        capturedBody = parseStrictLosslessIntegerJson(
          String(init.body),
          "ministry agenda proposal draft request",
        );
        assert.equal(url, `${BASE_URL}/v1/ministry/agenda/proposals/draft`);
        return createResponse({
          status: 200,
          jsonData: {
            ok: true,
            agenda_proposal_id: "AC-2026-001",
            authority: FIXTURE_ALICE_ID,
            tx_instructions: [
              { wire_id: "SubmitAgendaProposal", payload_hex: "aa55" },
            ],
            signable_transaction_b64: "AQID",
          },
          headers: { "content-type": "application/json" },
        });
      },
    });
    const proposal = {
      version: 1,
      proposal_id: "AC-2026-001",
      submitted_at_unix_ms: 18_446_744_073_709_551_615n,
      language: "en-US",
      action: "add-to-denylist",
      summary: {
        title: "Block malicious archive",
        motivation: "The archive carries a confirmed exploit.",
        expected_impact: "Clients will reject the malicious content.",
      },
      tags: ["malware"],
      targets: [{
        label: "archive",
        hash_family: "blake3-256",
        hash_hex: "11".repeat(32),
        reason: "Confirmed malicious payload",
      }],
      evidence: [{
        kind: "attachment",
        uri: "sorafs://evidence",
        digest_blake3_hex: "22".repeat(32),
      }],
      submitter: {
        name: "Ministry analyst",
        contact: "@analyst:example.org",
      },
    };
    const draft = await client.draftMinistryAgendaProposal({
      proposal,
      authority: FIXTURE_ALICE_ID,
    }, governanceReadOptions());

    const withOrdinaryObjectPrototypes = (value) => {
      if (Array.isArray(value)) return value.map(withOrdinaryObjectPrototypes);
      if (value !== null && typeof value === "object") {
        return Object.fromEntries(
          Object.entries(value).map(([key, nested]) => [
            key,
            withOrdinaryObjectPrototypes(nested),
          ]),
        );
      }
      return value;
    };
    assert.deepEqual(withOrdinaryObjectPrototypes(capturedBody), {
      proposal: {
        ...proposal,
        duplicates: [],
      },
      authority: FIXTURE_ALICE_ID,
    });
    assert.deepEqual(draft, {
      ok: true,
      agenda_proposal_id: "AC-2026-001",
      authority: FIXTURE_ALICE_ID,
      tx_instructions: [
        { wire_id: "SubmitAgendaProposal", payload_hex: "aa55" },
      ],
      signable_transaction_b64: "AQID",
    });
  });

  test("draftMinistryAgendaProposal rejects open or secret-bearing shapes before dispatch", async () => {
    let dispatched = false;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        dispatched = true;
        throw new Error("fetch should not run");
      },
    });
    const proposal = {
      version: 1,
      proposal_id: "AC-2026-001",
      submitted_at_unix_ms: 1n,
      language: "en",
      action: "add-to-denylist",
      summary: {
        title: "Block malicious archive",
        motivation: "Confirmed exploit",
        expected_impact: "Reject malicious content",
      },
      tags: ["malware"],
      targets: [{
        label: "archive",
        hash_family: "blake3-256",
        hash_hex: "11".repeat(32),
        reason: "Confirmed malicious payload",
      }],
      evidence: [{ kind: "url", uri: "https://evidence.example/case" }],
      submitter: { name: "Analyst", contact: "@analyst:example.org" },
    };

    await assert.rejects(
      () => client.draftMinistryAgendaProposal({
        proposal: { ...proposal, unexpected: true },
        authority: "i105-test-account",
      }),
      /unsupported fields: unexpected/,
    );
    await assert.rejects(
      () => client.draftMinistryAgendaProposal({
        proposal: {
          ...proposal,
          evidence: [{
            kind: "url",
            uri: "https://evidence.example/case",
            metadata: { privateKey: "secret" },
          }],
        },
        authority: "i105-test-account",
      }),
      /does not accept private-key fields/,
    );
    await assert.rejects(
      () => client.draftMinistryAgendaProposal({
        proposal,
        authority: " i105-test-account ",
      }),
      /surrounding whitespace/,
    );
    assert.equal(dispatched, false);
  });

  test("getMinistryAgendaProposal returns missing and persisted records", async () => {
    let call = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async (url) => {
        call += 1;
        assert.equal(url, `${BASE_URL}/v1/ministry/agenda/proposals/AC-2026-001`);
        if (call === 1) {
          return createResponse({
            status: 200,
            jsonData: {
              found: false,
              record: null,
            },
            headers: { "content-type": "application/json" },
          });
        }
        return createResponse({
          status: 200,
          jsonData: {
            found: true,
            record: {
              proposal: {
                proposal_id: "AC-2026-001",
                action: "add-to-denylist",
              },
              authority: FIXTURE_ALICE_ID,
              submitted_tx_hash_hex: "ab".repeat(32),
              submitted_height: 44,
            },
          },
          headers: { "content-type": "application/json" },
        });
      },
    });

    const missing = await client.getMinistryAgendaProposal(
      " AC-2026-001 ",
      governanceReadOptions(),
    );
    const found = await client.getMinistryAgendaProposal(
      "AC-2026-001",
      governanceReadOptions(),
    );

    assert.deepEqual(missing, {
      found: false,
      record: null,
    });
    assert.deepEqual(found, {
      found: true,
      record: {
        proposal: {
          proposal_id: "AC-2026-001",
          action: "add-to-denylist",
        },
        authority: FIXTURE_ALICE_ID,
        submitted_tx_hash_hex: "ab".repeat(32),
        submitted_height: 44,
      },
    });
  });

  test("governanceProposeDeployContract normalizes payloads", async () => {
    let capturedBody;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async (url, init) => {
        capturedBody = JSON.parse(init.body);
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.deployContractDraft),
          headers: { "content-type": "application/json" },
        });
      },
    });
    const result = await client.governanceProposeDeployContract(
      {
        proposalOperator: FIXTURE_ALICE_ID,
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        codeHash: `BlAkE2b32:0X${"1a".repeat(32)}`,
        abiHash: Buffer.alloc(32, 0xbb),
        abiVersion: 1,
        manifestProvenance: {
          signer: `ed25519:ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`,
          signature: `ed25519:${"22".repeat(64)}`,
        },
      },
      governanceBallotOptions(FIXTURE_ALICE_ID),
    );
    assert.equal(
      capturedBody.contract_address,
      "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    );
    assert.equal(capturedBody.proposal_operator, FIXTURE_ALICE_ID);
    assert.equal(capturedBody.code_hash, "1a".repeat(32));
    assert.equal(capturedBody.abi_hash, "bb".repeat(32));
    assert.equal(capturedBody.abi_version, 1);
    assert.equal(Object.hasOwn(capturedBody, "mode"), false);
    assert.equal(Object.hasOwn(capturedBody, "window"), false);
    assert.deepEqual(capturedBody.manifest_provenance, {
      signer: `ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX.toUpperCase()}`,
      signature: "22".repeat(64).toUpperCase(),
    });
    assert.equal(result.proposal_id, "cd".repeat(32));
    assert.equal(Object.hasOwn(result, "ok"), false);
    assert.deepEqual(result.tx_instructions, [
      {
wire_id: "iroha.instruction.v1::governance::ProposeDeployContract",
        payload_hex: "00",
      },
    ]);
  });

  test("governanceProposeDeployContract validates ML-DSA manifest signer keys before fetch", async () => {
    let capturedBody;
    let fetchCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async (_url, init) => {
        fetchCalls += 1;
        capturedBody = JSON.parse(init.body);
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.deployContractDraft),
          headers: { "content-type": "application/json" },
        });
      },
    });
    const base = {
      proposalOperator: FIXTURE_ALICE_ID,
      contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      codeHash: "aa".repeat(32),
      abiHash: "bb".repeat(32),
    };
    const proposeWithSigner = (signer) => client.governanceProposeDeployContract(
      {
        ...base,
        manifestProvenance: {
          signer,
          signature: "22".repeat(64),
        },
      },
      governanceBallotOptions(FIXTURE_ALICE_ID),
    );

    for (const [label, signer, errorPattern] of [
      ["one-byte", mlDsaManifestSigner(1), /expected 1952 bytes/u],
      ["short", mlDsaManifestSigner(1_951), /expected 1952 bytes/u],
      ["overlong", mlDsaManifestSigner(1_953), /expected 1952 bytes/u],
      ["all-zero", mlDsaManifestSigner(1_952, 0), /all-zero/u],
    ]) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () => proposeWithSigner(signer),
        errorPattern,
        `${label} ML-DSA signer must be rejected before fetch`,
      );
    }
    assert.equal(fetchCalls, 0);

    await proposeWithSigner(mlDsaManifestSigner(1_952));
    assert.equal(fetchCalls, 1);
    assert.equal(
      capturedBody.manifest_provenance.signer,
      `ee01a00f${"5A".repeat(1_952)}`,
    );
  });

  test("governanceProposeDeployContract rejects an operator distinct from canonical auth", async () => {
    let fetchCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("mismatched proposal reached transport");
      },
    });
    await assert.rejects(
      client.governanceProposeDeployContract(
        {
          proposalOperator: FIXTURE_BOB_ID,
          contractAddress:
            "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
          codeHash: "aa".repeat(32),
          abiHash: "bb".repeat(32),
        },
        governanceBallotOptions(FIXTURE_ALICE_ID),
      ),
      /canonicalAuth\.accountId must equal the exact proposalOperator/u,
    );
    assert.equal(fetchCalls, 0);
  });

  test("governanceProposeDeployContract rejects noncanonical draft responses", async () => {
    const request = {
      proposalOperator: FIXTURE_ALICE_ID,
      contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      codeHash: "11".repeat(32),
      abiHash: "22".repeat(32),
    };
    const canonical = cloneFixture(toriiFixtures.governance.deployContractDraft);
    const cases = [
      { ...canonical, ok: true },
      {
        ...canonical,
        tx_instructions: [{
          wire_id: "iroha.instruction.v1::governance::ProposeDeployContract",
        }],
      },
      {
        ...canonical,
        tx_instructions: [{
          wire_id: "ProposeDeployContract",
          payload_hex: "00",
        }],
      },
      {
        ...canonical,
        tx_instructions: [...canonical.tx_instructions, ...canonical.tx_instructions],
      },
      {
        ...canonical,
        proposal_id: canonical.proposal_id.toUpperCase(),
      },
      {
        ...canonical,
        proposal_id: `0x${canonical.proposal_id}`,
      },
      {
        ...canonical,
        tx_instructions: [{
          ...canonical.tx_instructions[0],
          payload_hex: "AA",
        }],
      },
      {
        ...canonical,
        tx_instructions: [{
          ...canonical.tx_instructions[0],
          payload_hex: "0x00",
        }],
      },
    ];
    for (const response of cases) {
      const client = new ToriiClient(BASE_URL, {
        fetchImpl: async () => createResponse({
          status: 200,
          jsonData: response,
          headers: { "content-type": "application/json" },
        }),
      });
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => client.governanceProposeDeployContract(
        request,
        governanceBallotOptions(FIXTURE_ALICE_ID),
      ));
    }
  });

  test("governance mutation declarations expose closed V1 request shapes", () => {
    const declarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
    const interfaceBody = (name) => {
      const match = declarations.match(
        new RegExp(`export interface ${name} \\{([\\s\\S]*?)\\n\\}`, "u"),
      );
      assert.ok(match, `missing ${name}`);
      return match[1];
    };
    const interfaceFields = (name) =>
      [...interfaceBody(name).matchAll(/^\s+([A-Za-z_][A-Za-z0-9_]*)\??:/gmu)]
        .map((match) => match[1])
        .sort();

    const deploy = interfaceBody("ToriiGovernanceDeployContractProposalRequest");
    assert.match(deploy, /proposalOperator: string;/u);
    assert.doesNotMatch(deploy, /\blimits\??:/u);
    assert.match(deploy, /abiVersion\?: 1;/u);
    assert.doesNotMatch(deploy, /\b(?:window|mode)\??:/u);
    assert.match(
      deploy,
      /manifestProvenance\?: ToriiGovernanceManifestProvenanceInput \| null;/u,
    );
    assert.doesNotMatch(deploy, /manifest_provenance/u);
    const storedDeploy = interfaceBody("ToriiGovernanceDeployContractProposal");
    assert.deepEqual(interfaceFields("ToriiGovernanceDeployContractProposal"), [
      "abi_hash",
      "abi_version",
      "code_hash",
      "contract_address",
      "manifest_provenance",
      "proposal_operator",
    ]);
    assert.match(storedDeploy, /abi_version: 1;/u);
    assert.match(
      storedDeploy,
      /manifest_provenance: ToriiGovernanceManifestProvenance \| null;/u,
    );
    assert.doesNotMatch(storedDeploy, /(?:code_hash_hex|abi_hash_hex)/u);
    assert.deepEqual(interfaceFields("ToriiGovernanceManifestProvenance"), [
      "signature",
      "signer",
    ]);
    const proposalKind = declarations.match(
      /export type ToriiGovernanceProposalKind =([\s\S]*?);\n\nexport interface ToriiGovernanceProposalRecord/u,
    );
    assert.ok(proposalKind, "missing closed ToriiGovernanceProposalKind union");
    for (const variant of [
      "DeployContract",
      "RuntimeUpgrade",
      "SccpRouteGovernance",
      "ValidationFeePolicy",
      "ValidationFeePayoutLifecycle",
      "MusubiRegistryGovernance",
      "SorafsProviderGovernance",
      "ContractLifecycleGovernance",
      "ContractEmergencyHold",
      "GlobalDataTriggerPermissionGovernance",
    ]) {
      assert.match(proposalKind[1], new RegExp(`variant: "${variant}"`, "u"));
    }
    assert.doesNotMatch(proposalKind[1], /\braw\b|variant: string/u);
    const proposalStatus = declarations.match(
      /export type ToriiGovernanceProposalStatus =([\s\S]*?);/u,
    );
    assert.ok(proposalStatus, "missing closed ToriiGovernanceProposalStatus union");
    assert.deepEqual(
      [...proposalStatus[1].matchAll(/"([A-Za-z]+)"/gu)].map((match) => match[1]),
      ["Proposed", "Rejected", "Enacted", "Superseded", "ExecutionFailed"],
    );
    assert.deepEqual(interfaceFields("ToriiGovernanceProposalRecord"), [
      "created_height",
      "kind",
      "proposer",
      "status",
    ]);
    assert.deepEqual(interfaceFields("ToriiGovernanceProposalDraftResponseV1"), [
      "proposal_id",
      "tx_instructions",
    ]);
    assert.deepEqual(interfaceFields("ToriiGovernanceProposalInstructionDraftV1"), [
      "payload_hex",
      "wire_id",
    ]);
    const provenance = interfaceBody("ToriiGovernanceManifestProvenanceInput");
    assert.deepEqual(
      [...provenance.matchAll(/^\s+([A-Za-z_][A-Za-z0-9_]*)\??:/gmu)]
        .map((match) => match[1])
        .sort(),
      ["signature", "signer"],
    );
    const publicInputs = interfaceBody("GovernanceZkBallotPublicInputs");
    assert.deepEqual(
      [...publicInputs.matchAll(/^\s+([A-Za-z_][A-Za-z0-9_]*)\??:/gmu)]
        .map((match) => match[1])
        .sort(),
      ["amount", "direction", "duration_blocks", "nullifier", "owner", "root_hint"],
    );
    const zkBallotV1 = interfaceBody("ToriiGovernanceZkBallotV1Request");
    assert.match(zkBallotV1, /^\s+envelope:/mu);
    assert.doesNotMatch(zkBallotV1, /envelope(?:B64|_b64)/u);
    assert.deepEqual(interfaceFields("ToriiGovernanceBallotProof"), [
      "amount",
      "backend",
      "direction",
      "durationBlocks",
      "envelopeBytes",
      "nullifier",
      "owner",
      "rootHint",
    ]);
  });

  test("legacy governance ZK ballot HTTP surface is absent", () => {
    const declarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
    const source = readFileSync(new URL("../src/toriiClient.js", import.meta.url), "utf8");
    const client = new ToriiClient(BASE_URL);

    assert.equal(
      Object.getOwnPropertyDescriptor(ToriiClient.prototype, "governanceSubmitZkBallot"),
      undefined,
    );
    assert.equal(client.governanceSubmitZkBallot, undefined);
    assert.doesNotMatch(source, /\basync governanceSubmitZkBallot\(/u);
    assert.doesNotMatch(source, /["']\/v1\/gov\/ballots\/zk["']/u);
    assert.doesNotMatch(declarations, /\bgovernanceSubmitZkBallot\(/u);
    assert.doesNotMatch(declarations, /\bToriiGovernanceZkBallotRequest\b/u);
    assert.doesNotMatch(declarations, /\bToriiGovernanceZkPublicInputs\b/u);
  });

  test("governanceProposeDeployContract accepts byte-array hashes", async () => {
    let capturedBody;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async (_url, init) => {
        capturedBody = JSON.parse(init.body);
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.deployContractDraft),
          headers: { "content-type": "application/json" },
        });
      },
    });

    await client.governanceProposeDeployContract(
      {
        proposalOperator: FIXTURE_ALICE_ID,
        contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
        codeHash: Array.from(Buffer.alloc(32, 0x1a)),
        abiHash: Array.from(Buffer.alloc(32, 0xbb)),
      },
      governanceBallotOptions(FIXTURE_ALICE_ID),
    );

    assert.equal(capturedBody.code_hash, "1a".repeat(32));
    assert.equal(capturedBody.abi_hash, "bb".repeat(32));
    assert.equal(capturedBody.abi_version, 1);
  });

  test("governanceProposeDeployContract accepts only numeric ABI V1", async () => {
    let fetchCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        fetchCalls += 1;
        return createResponse({ status: 204 });
      },
    });
    const base = {
      proposalOperator: FIXTURE_ALICE_ID,
      contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      codeHash: "1a".repeat(32),
      abiHash: "bb".repeat(32),
    };

    for (const abiVersion of ["1", "2", "01", " 1", "1 ", 0, 2, 1n, null]) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () => client.governanceProposeDeployContract(
          { ...base, abiVersion },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
        /abiVersion must be exactly 1/u,
      );
    }
    assert.equal(fetchCalls, 0);
  });

  test("governanceProposeDeployContract rejects undeclared hash aliases before fetch", async () => {
    let fetchCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        fetchCalls += 1;
        return createResponse({ status: 204 });
      },
    });
    const hash = "1a".repeat(32);
    const base = {
      proposalOperator: FIXTURE_ALICE_ID,
      contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      abiHash: "bb".repeat(32),
    };
    for (const codeHash of [
      `:${hash}`,
      ` ${hash}`,
      `${hash} `,
      `blake2b32:${hash}:ignored`,
      `sha256:${hash}`,
    ]) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () => client.governanceProposeDeployContract(
          { ...base, codeHash },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
        /32-byte hex string|surrounding whitespace/u,
      );
    }
    assert.equal(fetchCalls, 0);
  });

  test("governanceProposeDeployContract rejects retired lifecycle controls", async () => {
    let fetchCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("retired lifecycle control reached transport");
      },
    });
    const base = {
      proposalOperator: FIXTURE_ALICE_ID,
      contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      codeHash: `0x${"1a".repeat(32)}`,
      abiHash: Buffer.alloc(32, 0xbb),
    };
    for (const [field, value] of [
      ["window", { lower: 10, upper: 20 }],
      ["mode", "Plain"],
      ["votingMode", "Zk"],
    ]) {
      await assert.rejects(
        () => client.governanceProposeDeployContract(
          { ...base, [field]: value },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
        new RegExp(`unsupported fields: ${field}`, "u"),
      );
    }
    assert.equal(fetchCalls, 0);
  });

  test("governanceProposeDeployContract rejects non-byte hash arrays", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.deployContractDraft),
          headers: { "content-type": "application/json" },
        }),
    });

    await assert.rejects(
      () =>
        client.governanceProposeDeployContract(
          {
            proposalOperator: FIXTURE_ALICE_ID,
            contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            codeHash: [256],
            abiHash: Array.from(Buffer.alloc(32, 0xbb)),
          },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      (error) =>
        error?.name === "ValidationError" &&
        /governanceProposeDeployContract\.codeHash\[0\]/i.test(error.message),
    );
  });

  test("governanceSubmitPlainBallot normalizes amount and direction", async () => {
    let capturedBody;
    let capturedInit;
    let fetchCalls = 0;
    const client = governanceBallotClient({
      fetchImpl: async (url, init) => {
        fetchCalls += 1;
        capturedInit = init;
        capturedBody = JSON.parse(init.body);
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.plainBallotDraftResponse),
          headers: { "content-type": "application/json" },
        });
      },
    });
    const ballot = await client.governanceSubmitPlainBallot(
      {
        authority: FIXTURE_ALICE_ID,
        networkId: GOVERNANCE_NETWORK_ID,
        referendumId: "ref-plain",
        owner: FIXTURE_ALICE_ID,
        amount: 500n,
        durationBlocks: "600",
        direction: "Nay",
      },
      governanceBallotOptions(FIXTURE_ALICE_ID),
    );
    assert.equal(capturedBody.amount, "500");
    assert.equal(capturedBody.duration_blocks, "600");
    assert.equal(capturedBody.direction, "Nay");
    assert.equal(capturedBody.network_id, GOVERNANCE_NETWORK_ID.literal);
    assert.equal(capturedBody.chain_id, undefined);
    assert.equal(capturedInit.redirect, "error");
    assert.equal(fetchCalls, 1);
    assert.equal(ballot.drafted, true);
    assert.equal(ballot.accepted, undefined);
  });

  test("governance ballot drafts reject noncanonical response contracts", async () => {
    const responses = [
      {
        ok: false,
        accepted: false,
        reason: "invalid ballot",
        tx_instructions: [],
      },
      {
        drafted: true,
        tx_instructions: [{ wire_id: "Cast ZkBallot", payload_hex: "00" }],
      },
      {
        drafted: true,
        tx_instructions: [{ wire_id: "CastZkBallot", payload_hex: "AA" }],
      },
    ];
    for (const jsonData of responses) {
      const client = governanceBallotClient({
        fetchImpl: async () => createResponse({
          status: 200,
          jsonData,
          headers: { "content-type": "application/json" },
        }),
      });

      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () => client.governanceSubmitPlainBallot(
          {
            authority: FIXTURE_ALICE_ID,
            networkId: GOVERNANCE_NETWORK_ID,
            referendumId: "ref-plain",
            owner: FIXTURE_ALICE_ID,
            amount: "1",
            durationBlocks: 1,
            direction: "Aye",
          },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
        /unsupported fields|drafted|whitespace|lowercase/u,
      );
    }
  });

  test("governance ballots reject retired identity keys and unbound authentication", async () => {
    let fetchCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("invalid ballot identity reached fetch");
      },
    });
    const payload = {
      authority: FIXTURE_ALICE_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      referendumId: "ref-plain",
      owner: FIXTURE_ALICE_ID,
      amount: "1",
      durationBlocks: 1,
      direction: "Aye",
    };
    await assert.rejects(
      () => client.governanceSubmitPlainBallot(payload),
      /canonicalAuth is required/u,
    );
    await assert.rejects(
      () =>
        client.governanceSubmitPlainBallot(
          payload,
          governanceBallotOptions(FIXTURE_BOB_ID),
        ),
      /canonicalAuth\.accountId must equal the exact payload authority/u,
    );
    await assert.rejects(
      () =>
        client.governanceSubmitPlainBallot(
          { ...payload, chainId: "same-label" },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      /unsupported fields: chainId/u,
    );
    assert.equal(fetchCalls, 0);
  });

  test("governance ballots reject a different genesis under the same display label", async () => {
    let fetchCalls = 0;
    const foreignBytes = GOVERNANCE_NETWORK_ID.toBytes();
    foreignBytes[foreignBytes.length - 1] ^= 0x02;
    const foreignNetworkId = NetworkId.fromBytes(foreignBytes);
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("foreign-network ballot reached fetch");
      },
      localSigningContext: new LocalSigningContext(foreignNetworkId, 753),
    });
    await assert.rejects(
      () =>
        client.governanceSubmitPlainBallot(
          {
            authority: FIXTURE_ALICE_ID,
            networkId: GOVERNANCE_NETWORK_ID,
            referendumId: "same-label-different-genesis",
            owner: FIXTURE_ALICE_ID,
            amount: "1",
            durationBlocks: 1,
            direction: "Aye",
          },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      /networkId must equal the client's exact LocalSigningContext/u,
    );
    assert.equal(fetchCalls, 0);
  });

  test("governance ballot authentication is one-shot on redirect responses", async () => {
    let fetchCalls = 0;
    const client = governanceBallotClient({
      fetchImpl: async (_url, init) => {
        fetchCalls += 1;
        assert.equal(init.redirect, "error");
        return createResponse({ status: 307 });
      },
      maxRetries: 5,
    });
    await assert.rejects(
      () =>
        client.governanceSubmitPlainBallot(
          {
            authority: FIXTURE_ALICE_ID,
            networkId: GOVERNANCE_NETWORK_ID,
            referendumId: "ref-plain",
            owner: FIXTURE_ALICE_ID,
            amount: "1",
            durationBlocks: 1,
            direction: "Aye",
          },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      /HTTP 307/u,
    );
    assert.equal(fetchCalls, 1);
  });

  test("governance ballots reject noncanonical direction aliases before fetch", async () => {
    let fetchCalls = 0;
    const client = governanceBallotClient({
      fetchImpl: async () => {
        fetchCalls += 1;
        return createResponse({ status: 204 });
      },
    });
    const base = {
      authority: FIXTURE_ALICE_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      referendumId: "ref-plain",
      owner: FIXTURE_ALICE_ID,
      amount: "500",
      durationBlocks: "600",
    };
    for (const direction of ["aye", "nay", "abstain", " Aye", "Aye ", "Approve", 1]) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () => client.governanceSubmitPlainBallot({ ...base, direction }),
        /must be one of Aye, Nay, or Abstain|surrounding whitespace|must be a string/u,
      );
    }
    assert.equal(fetchCalls, 0);
  });

  test("governance mutations reject private-key aliases and unknown fields before fetch", async () => {
    let fetchCalls = 0;
    const client = governanceBallotClient({
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("fetch must not run for an invalid governance mutation");
      },
    });
    const proofRequest = {
      authority: FIXTURE_BOB_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      electionId: "ref-zk",
      ballot: {
        backend: "pipa-r/pasta",
        envelopeBytes: "AAE=",
      },
    };
    const routes = [
      {
        name: "deploy-contract",
        payload: {
          proposalOperator: FIXTURE_ALICE_ID,
          contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
          codeHash: "11".repeat(32),
          abiHash: "22".repeat(32),
        },
        invoke: (payload) => client.governanceProposeDeployContract(
          payload,
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      },
      {
        name: "plain ballot",
        payload: {
          authority: FIXTURE_ALICE_ID,
          networkId: GOVERNANCE_NETWORK_ID,
          referendumId: "ref-plain",
          owner: FIXTURE_ALICE_ID,
          amount: "42",
          durationBlocks: 128,
          direction: "Aye",
        },
        invoke: (payload) => client.governanceSubmitPlainBallot(
          payload,
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      },
      {
        name: "zk-v1 ballot",
        payload: {
          authority: FIXTURE_BOB_ID,
          networkId: GOVERNANCE_NETWORK_ID,
          electionId: "ref-zk",
          backend: "pipa-r/pasta",
          envelope: [4, 5],
        },
        invoke: (payload) => client.governanceSubmitZkBallotV1(
          payload,
          governanceBallotOptions(FIXTURE_BOB_ID),
        ),
      },
      {
        name: "zk-v1 ballot proof",
        payload: proofRequest,
        invoke: (payload) => client.governanceSubmitZkBallotProofV1(
          payload,
          governanceBallotOptions(FIXTURE_BOB_ID),
        ),
      },
    ];
    const privateKeyAliases = [
      "private_key",
      "privateKey",
      "private_key_hex",
      "privateKeyHex",
      "private_key_bytes",
      "privateKeyBytes",
      "private_key_seed",
      "privateKeySeed",
      "private_key_multihash",
      "privateKeyMultihash",
      "private_key_algorithm",
      "privateKeyAlgorithm",
    ];

    for (const route of routes) {
      for (const alias of privateKeyAliases) {
        // eslint-disable-next-line no-await-in-loop
        await assert.rejects(
          () => route.invoke({ ...route.payload, [alias]: "attacker-secret" }),
          (error) => {
            assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT, route.name);
            assert.match(String(error?.message), /does not accept private-key fields/u);
            assert.match(String(error?.message), new RegExp(alias, "u"));
            return true;
          },
        );
        // eslint-disable-next-line no-await-in-loop
        await assert.rejects(
          () =>
            route.invoke({
              ...route.payload,
              nested: { items: [{ [alias]: "attacker-secret" }] },
            }),
          (error) => {
            assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT, route.name);
            assert.match(String(error?.message), /does not accept private-key fields/u);
            assert.match(String(error?.message), new RegExp(alias, "u"));
            return true;
          },
        );
      }
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () => route.invoke({ ...route.payload, attacker_field: true }),
        (error) => {
          assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT, route.name);
          assert.match(String(error?.message), /unsupported fields: attacker_field/u);
          return true;
        },
      );
    }

    for (const alias of privateKeyAliases) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () =>
          client.governanceSubmitZkBallotProofV1({
            ...proofRequest,
            ballot: { ...proofRequest.ballot, [alias]: "attacker-secret" },
          }),
        (error) => {
          assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT);
          assert.match(String(error?.message), /ballot does not accept private-key fields/u);
          assert.match(String(error?.message), new RegExp(alias, "u"));
          return true;
        },
      );
    }
    await assert.rejects(
      () =>
        client.governanceSubmitZkBallotProofV1({
          ...proofRequest,
          ballot: { ...proofRequest.ballot, attacker_field: true },
        }),
      /unsupported fields: attacker_field/u,
    );
    await assert.rejects(
      () =>
        client.governanceProposeDeployContract(
          {
            proposalOperator: FIXTURE_ALICE_ID,
            contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            codeHash: "11".repeat(32),
            abiHash: "22".repeat(32),
            limits: { maxTx: 5 },
          },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      /unsupported fields: limits/u,
    );
    await assert.rejects(
      () =>
        client.governanceProposeDeployContract(
          {
            proposalOperator: FIXTURE_ALICE_ID,
            contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            codeHash: "11".repeat(32),
            abiHash: "22".repeat(32),
            manifestProvenance: {
              signer: `ed25519:ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`,
              signature: `ed25519:${"22".repeat(64)}`,
              algorithm: "ed25519",
            },
          },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      /unsupported fields: algorithm/u,
    );
    assert.equal(fetchCalls, 0);
  });

  test("governance mutation DTOs reject alternate keys instead of shadowing canonical fields", async () => {
    let fetchCalls = 0;
    const client = governanceBallotClient({
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("alternate governance DTO key reached transport");
      },
    });
    const deploy = {
      proposalOperator: FIXTURE_ALICE_ID,
      contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
      codeHash: "11".repeat(32),
      abiHash: "22".repeat(32),
      abiVersion: 1,
      manifestProvenance: {
        signer: `ed25519:ed0120${SEED_11_ED25519_PUBLIC_KEY_HEX}`,
        signature: `ed25519:${"22".repeat(64)}`,
      },
    };
    const plain = {
      authority: FIXTURE_ALICE_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      referendumId: "ref-plain",
      owner: FIXTURE_ALICE_ID,
      amount: "42",
      durationBlocks: 128,
      direction: "Aye",
    };
    const publicInputs = {
      rootHint: "44".repeat(32),
      owner: SAMPLE_ACCOUNT_FORMS.i105,
      amount: "42",
      durationBlocks: 128,
      nullifier: "55".repeat(32),
    };
    const zkV1 = {
      authority: FIXTURE_BOB_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      electionId: "ref-zk",
      backend: "pipa-r/pasta",
      envelope: [4, 5],
      ...publicInputs,
    };
    const ballot = {
      backend: "pipa-r/pasta",
      envelopeBytes: "AAE=",
      ...publicInputs,
    };
    const proofRequest = {
      authority: FIXTURE_BOB_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      electionId: "ref-zk",
      ballot,
    };

    const topLevelCases = [
      ...[
        "contract_address",
        "contract_alias",
        "abi_version",
        "code_hash",
        "abi_hash",
        "manifest_provenance",
      ].map((alias) => [
        alias,
        () => client.governanceProposeDeployContract(
          { ...deploy, [alias]: "shadow" },
          governanceBallotOptions(FIXTURE_ALICE_ID),
        ),
      ]),
      ...[
        "chain_id",
        "genesis_hash",
        "genesisHash",
        "referendum_id",
        "duration_blocks",
      ].map((alias) => [
          alias,
          () => client.governanceSubmitPlainBallot({ ...plain, [alias]: "shadow" }),
        ]),
      ...[
        "chain_id",
        "genesis_hash",
        "genesisHash",
        "election_id",
        "envelope_b64",
        "envelopeB64",
        "root_hint",
        "duration_blocks",
        "root_hint_hex",
        "rootHintHex",
        "nullifier_hex",
        "nullifierHex",
      ].map((alias) => [
        alias,
        () => client.governanceSubmitZkBallotV1({ ...zkV1, [alias]: "shadow" }),
      ]),
      ...["chain_id", "genesis_hash", "genesisHash", "election_id"].map(
        (alias) => [
          alias,
          () => client.governanceSubmitZkBallotProofV1({
            ...proofRequest,
            [alias]: "shadow",
          }),
        ],
      ),
    ];
    for (const [alias, invoke] of topLevelCases) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(invoke, (error) => {
        assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT, alias);
        assert.match(String(error?.message), new RegExp(alias, "u"));
        return true;
      });
    }

    for (const alias of [
      "envelope_bytes",
      "root_hint",
      "duration_blocks",
      "root_hint_hex",
      "rootHintHex",
      "nullifier_hex",
      "nullifierHex",
    ]) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () =>
          client.governanceSubmitZkBallotProofV1({
            ...proofRequest,
            ballot: { ...ballot, [alias]: "shadow" },
          }),
        (error) => {
          assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT, alias);
          assert.match(String(error?.message), new RegExp(alias, "u"));
          return true;
        },
      );
    }
    assert.equal(fetchCalls, 0);
  });

  test("governanceSubmitPlainBallot dispatches zero as a canonical decimal string", async () => {
    let capturedBody;
    let fetchCalls = 0;
    const client = governanceBallotClient({
      fetchImpl: async (_url, init) => {
        fetchCalls += 1;
        capturedBody = JSON.parse(init.body);
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.plainBallotDraftResponse),
          headers: { "content-type": "application/json" },
        });
      },
    });

    await client.governanceSubmitPlainBallot(
      {
        authority: FIXTURE_ALICE_ID,
        networkId: GOVERNANCE_NETWORK_ID,
        referendumId: "ref-zero",
        owner: FIXTURE_ALICE_ID,
        amount: "1",
        durationBlocks: 0,
        direction: "Abstain",
      },
      governanceBallotOptions(FIXTURE_ALICE_ID),
    );

    assert.equal(fetchCalls, 1);
    assert.equal(capturedBody.duration_blocks, "0");
  });

  test("governanceSubmitPlainBallot accepts canonical fractional Quantity amounts", async () => {
    let capturedBody;
    const client = governanceBallotClient({
      fetchImpl: async (_url, init) => {
        capturedBody = JSON.parse(init.body);
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.plainBallotDraftResponse),
          headers: { "content-type": "application/json" },
        });
      },
    });
    await client.governanceSubmitPlainBallot(
      {
        authority: FIXTURE_ALICE_ID,
        networkId: GOVERNANCE_NETWORK_ID,
        referendumId: "ref-plain-decimal",
        owner: FIXTURE_ALICE_ID,
        amount: "12.5",
        durationBlocks: 1,
        direction: "Aye",
      },
      governanceBallotOptions(FIXTURE_ALICE_ID),
    );
    assert.equal(capturedBody.amount, "12.5");
  });

  test("governanceSubmitPlainBallot enforces canonical lossless Quantity input", async () => {
    let fetchCalls = 0;
    let capturedBody;
    const client = governanceBallotClient({
      fetchImpl: async (_url, init) => {
        fetchCalls += 1;
        capturedBody = JSON.parse(init.body);
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.plainBallotDraftResponse),
          headers: { "content-type": "application/json" },
        });
      },
    });
    const maximumAmount = (1n << 511n) - 1n;
    const payload = {
      authority: FIXTURE_ALICE_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      referendumId: "ref-plain-bounds",
      owner: FIXTURE_ALICE_ID,
      durationBlocks: 1,
      direction: "Aye",
    };

    await client.governanceSubmitPlainBallot(
      { ...payload, amount: maximumAmount },
      governanceBallotOptions(FIXTURE_ALICE_ID),
    );
    assert.equal(capturedBody.amount, maximumAmount.toString());
    assert.equal(fetchCalls, 1);

    await assert.rejects(
      () => client.governanceSubmitPlainBallot({ ...payload, amount: 1n << 511n }),
      /mantissa_overflow/u,
    );
    for (const amount of [
      1,
      "+1",
      "01",
      "1.0",
      "1amt",
      "1qty",
      " 1",
      "-1",
      "1".repeat(100_000),
    ]) {
      await assert.rejects(
        () => client.governanceSubmitPlainBallot({ ...payload, amount }),
        /canonical|JavaScript numbers are rejected|mantissa_overflow/u,
        `amount ${String(amount).slice(0, 32)} must be rejected`,
      );
    }
    assert.equal(fetchCalls, 1);
  });

  test("governanceSubmitPlainBallot forwards AbortSignal to fetch", async () => {
    let observedSignal;
    const client = governanceBallotClient({
      fetchImpl: async (url, init) => {
        observedSignal = init?.signal;
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.plainBallotDraftResponse),
          headers: { "content-type": "application/json" },
        });
      },
    });
    const controller = new AbortController();
    await client.governanceSubmitPlainBallot(
      {
        authority: FIXTURE_ALICE_ID,
        networkId: GOVERNANCE_NETWORK_ID,
        referendumId: "ref-plain",
        owner: FIXTURE_ALICE_ID,
        amount: "5000",
        durationBlocks: 1_000,
        direction: "Aye",
      },
      governanceBallotOptions(FIXTURE_ALICE_ID, { signal: controller.signal }),
    );
    assertRequestSignal(observedSignal, controller.signal);
  });

  test("protected namespace helpers preserve exact tokens and support AbortSignal", async () => {
    const captures = [];
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async (url, init = {}) => {
        captures.push({ url, init });
        const payload = init.method === "POST"
          ? toriiFixtures.governance.protectedNamespacesApply
          : toriiFixtures.governance.protectedNamespacesGet;
        return createResponse({
          status: 200,
          jsonData: cloneFixture(payload),
          headers: { "content-type": "application/json" },
        });
      },
    });
    const controller = new AbortController();
    const applyResponse = await client.setProtectedNamespaces(
      ["apps", "system"],
      { signal: controller.signal },
    );
    assert.equal(captures[0].url, `${BASE_URL}/v1/gov/protected-namespaces`);
    assert.equal(captures[0].init.method, "POST");
    assertRequestSignal(captures[0].init.signal, controller.signal);
    assert.deepEqual(JSON.parse(String(captures[0].init.body)), {
      namespaces: ["apps", "system"],
    });
    assert.equal(applyResponse.ok, true);
    assert.equal(applyResponse.applied, 2);

    const getResponse = await client.getProtectedNamespaces(
      governanceReadOptions({ signal: controller.signal }),
    );
    assert.equal(captures[1].url, `${BASE_URL}/v1/gov/protected-namespaces`);
    assert.equal(captures[1].init.method, "GET");
    assertRequestSignal(captures[1].init.signal, controller.signal);
    assert.equal(getResponse.found, true);
    assert.deepEqual(getResponse.namespaces, ["apps", "system"]);
  });

  test("protected namespace helpers validate options", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not run");
      },
    });
    await assert.rejects(
      () => client.setProtectedNamespaces(["apps"], 123),
      /setProtectedNamespaces options must be an object/,
    );
    await assert.rejects(
      () => client.setProtectedNamespaces(["apps"], { signal: "oops" }),
      /setProtectedNamespaces options\.signal must be an AbortSignal/,
    );
    await assert.rejects(
      () => client.getProtectedNamespaces(123),
      /getProtectedNamespaces options must be an object/,
    );
    for (const invalid of ["", " apps", "apps ", "app space", "apps\t", "\u0000apps", "åpps"]) {
      await assert.rejects(
        () => client.setProtectedNamespaces([invalid]),
        /namespaces\[0\]/,
      );
    }
  });

  test("governance helpers reject unsupported option keys", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not be invoked for option validation");
      },
    });
    const ballotPayload = {
      authority: FIXTURE_ALICE_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      referendumId: "ref-1",
      owner: FIXTURE_ALICE_ID,
      amount: "10",
      durationBlocks: 1,
      direction: "Aye",
    };
    await assert.rejects(
      () => client.governanceSubmitPlainBallot(ballotPayload, { unexpected: 1 }),
      /governanceSubmitPlainBallot options contains unsupported fields: unexpected/,
    );
  });

  test("governanceProposeDeployContract rejects invalid signal options", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("should not fetch when signal is invalid");
      },
    });
    await assert.rejects(
      () =>
        client.governanceProposeDeployContract(
          {
            proposalOperator: FIXTURE_ALICE_ID,
            contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
            codeHash: "11".repeat(32),
            abiHash: Buffer.alloc(32, 0xaa),
            abiVersion: 1,
          },
          // @ts-expect-error: exercised to assert runtime validation.
          governanceBallotOptions(FIXTURE_ALICE_ID, { signal: {} }),
        ),
      /governanceProposeDeployContract options\.signal must be an AbortSignal/,
    );
  });

  test("governance ZK-v1 routes encode envelopes and hints", async () => {
    const calls = [];
    const client = governanceBallotClient({
      fetchImpl: async (url, init) => {
        calls.push({ url, body: JSON.parse(init.body) });
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.zkBallotDraftResponse),
          headers: { "content-type": "application/json" },
        });
      },
    });
    const zkV1Result = await client.governanceSubmitZkBallotV1(
      {
        authority: FIXTURE_BOB_ID,
        networkId: GOVERNANCE_NETWORK_ID,
        electionId: "ref-zk",
        backend: "pipa-r/pasta",
        envelope: [4, 5],
        rootHint: `blake2b32:${"Ab".repeat(32)}`,
        owner: SAMPLE_ACCOUNT_FORMS.i105,
        amount: "18446744073709551616.25",
        durationBlocks: 0,
        direction: "Aye",
        nullifier: Buffer.alloc(32, 0xff),
      },
      governanceBallotOptions(FIXTURE_BOB_ID),
    );
    assert.equal(calls[0].url, `${BASE_URL}/v1/gov/ballots/zk-v1`);
    assert.equal(calls[0].body.envelope_b64, "BAU=");
    assert.equal(calls[0].body.root_hint, "ab".repeat(32));
    assert.equal(calls[0].body.amount, "18446744073709551616.25");
    assert.equal(calls[0].body.duration_blocks, 0);
    assert.equal(calls[0].body.nullifier, "ff".repeat(32));
    assert.equal(zkV1Result.drafted, true);
    assert.equal(zkV1Result.accepted, undefined);

    const zkProofResult = await client.governanceSubmitZkBallotProofV1(
      {
        authority: FIXTURE_BOB_ID,
        networkId: GOVERNANCE_NETWORK_ID,
        electionId: "ref-zk",
        ballot: {
          backend: "pipa-r/pasta",
          envelopeBytes: "AAE=",
          rootHint: `blake2b32:${"Cc".repeat(32)}`,
          nullifier: `0x${"DD".repeat(32)}`,
          owner: SAMPLE_ACCOUNT_FORMS.i105,
          amount: "18446744073709551616.25",
          durationBlocks: 0,
          direction: "Nay",
        },
      },
      governanceBallotOptions(FIXTURE_BOB_ID),
    );
    assert.equal(calls[1].url, `${BASE_URL}/v1/gov/ballots/zk-v1/ballot-proof`);
    assert.equal(calls[1].body.ballot.root_hint, "cc".repeat(32));
    assert.equal(calls[1].body.ballot.nullifier, "dd".repeat(32));
    assert.equal(calls[1].body.ballot.amount, "18446744073709551616.25");
    assert.equal(calls[1].body.ballot.duration_blocks, 0);
    assert.equal(calls[1].body.ballot.direction, "Nay");
    assert.equal(zkProofResult.drafted, true);
  });

  test("governance ZK-v1 routes emit full-u64 duration tokens losslessly", async () => {
    const bodies = [];
    const client = governanceBallotClient({
      fetchImpl: async (_url, init) => {
        bodies.push(String(init.body));
        return createResponse({
          status: 200,
          jsonData: cloneFixture(toriiFixtures.governance.zkBallotDraftResponse),
          headers: { "content-type": "application/json" },
        });
      },
    });
    const maximum = (1n << 64n) - 1n;
    const lock = {
      owner: SAMPLE_ACCOUNT_FORMS.i105,
      amount: "42",
      durationBlocks: maximum,
    };
    await client.governanceSubmitZkBallotV1(
      {
        authority: FIXTURE_BOB_ID,
        networkId: GOVERNANCE_NETWORK_ID,
        electionId: "ref-zk",
        backend: "pipa-r/pasta",
        envelope: [1, 2, 3],
        owner: lock.owner,
        amount: lock.amount,
        durationBlocks: maximum,
      },
      governanceBallotOptions(FIXTURE_BOB_ID),
    );
    await client.governanceSubmitZkBallotProofV1(
      {
        authority: FIXTURE_BOB_ID,
        networkId: GOVERNANCE_NETWORK_ID,
        electionId: "ref-zk",
        ballot: {
          backend: "pipa-r/pasta",
          envelopeBytes: "AQID",
          ...lock,
        },
      },
      governanceBallotOptions(FIXTURE_BOB_ID),
    );

    assert.equal(bodies.length, 2);
    for (const [index, body] of bodies.entries()) {
      assert.match(body, /"duration_blocks":18446744073709551615/u);
      const decoded = parseStrictLosslessIntegerJson(body, `governance body ${index}`);
      const duration = decoded.ballot?.duration_blocks ?? decoded.duration_blocks;
      assert.equal(duration, maximum);
    }
  });

  test("governance ZK-v1 lock hints reject noncanonical Quantity amounts", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not run");
      },
    });
    for (const amount of [
      1,
      "+1",
      "01",
      "1.0",
      "1.2300",
      "1amt",
      "1qty",
      " 1",
      "1 ",
      "-1",
      "9".repeat(155),
    ]) {
      await assert.rejects(
        () =>
          client.governanceSubmitZkBallotV1({
            authority: FIXTURE_BOB_ID,
            networkId: GOVERNANCE_NETWORK_ID,
            electionId: "ref-zk",
            backend: "pipa-r/pasta",
            envelope: [4, 5],
            owner: SAMPLE_ACCOUNT_FORMS.i105,
            amount,
            durationBlocks: 128,
          }),
        /canonical|JavaScript numbers are rejected/u,
        `V1 amount ${String(amount)} must be rejected`,
      );
      await assert.rejects(
        () =>
          client.governanceSubmitZkBallotProofV1({
            authority: FIXTURE_BOB_ID,
            networkId: GOVERNANCE_NETWORK_ID,
            electionId: "ref-zk",
            ballot: {
              backend: "pipa-r/pasta",
              envelopeBytes: "AAE=",
              owner: SAMPLE_ACCOUNT_FORMS.i105,
              amount,
              durationBlocks: 128,
            },
          }),
        /canonical|JavaScript numbers are rejected/u,
        `BallotProof amount ${String(amount)} must be rejected`,
      );
    }
  });

  test("governanceSubmitZkBallotV1 rejects partial lock hints", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not run");
      },
    });
    await assert.rejects(
      () =>
        client.governanceSubmitZkBallotV1({
          authority: FIXTURE_BOB_ID,
          networkId: GOVERNANCE_NETWORK_ID,
          electionId: "ref-zk",
          backend: "pipa-r/pasta",
          envelope: [4, 5],
          owner: SAMPLE_ACCOUNT_FORMS.i105,
        }),
      (error) => {
        assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT);
        assert.match(String(error?.message), /owner, amount, and durationBlocks/i);
        return true;
      },
    );
  });

  test("governanceSubmitZkBallotV1 rejects noncanonical owner", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not run");
      },
    });
    await assert.rejects(
      () =>
        client.governanceSubmitZkBallotV1({
          authority: FIXTURE_BOB_ID,
          networkId: GOVERNANCE_NETWORK_ID,
          electionId: "ref-zk",
          backend: "pipa-r/pasta",
          envelope: [4, 5],
          owner: SAMPLE_ACCOUNT_FORMS.malformedI105,
          amount: "42",
          durationBlocks: 128,
        }),
      (error) => {
        assert.equal(error?.code, ValidationErrorCode.INVALID_ACCOUNT_ID);
        assert.match(String(error?.message), /canonical .*i105 account id/i);
        return true;
      },
    );
  });

  test("governanceSubmitZkBallotV1 rejects invalid hex hints", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not run");
      },
    });
    await assert.rejects(
      () =>
        client.governanceSubmitZkBallotV1({
          authority: FIXTURE_BOB_ID,
          networkId: GOVERNANCE_NETWORK_ID,
          electionId: "ref-zk",
          backend: "pipa-r/pasta",
          envelope: [4, 5],
          rootHint: "not-hex",
        }),
      (error) => {
        assert.equal(error?.code, ValidationErrorCode.INVALID_HEX);
        assert.match(String(error?.message), /rootHint/i);
        return true;
      },
    );
  });

  test("governance ZK-v1 routes require exact nonempty backend tokens", async () => {
    let fetchCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        fetchCalls += 1;
        return createResponse({ status: 204 });
      },
    });
    const base = {
      authority: FIXTURE_BOB_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      electionId: "ref-zk",
    };
    for (const backend of ["", " halo2/ipa", "halo2/ipa ", "halo2 ipa", "halo2\nipa"] ) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () =>
          client.governanceSubmitZkBallotV1({
            ...base,
            backend,
            envelope: [4, 5],
          }),
        /backend.*(?:empty|whitespace|control)/u,
      );
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () =>
          client.governanceSubmitZkBallotProofV1({
            ...base,
            ballot: { backend, envelopeBytes: "AAE=" },
          }),
        /backend.*(?:empty|whitespace|control)/u,
      );
    }
    assert.equal(fetchCalls, 0);
  });

  test("governanceSubmitZkBallotProofV1 rejects partial lock hints", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not run");
      },
    });
    await assert.rejects(
      () =>
        client.governanceSubmitZkBallotProofV1({
          authority: FIXTURE_BOB_ID,
          networkId: GOVERNANCE_NETWORK_ID,
          electionId: "ref-zk",
          ballot: {
            backend: "pipa-r/pasta",
            envelopeBytes: "AAE=",
            owner: SAMPLE_ACCOUNT_FORMS.i105,
          },
        }),
      (error) => {
        assert.equal(error?.code, ValidationErrorCode.INVALID_OBJECT);
        assert.match(String(error?.message), /owner, amount, and durationBlocks/i);
        return true;
      },
    );
  });

  test("governanceSubmitZkBallotProofV1 rejects noncanonical owner", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        throw new Error("fetch should not run");
      },
    });
    await assert.rejects(
      () =>
        client.governanceSubmitZkBallotProofV1({
          authority: FIXTURE_BOB_ID,
          networkId: GOVERNANCE_NETWORK_ID,
          electionId: "ref-zk",
          ballot: {
            backend: "pipa-r/pasta",
            envelopeBytes: "AAE=",
            owner: SAMPLE_ACCOUNT_FORMS.malformedI105,
            amount: "42",
            durationBlocks: 128,
          },
        }),
      (error) => {
        assert.equal(error?.code, ValidationErrorCode.INVALID_ACCOUNT_ID);
        assert.match(String(error?.message), /canonical .*i105 account id/i);
        return true;
      },
    );
  });

  test("governanceSubmitZkBallotProofV1 requires its proof envelope before fetch", async () => {
    let fetchCalls = 0;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        fetchCalls += 1;
        return createResponse({ status: 204 });
      },
    });
    const base = {
      authority: FIXTURE_BOB_ID,
      networkId: GOVERNANCE_NETWORK_ID,
      electionId: "ref-zk",
    };
    const invalidBallots = [
      { envelopeBytes: "AAE=" },
      { backend: null, envelopeBytes: "AAE=" },
      { backend: "", envelopeBytes: "AAE=" },
      { backend: "   ", envelopeBytes: "AAE=" },
      { backend: "pipa-r/pasta" },
      { backend: "pipa-r/pasta", envelopeBytes: null },
      { backend: "pipa-r/pasta", envelopeBytes: "" },
      { backend: "pipa-r/pasta", envelopeBytes: "%%%" },
    ];

    for (const ballot of invalidBallots) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(
        () => client.governanceSubmitZkBallotProofV1({ ...base, ballot }),
        /backend|envelopeBytes/u,
      );
    }
    assert.equal(fetchCalls, 0);
  });

  test("setProtectedNamespaces posts exact namespace list", async () => {
    let captured;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async (url, init) => {
        captured = { url, init };
        return createResponse({
          status: 200,
          jsonData: { ok: true, applied: 2 },
          headers: { "content-type": "application/json" },
        });
      },
    });
    const result = await client.setProtectedNamespaces(["apps", "system"]);
    assert.deepEqual(result, { ok: true, applied: 2 });
    assert.equal(captured.url, `${BASE_URL}/v1/gov/protected-namespaces`);
    assert.equal(captured.init.method, "POST");
    assert.equal(captured.init.headers["Content-Type"], "application/json");
    assert.deepEqual(JSON.parse(captured.init.body), {
      namespaces: ["apps", "system"],
    });
  });

  test("setProtectedNamespaces validates namespace inputs", async () => {
    let called = false;
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () => {
        called = true;
        return createResponse({
          status: 200,
          jsonData: { ok: true, applied: 0 },
          headers: { "content-type": "application/json" },
        });
      },
    });
    await assert.rejects(() => client.setProtectedNamespaces([]), /must not be empty/);
    await assert.rejects(
      () => client.setProtectedNamespaces(["apps", 42]),
      /namespaces\[1\] must be a string/,
    );
    await assert.rejects(
      () => client.setProtectedNamespaces([" apps"]),
      /namespaces\[0\] must not contain surrounding whitespace/,
    );
    assert.equal(called, false);
  });

  test("getProtectedNamespaces accepts an exact namespace payload", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: { found: "true", namespaces: ["apps", "system"] },
          headers: { "content-type": "application/json" },
        }),
    });
    const result = await client.getProtectedNamespaces(governanceReadOptions());
    assert.deepEqual(result, { found: true, namespaces: ["apps", "system"] });
  });

  test("getProtectedNamespaces rejects noncanonical namespace payloads", async () => {
    const client = new ToriiClient(BASE_URL, {
      fetchImpl: async () =>
        createResponse({
          status: 200,
          jsonData: { found: true, namespaces: [" apps", "system"] },
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => client.getProtectedNamespaces(governanceReadOptions()),
      /protected namespaces response\.namespaces\[0\] must not contain surrounding whitespace/,
    );
  });
}
