package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.text.Normalizer
import java.util.Base64
import org.hyperledger.iroha.sdk.address.AssetDefinitionIdEncoder
import org.hyperledger.iroha.sdk.address.PublicKeyPayload
import org.hyperledger.iroha.sdk.address.decodePublicKeyLiteral
import org.hyperledger.iroha.sdk.address.encodePublicKeyMultihash
import org.hyperledger.iroha.sdk.address.requireCanonicalI105Address
import org.hyperledger.iroha.sdk.core.model.NetworkId
import org.hyperledger.iroha.sdk.core.model.requireCanonicalV1ContractAddress

/** Recursive fail-closed admission for the exact first-release proposal wire contract. */
internal object ParliamentProposalValidatorV1 {
    private val U64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
    private val FIRST_RELEASE_MAX_EXACT_JSON_U64 = BigInteger("9007199254740991")
    private const val SCCP_GOVERNANCE_MAX_ENTRIES = 16
    private val SCCP_EXTERNAL_NETWORKS = setOf(
        "ethereum_mainnet", "bsc_mainnet", "ton_mainnet", "tron_mainnet",
    )
    private val SCCP_GOVERNANCE_ACTIONS = setOf(
        "register_route", "activate_revision", "switch_revision", "deactivate_outbound",
        "retire_revision", "remove_staged", "release_stranded", "set_taira_paused",
        "set_destination_paused", "initialize_light_client", "install_trusted_checkpoint",
        "freeze_light_client", "set_parameters", "clear_bridge_key_fault",
    )
    private val BLS_VALIDATOR_ID = Regex("ea0130[0-9A-F]{96}")
    private val KEBAB = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
    private val ALPHANUMERIC_PRERELEASE = Regex("(?=.*[A-Za-z-])[A-Za-z0-9-]+")

    @Suppress("UNCHECKED_CAST")
    fun parse(bytes: ByteArray): Map<String, Any?> {
        val text = String(bytes, StandardCharsets.UTF_8)
        require(text.toByteArray(StandardCharsets.UTF_8).contentEquals(bytes)) {
            "proposal must be UTF-8 JSON"
        }
        val proposal = objectValue(JsonParser.parse(text), "proposal")
        exact(proposal, setOf("kind", "payload"), "proposal")
        val kind = text(proposal["kind"], "proposal.kind")
        require(kind in ParliamentApiV1.PROPOSAL_KINDS) { "proposal.kind is unknown or retired" }
        val payload = objectValue(proposal["payload"], "proposal.payload")
        when (kind) {
            "DeployContract" -> deployContract(payload)
            "RuntimeUpgrade" -> runtimeUpgrade(payload)
            "SccpRouteGovernance" -> sccpRoute(payload)
            "ValidationFeePolicy" -> validationFeePolicyProposal(payload)
            "ValidationFeePayoutLifecycle" -> validationFeePayoutLifecycle(payload)
            "MusubiRegistryGovernance" -> musubiAction(payload)
            "SorafsProviderGovernance" -> sorafsProvider(payload)
            "ContractLifecycleGovernance" -> contractLifecycle(payload)
            "ContractEmergencyHold" -> contractEmergencyHold(payload)
            "GlobalDataTriggerPermissionGovernance" -> globalDataTriggerPermission(payload)
            else -> throw IllegalArgumentException("proposal.kind is unknown or retired")
        }
        return proposal
    }

    private fun deployContract(value: Map<String, Any?>) {
        exact(
            value,
            setOf(
                "proposal_operator",
                "contract_address",
                "code_hash",
                "abi_hash",
                "abi_version",
                "manifest_provenance",
            ),
            "DeployContract",
        )
        account(value["proposal_operator"], "proposal_operator")
        requireCanonicalV1ContractAddress(text(value["contract_address"], "contract_address"))
        lowerHex32(value["code_hash"], "code_hash")
        lowerHex32(value["abi_hash"], "abi_hash")
        require(uint(value["abi_version"], "abi_version") == BigInteger.ONE) {
            "abi_version must equal 1"
        }
        value["manifest_provenance"]?.let {
            manifestProvenance(objectValue(it, "manifest_provenance"), "manifest_provenance")
        }
    }

    private fun manifestProvenance(value: Map<String, Any?>, label: String) {
        exact(value, setOf("signer", "signature"), label)
        canonicalPublicKey(value["signer"], "$label.signer")
        canonicalSignature(value["signature"], "$label.signature")
    }

    private fun runtimeUpgrade(value: Map<String, Any?>) {
        exact(value, setOf("proposal_operator", "manifest"), "RuntimeUpgrade")
        account(value["proposal_operator"], "RuntimeUpgrade.proposal_operator")
        val manifest = objectValue(value["manifest"], "RuntimeUpgrade.manifest")
        exact(
            manifest,
            setOf(
                "name", "description", "abi_version", "abi_hash", "added_syscalls",
                "added_pointer_types", "start_height", "end_height", "sbom_digests",
                "slsa_attestation", "provenance",
            ),
            "RuntimeUpgrade.manifest",
        )
        text(manifest["name"], "manifest.name")
        string(manifest["description"], "manifest.description")
        require(uint(manifest["abi_version"], "manifest.abi_version") == BigInteger.ONE) {
            "manifest.abi_version must equal 1"
        }
        bytes(manifest["abi_hash"], 32, "manifest.abi_hash", false)
        val syscalls = list(manifest["added_syscalls"], "manifest.added_syscalls")
        val pointers = list(manifest["added_pointer_types"], "manifest.added_pointer_types")
        syscalls.forEachIndexed { index, item ->
            require(uint(item, "manifest.added_syscalls[$index]") <= BigInteger.valueOf(0xffff))
        }
        pointers.forEachIndexed { index, item ->
            require(uint(item, "manifest.added_pointer_types[$index]") <= BigInteger.valueOf(0xffff))
        }
        require(syscalls.isEmpty() && pointers.isEmpty()) { "V1 ABI delta lists must be empty" }
        val start = uint(manifest["start_height"], "manifest.start_height")
        val end = uint(manifest["end_height"], "manifest.end_height")
        require(end > start) { "manifest.end_height must exceed start_height" }
        list(manifest["sbom_digests"], "manifest.sbom_digests").forEachIndexed { index, item ->
            val digest = objectValue(item, "manifest.sbom_digests[$index]")
            exact(digest, setOf("algorithm", "digest"), "manifest.sbom_digests[$index]")
            text(digest["algorithm"], "manifest.sbom_digests[$index].algorithm")
            canonicalBase64(digest["digest"], "manifest.sbom_digests[$index].digest")
        }
        canonicalBase64(manifest["slsa_attestation"], "manifest.slsa_attestation")
        list(manifest["provenance"], "manifest.provenance").forEachIndexed { index, item ->
            manifestProvenance(objectValue(item, "manifest.provenance[$index]"), "manifest.provenance[$index]")
        }
    }

    /**
     * Checks the closed `SccpGovernanceProposalV1` envelope (specs/sccp.md §4.14.3): subjects,
     * revisions and action tags. Action payloads must be objects; Torii performs the
     * state-independent payload checks against the live network and core the state-dependent ones.
     */
    private fun sccpRoute(value: Map<String, Any?>) {
        exact(value, setOf("proposal"), "SccpRouteGovernance")
        val proposal = objectValue(value["proposal"], "SccpRouteGovernance.proposal")
        exact(
            proposal,
            setOf("network_id", "base_revisions", "actions"),
            "SccpRouteGovernance.proposal",
        )
        NetworkId.parse(text(proposal["network_id"], "proposal.network_id"))
        val baseRevisions = list(proposal["base_revisions"], "proposal.base_revisions")
        require(baseRevisions.size in 1..SCCP_GOVERNANCE_MAX_ENTRIES) {
            "proposal.base_revisions must hold 1 to $SCCP_GOVERNANCE_MAX_ENTRIES entries"
        }
        baseRevisions.forEachIndexed { index, item ->
            val label = "proposal.base_revisions[$index]"
            val entry = objectValue(item, label)
            exact(entry, setOf("subject", "revision"), label)
            sccpGovernanceSubject(objectValue(entry["subject"], "$label.subject"), "$label.subject")
            uint(entry["revision"], "$label.revision")
        }
        val actions = list(proposal["actions"], "proposal.actions")
        require(actions.size in 1..SCCP_GOVERNANCE_MAX_ENTRIES) {
            "proposal.actions must hold 1 to $SCCP_GOVERNANCE_MAX_ENTRIES entries"
        }
        actions.forEachIndexed { index, item ->
            val label = "proposal.actions[$index]"
            val action = objectValue(item, label)
            exact(action, setOf("action", "payload"), label)
            require(text(action["action"], "$label.action") in SCCP_GOVERNANCE_ACTIONS) {
                "$label.action is unknown"
            }
            objectValue(action["payload"], "$label.payload")
        }
    }

    private fun sccpGovernanceSubject(value: Map<String, Any?>, label: String) {
        exact(value, setOf("subject", "key"), label)
        when (text(value["subject"], "$label.subject")) {
            "route", "route_control", "light_client" ->
                sccpExternalNetwork(objectValue(value["key"], "$label.key"), "$label.key")
            "parameters" -> require(value["key"] == null) { "$label.key must be null" }
            "bridge_key_fault" ->
                require(BLS_VALIDATOR_ID.matches(string(value["key"], "$label.key"))) {
                    "$label.key must be a canonical BLS validator id"
                }
            else -> throw IllegalArgumentException("$label.subject is unknown")
        }
    }

    private fun sccpExternalNetwork(value: Map<String, Any?>, label: String) {
        exact(value, setOf("network", "profile"), label)
        require(text(value["network"], "$label.network") in SCCP_EXTERNAL_NETWORKS) {
            "$label.network is unknown"
        }
        require(value["profile"] == null) { "$label.profile must be null" }
    }

    private fun validationFeePolicyProposal(value: Map<String, Any?>) {
        exact(
            value,
            setOf("proposal_operator", "policy"),
            "ValidationFeePolicy",
        )
        account(value["proposal_operator"], "proposal_operator")
        val policy = objectValue(value["policy"], "policy")
        validationFeePolicy(policy)

    }

    private fun validationFeePolicy(value: Map<String, Any?>) {
        exact(value, setOf(
            "schema_version", "network_id", "policy_version", "previous_policy_hash",
            "ds_asset_id", "ds_scale", "retail_schedule", "effective_from_ms", "notice_published_at_ms",
            "fee", "treasury_account_id", "charging_mode",
            "exemption_classes", "reward_custody",
        ), "validation fee policy")
        require(uint(value["schema_version"], "policy.schema_version") == BigInteger.ONE)
        NetworkId.parse(text(value["network_id"], "policy.network_id"))
        val version = u64String(value["policy_version"], "policy.policy_version", true)
        val previous = value["previous_policy_hash"]?.let { nonzeroFeeHash(it, "policy.previous_policy_hash") }
        require((version == BigInteger.ONE) == (previous == null))
        asset(value["ds_asset_id"], "policy.ds_asset_id")
        require(uint(value["ds_scale"], "policy.ds_scale") == BigInteger.valueOf(2))
        val fee = quantity(value["fee"], "policy.fee")
        require(fee != "0" && fee.substringAfter('.', "").length <= 2) { "Institutional fee must be positive exact minor units" }
        account(value["treasury_account_id"], "policy.treasury_account_id")
        val mode = objectValue(value["charging_mode"], "policy.charging_mode")
        exact(mode, setOf("charging_mode", "value"), "charging_mode")
        require(mode["charging_mode"] == "RETAIL_MONTHLY_ALLOWANCE" && mode["value"] == null)
        val effective = uint(value["effective_from_ms"], "policy.effective_from_ms").longValueExact()
        val notice = uint(value["notice_published_at_ms"], "policy.notice_published_at_ms").longValueExact()
        val boundary = java.time.Instant.ofEpochMilli(effective).atOffset(java.time.ZoneOffset.ofHours(11))
        require(boundary.dayOfMonth == 1 && boundary.toLocalTime() == java.time.LocalTime.MIDNIGHT && effective - notice >= 30L * 86_400_000)
        val schedule = objectValue(value["retail_schedule"], "policy.retail_schedule")
        exact(schedule, setOf("included_payments", "overage_minor", "maintenance_tiers"), "retail_schedule")
        require(uint(schedule["included_payments"], "included_payments") in BigInteger.ONE..BigInteger("4294967295"))
        require(uint(schedule["overage_minor"], "overage_minor") > BigInteger.ZERO)
        val tiers = list(schedule["maintenance_tiers"], "maintenance_tiers")
        require(tiers.size in 1..32)
        var previousMinimum = BigInteger.valueOf(-1)
        var previousFee = BigInteger.ZERO
        tiers.forEachIndexed { index, item ->
            val tier = objectValue(item, "maintenance_tiers[$index]")
            exact(tier, setOf("minimum_average_balance_minor", "monthly_fee_minor"), "maintenance tier")
            val minimum = uint(tier["minimum_average_balance_minor"], "minimum_average_balance_minor")
            require(minimum > previousMinimum && (index != 0 || minimum == BigInteger.ZERO))
            val monthlyFee = uint(tier["monthly_fee_minor"], "monthly_fee_minor")
            require(monthlyFee > BigInteger.ZERO && monthlyFee >= previousFee)
            previousMinimum = minimum
            previousFee = monthlyFee
        }
        val exemptions = list(value["exemption_classes"], "exemption_classes")
        require(exemptions == listOf("TREASURY_PAYOUT"))
        val custody=objectValue(value["reward_custody"],"reward_custody")
        exact(custody,setOf("contract_address","treasury_account_id","ds_asset_id","xor_asset_id","reward_pool_account_id","validator_lane_id"),"reward_custody")
        requireCanonicalV1ContractAddress(text(custody["contract_address"],"reward contract"))
        require(account(custody["treasury_account_id"],"custody treasury")==account(value["treasury_account_id"],"policy treasury"))
        require(asset(custody["ds_asset_id"],"custody asset")==asset(value["ds_asset_id"],"policy asset"))
        require(asset(custody["xor_asset_id"],"custody XOR")!=custody["ds_asset_id"])
        require(account(custody["reward_pool_account_id"],"reward pool")!=custody["treasury_account_id"])
        require(uint(custody["validator_lane_id"],"validator lane")<=BigInteger("4294967295"))
    }

    private fun validationFeePayoutLifecycle(value: Map<String, Any?>) {
        exact(value, setOf("proposal_operator", "payout_binding"), "ValidationFeePayoutLifecycle")
        account(value["proposal_operator"], "proposal_operator")
        payoutBinding(objectValue(value["payout_binding"], "payout_binding"))
    }

    private fun payoutBinding(value: Map<String, Any?>) {
        exact(value, setOf(
            "contract_address", "code_hash", "entrypoint", "treasury_account_id", "ds_asset_id", "xor_asset_id",
            "pool_contract_address", "pool_code_hash", "pool_vault_account_id", "reward_pool_account_id",
            "reference_feed_id", "reference_feed_config_version", "reference_provider_accounts",
            "max_sbd_per_attempt_minor", "max_sbd_per_day_minor", "min_interval_ms", "max_source_age_ms",
            "max_slippage_bps", "validator_lane_id", "min_reward_claim_xor_minor",
        ), "payout_binding")
        for (field in listOf("contract_address", "pool_contract_address")) requireCanonicalV1ContractAddress(text(value[field], field))
        for (field in listOf("code_hash", "pool_code_hash")) nonzeroFeeHash(value[field], field)
        require(text(value["entrypoint"], "entrypoint") == "autonomous_validation_fee_tick")
        val accounts = listOf("treasury_account_id", "pool_vault_account_id", "reward_pool_account_id").map { account(value[it], it) }
        require(accounts.distinct().size == 3)
        require(asset(value["ds_asset_id"], "ds_asset_id") != asset(value["xor_asset_id"], "xor_asset_id"))
        text(stringTuple(value["reference_feed_id"], "reference_feed_id"), "reference_feed_id")
        require(uint(value["reference_feed_config_version"], "reference_feed_config_version") in BigInteger.ONE..BigInteger("4294967295"))
        val providers = list(value["reference_provider_accounts"], "reference_provider_accounts").map { account(it, "reference provider") }
        require(providers.size == 5 && providers.distinct().size == 5)
        val attempt = uint(value["max_sbd_per_attempt_minor"], "max_sbd_per_attempt_minor")
        require(attempt > BigInteger.ZERO && uint(value["max_sbd_per_day_minor"], "max_sbd_per_day_minor") >= attempt)
        for (field in listOf("min_interval_ms", "max_source_age_ms", "min_reward_claim_xor_minor")) require(uint(value[field], field) > BigInteger.ZERO)
        require(uint(value["max_slippage_bps"], "max_slippage_bps") < BigInteger.valueOf(10000))
        require(uint(value["validator_lane_id"], "validator_lane_id") <= BigInteger("4294967295"))
    }

    private fun nonzeroFeeHash(value: Any?, label: String): String {
        require(value is String && Regex("[0-9A-F]{64}").matches(value) && value != "0".repeat(64)) {
            "$label must be nonzero canonical uppercase 32-byte hexadecimal"
        }
        return value
    }

    private fun musubiAction(value: Map<String, Any?>) {
        exact(value, setOf("kind", "value"), "MusubiRegistryGovernance")
        val kind = text(value["kind"], "MusubiRegistryGovernance.kind")
        val action = objectValue(value["value"], "MusubiRegistryGovernance.value")
        when (kind) {
            "RecoverPackageOwners" -> {
                exact(action, setOf("package", "owners", "expected_revision"), kind)
                musubiPackage(objectValue(action["package"], "$kind.package"), "$kind.package")
                val owners = list(action["owners"], "$kind.owners").mapIndexed { index, item ->
                    account(item, "$kind.owners[$index]")
                }
                require(owners.size in 1..64 && owners.distinct().size == owners.size)
                require(uint(action["expected_revision"], "$kind.expected_revision") > BigInteger.ZERO)
            }
            "RetargetAlias" -> {
                exact(action, setOf("alias", "target", "expected_revision"), kind)
                kebab(stringTuple(action["alias"], "$kind.alias"), "$kind.alias", 32)
                musubiPackage(objectValue(action["target"], "$kind.target"), "$kind.target")
                require(uint(action["expected_revision"], "$kind.expected_revision") > BigInteger.ZERO)
            }
            "TakedownArtifact" -> {
                exact(action, setOf("release", "reason", "expected_artifact_governance_revision"), kind)
                musubiRelease(objectValue(action["release"], "$kind.release"), "$kind.release")
                reason(stringTuple(action["reason"], "$kind.reason"), "$kind.reason")
                require(
                    uint(
                        action["expected_artifact_governance_revision"],
                        "$kind.expected_artifact_governance_revision",
                    ) > BigInteger.ZERO,
                )
            }
            "SetRegistryPolicy" -> {
                exact(action, setOf("policy", "expected_revision"), kind)
                val expected = uint(action["expected_revision"], "$kind.expected_revision")
                require(expected > BigInteger.ZERO)
                val revision = musubiRegistryPolicy(objectValue(action["policy"], "$kind.policy"), "$kind.policy")
                require(revision == expected + BigInteger.ONE) { "policy revision must follow expected_revision" }
            }
            else -> throw IllegalArgumentException("Musubi governance action is unsupported")
        }
    }

    private fun musubiPackage(value: Map<String, Any?>, label: String) {
        exact(value, setOf("home_dataspace", "scope", "name"), label)
        uint(value["home_dataspace"], "$label.home_dataspace")
        val scope = objectValue(value["scope"], "$label.scope")
        exact(scope, setOf("kind", "value"), "$label.scope")
        when (text(scope["kind"], "$label.scope.kind")) {
            "DataspaceRoot" -> require(scope["value"] == null) { "$label.scope.value must be null" }
            "Domain" -> canonicalName(scope["value"], "$label.scope.value")
            else -> throw IllegalArgumentException("$label.scope.kind is unsupported")
        }
        kebab(stringTuple(value["name"], "$label.name"), "$label.name", 64)
    }

    private fun musubiRelease(value: Map<String, Any?>, label: String) {
        exact(value, setOf("package", "version"), label)
        musubiPackage(objectValue(value["package"], "$label.package"), "$label.package")
        val version = objectValue(value["version"], "$label.version")
        exact(version, setOf("major", "minor", "patch", "prerelease"), "$label.version")
        uint(version["major"], "$label.version.major")
        uint(version["minor"], "$label.version.minor")
        uint(version["patch"], "$label.version.patch")
        val prerelease = list(version["prerelease"], "$label.version.prerelease")
        require(prerelease.size <= 16)
        prerelease.forEachIndexed { index, item ->
            val identifier = objectValue(item, "$label.version.prerelease[$index]")
            exact(identifier, setOf("kind", "value"), "$label.version.prerelease[$index]")
            when (text(identifier["kind"], "$label.version.prerelease[$index].kind")) {
                "Numeric" -> uint(identifier["value"], "$label.version.prerelease[$index].value")
                "AlphaNumeric" -> {
                    val literal = text(identifier["value"], "$label.version.prerelease[$index].value")
                    require(literal.toByteArray(StandardCharsets.UTF_8).size <= 64 && ALPHANUMERIC_PRERELEASE.matches(literal))
                }
                else -> throw IllegalArgumentException("unsupported prerelease identifier")
            }
        }
    }

    private fun musubiRegistryPolicy(value: Map<String, Any?>, label: String): BigInteger {
        exact(value, setOf("version", "revision", "mode", "allowlisted_dataspaces", "alias_pricing"), label)
        require(uint(value["version"], "$label.version") == BigInteger.ONE)
        val revision = uint(value["revision"], "$label.revision")
        require(revision > BigInteger.ZERO)
        val mode = objectValue(value["mode"], "$label.mode")
        exact(mode, setOf("kind", "value"), "$label.mode")
        val modeKind = text(mode["kind"], "$label.mode.kind")
        require(modeKind in setOf("Closed", "Allowlisted", "Open") && mode["value"] == null)
        val allowed = list(value["allowlisted_dataspaces"], "$label.allowlisted_dataspaces").mapIndexed { index, item ->
            uint(item, "$label.allowlisted_dataspaces[$index]")
        }
        require(allowed.zipWithNext().all { (left, right) -> left < right })
        require(modeKind == "Allowlisted" || allowed.isEmpty())
        val pricing = objectValue(value["alias_pricing"], "$label.alias_pricing")
        val pricingFields = setOf(
            "revision", "length_1_xor", "length_2_xor", "length_3_xor",
            "length_4_xor", "length_5_to_32_xor",
        )
        exact(pricing, pricingFields, "$label.alias_pricing")
        pricingFields.forEach { field ->
            require(uint(pricing[field], "$label.alias_pricing.$field") > BigInteger.ZERO)
        }
        return revision
    }

    private fun sorafsProvider(value: Map<String, Any?>) {
        exact(value, setOf("action"), "SorafsProviderGovernance")
        val action = objectValue(value["action"], "SorafsProviderGovernance.action")
        exact(action, setOf("action", "value"), "SorafsProviderGovernance.action")
        val kind = text(action["action"], "SorafsProviderGovernance.action.action")
        val payload = objectValue(action["value"], "SorafsProviderGovernance.action.value")
        when (kind) {
            "establish" -> {
                exact(payload, setOf("provider_id", "owner"), "provider establish")
                providerId(payload["provider_id"], "provider_id")
                account(payload["owner"], "owner")
            }
            "rebind" -> {
                exact(payload, setOf("provider_id", "expected_owner", "next_owner"), "provider rebind")
                providerId(payload["provider_id"], "provider_id")
                val current = account(payload["expected_owner"], "expected_owner")
                val next = account(payload["next_owner"], "next_owner")
                require(current != next) { "next_owner must differ from expected_owner" }
            }
            "remove" -> {
                exact(payload, setOf("provider_id", "expected_owner"), "provider remove")
                providerId(payload["provider_id"], "provider_id")
                account(payload["expected_owner"], "expected_owner")
            }
            else -> throw IllegalArgumentException("Sorafs provider action is unsupported")
        }
    }

    private fun contractLifecycle(value: Map<String, Any?>) {
        exact(
            value,
            setOf("proposal_operator", "contract_address", "expected_revision", "action"),
            "ContractLifecycleGovernance",
        )
        account(
            value["proposal_operator"],
            "ContractLifecycleGovernance.proposal_operator",
        )
        requireCanonicalV1ContractAddress(
            text(value["contract_address"], "ContractLifecycleGovernance.contract_address"),
        )
        require(
            uint(value["expected_revision"], "ContractLifecycleGovernance.expected_revision") >
                BigInteger.ZERO,
        ) { "contract lifecycle expected_revision must be nonzero" }
        val action = objectValue(value["action"], "ContractLifecycleGovernance.action")
        exact(action, setOf("action", "payload"), "ContractLifecycleGovernance.action")
        val kind = text(action["action"], "ContractLifecycleGovernance.action.action")
        require(kind in ParliamentApiV1.CONTRACT_LIFECYCLE_ACTIONS) {
            "contract lifecycle action is unsupported"
        }
        if (kind == "CancelOwnershipOffer" || kind == "AcceptParliamentOwnership") {
            require(action["payload"] == null) { "$kind payload must be null" }
            return
        }
        val payload = objectValue(action["payload"], "ContractLifecycleGovernance.action.payload")
        when (kind) {
            "Activate" -> {
                exact(
                    payload,
                    setOf("code_hash", "abi_hash", "abi_version", "manifest_provenance"),
                    kind,
                )
                lowerHex32(payload["code_hash"], "$kind.code_hash")
                lowerHex32(payload["abi_hash"], "$kind.abi_hash")
                require(uint(payload["abi_version"], "$kind.abi_version") == BigInteger.ONE) {
                    "$kind.abi_version must equal 1"
                }
                payload["manifest_provenance"]?.let {
                    manifestProvenance(objectValue(it, "$kind.manifest_provenance"), "$kind.manifest_provenance")
                }
            }
            "Deactivate" -> {
                val fields = if (payload.containsKey("reason")) {
                    setOf("expected_code_hash", "reason")
                } else {
                    setOf("expected_code_hash")
                }
                exact(payload, fields, kind)
                lowerHex32(payload["expected_code_hash"], "$kind.expected_code_hash")
                payload["reason"]?.let { string(it, "$kind.reason") }
            }
            "OfferOwnership" -> {
                exact(payload, setOf("new_owner"), kind)
                account(payload["new_owner"], "$kind.new_owner")
            }
            "CompleteEmergencyHoldRetrospective" -> {
                exact(
                    payload,
                    setOf(
                        "hold_proposal_content_id", "hold_governance_attempt_id",
                        "incident_digest", "retrospective_finding_root",
                    ),
                    kind,
                )
                bytes(payload["hold_proposal_content_id"], 32, "$kind.hold_proposal_content_id", true)
                bytes(payload["hold_governance_attempt_id"], 32, "$kind.hold_governance_attempt_id", true)
                bytes(payload["incident_digest"], 32, "$kind.incident_digest", true)
                bytes(payload["retrospective_finding_root"], 32, "$kind.retrospective_finding_root", true)
            }
            else -> throw IllegalArgumentException("contract lifecycle action is unsupported")
        }
    }

    private fun globalDataTriggerPermission(value: Map<String, Any?>) {
        exact(
            value,
            setOf("authority", "action"),
            "GlobalDataTriggerPermissionGovernance",
        )
        account(
            value["authority"],
            "GlobalDataTriggerPermissionGovernance.authority",
        )
        val action = objectValue(
            value["action"],
            "GlobalDataTriggerPermissionGovernance.action",
        )
        exact(
            action,
            setOf("action", "value"),
            "GlobalDataTriggerPermissionGovernance.action",
        )
        val kind = text(
            action["action"],
            "GlobalDataTriggerPermissionGovernance.action.action",
        )
        require(kind == "grant" || kind == "revoke") {
            "GlobalDataTriggerPermissionGovernance.action.action must be grant or revoke"
        }
        require(action["value"] == null) {
            "GlobalDataTriggerPermissionGovernance.action.value must be null"
        }
    }

    private fun contractEmergencyHold(value: Map<String, Any?>) {
        exact(
            value,
            setOf(
                "contract_address", "expected_revision", "expected_code_hash",
                "incident_digest", "reason", "duration_blocks",
            ),
            "ContractEmergencyHold",
        )
        requireCanonicalV1ContractAddress(
            text(value["contract_address"], "ContractEmergencyHold.contract_address"),
        )
        require(
            uint(value["expected_revision"], "ContractEmergencyHold.expected_revision") >
                BigInteger.ZERO,
        ) { "contract emergency-hold expected_revision must be nonzero" }
        lowerHex32(value["expected_code_hash"], "ContractEmergencyHold.expected_code_hash")
        bytes(value["incident_digest"], 32, "ContractEmergencyHold.incident_digest", true)
        require(string(value["reason"], "ContractEmergencyHold.reason").trim().isNotEmpty()) {
            "ContractEmergencyHold.reason must not be blank"
        }
        val duration = uint(value["duration_blocks"], "ContractEmergencyHold.duration_blocks")
        require(duration in BigInteger.ONE..BigInteger.valueOf(3_600)) {
            "ContractEmergencyHold.duration_blocks must be in 1..3600"
        }
    }

    private fun providerId(value: Any?, label: String) {
        val tuple = list(value, label)
        require(tuple.size == 1) { "$label must use the exact ProviderId tuple" }
        bytes(tuple[0], 32, "$label[0]", true)
    }

    private fun account(value: Any?, label: String): String =
        requireCanonicalI105Address(text(value, label), label)

    private fun asset(value: Any?, label: String): String {
        val literal = text(value, label)
        require(AssetDefinitionIdEncoder.isCanonicalAddress(literal)) { "$label must be a canonical AssetDefinitionId" }
        return literal
    }

    private fun quantity(value: Any?, label: String): String {
        val literal = string(value, label)
        require(Regex("(?:0|[1-9][0-9]*)(?:\\.[0-9]*[1-9])?").matches(literal)) {
            "$label must be a canonical non-negative quantity"
        }
        return literal
    }

    private fun canonicalBase64(value: Any?, label: String) {
        val literal = string(value, label)
        val decoded = try {
            Base64.getDecoder().decode(literal)
        } catch (ex: IllegalArgumentException) {
            throw IllegalArgumentException("$label must be canonical padded base64", ex)
        }
        require(Base64.getEncoder().encodeToString(decoded) == literal) {
            "$label must be canonical padded base64"
        }
    }

    private fun canonicalPublicKey(value: Any?, label: String): PublicKeyPayload {
        val literal = text(value, label)
        val parsed = requireNotNull(decodePublicKeyLiteral(literal)) {
            "$label must be a canonical public-key multihash"
        }
        require(encodePublicKeyMultihash(parsed.curveId, parsed.keyBytes) == literal) {
            "$label must use the canonical bare public-key spelling"
        }
        return parsed
    }

    private fun canonicalSignature(value: Any?, label: String) {
        val literal = string(value, label)
        require(literal.length % 2 == 0 && Regex("[0-9A-F]+").matches(literal)) {
            "$label must be nonempty canonical uppercase hexadecimal"
        }
        require(literal.chunked(2).any { it != "00" }) { "$label must be nonzero" }
    }

    private fun stringTuple(value: Any?, label: String): String {
        val tuple = list(value, label)
        require(tuple.size == 1 && tuple[0] is String) { "$label must use an exact one-string tuple" }
        return tuple[0] as String
    }

    private fun kebab(value: String, label: String, maximumBytes: Int) {
        require(value.toByteArray(StandardCharsets.UTF_8).size <= maximumBytes && KEBAB.matches(value)) {
            "$label must be canonical lowercase ASCII kebab text"
        }
    }

    private fun canonicalName(value: Any?, label: String) {
        val literal = text(value, label)
        require(
            literal.toByteArray(StandardCharsets.UTF_8).size <= 255 &&
                Normalizer.normalize(literal, Normalizer.Form.NFC) == literal &&
                literal.none { it.isWhitespace() || it in setOf('@', '#', '$') || Character.isISOControl(it) } &&
                literal.none { it.code == 0x061c || it.code in 0x200e..0x200f || it.code in 0x202a..0x202e || it.code in 0x2066..0x2069 },
        ) { "$label must be a canonical Iroha Name" }
    }

    private fun reason(value: String, label: String) {
        require(
            value.isNotEmpty() && value == value.trim() &&
                value.toByteArray(StandardCharsets.UTF_8).size <= 1024 &&
                value.none { it.code in 0..0x1f || it.code == 0x7f },
        ) { "$label must be bounded canonical public text" }
    }

    private fun lowerHex32(value: Any?, label: String) {
        require(value is String && Regex("[0-9a-f]{64}").matches(value)) {
            "$label must contain 32 lowercase hexadecimal bytes"
        }
    }

    private fun bytes(value: Any?, size: Int, label: String, nonzero: Boolean): ByteArray {
        val items = list(value, label)
        require(items.size == size) { "$label must contain exactly $size bytes" }
        val result = ByteArray(size)
        items.forEachIndexed { index, item ->
            val parsed = uint(item, "$label[$index]")
            require(parsed <= BigInteger.valueOf(255)) { "$label[$index] must be a byte" }
            result[index] = parsed.toByte()
        }
        require(!nonzero || result.any { it.toInt() != 0 }) { "$label must be nonzero" }
        return result
    }

    private fun u64String(value: Any?, label: String, positive: Boolean): BigInteger {
        val literal = string(value, label)
        require(Regex("0|[1-9][0-9]*").matches(literal)) { "$label must be a canonical u64 decimal string" }
        val parsed = BigInteger(literal)
        require(parsed <= U64_MAX && (!positive || parsed > BigInteger.ZERO)) { "$label is outside u64" }
        return parsed
    }

    private fun uint(value: Any?, label: String): BigInteger {
        require(value is Number) { "$label must be an unsigned JSON integer" }
        val literal = value.toString()
        require(Regex("0|[1-9][0-9]*").matches(literal)) { "$label must be an unsigned JSON integer" }
        val parsed = BigInteger(literal)
        require(parsed <= FIRST_RELEASE_MAX_EXACT_JSON_U64) {
            "$label exceeds the first-release exact JSON integer bound"
        }
        return parsed
    }

    private fun text(value: Any?, label: String): String {
        val literal = string(value, label)
        require(literal.isNotEmpty() && literal == literal.trim()) { "$label must be canonical nonempty text" }
        return literal
    }

    private fun string(value: Any?, label: String): String =
        value as? String ?: throw IllegalArgumentException("$label must be a string")

    private fun list(value: Any?, label: String): List<*> =
        value as? List<*> ?: throw IllegalArgumentException("$label must be an array")

    @Suppress("UNCHECKED_CAST")
    private fun objectValue(value: Any?, label: String): Map<String, Any?> {
        require(value is Map<*, *> && value.keys.all { it is String }) { "$label must be an object" }
        return value as Map<String, Any?>
    }

    private fun exact(value: Map<String, Any?>, fields: Set<String>, label: String) {
        require(value.keys == fields) { "$label contains unknown, aliased, or missing fields" }
    }
}
