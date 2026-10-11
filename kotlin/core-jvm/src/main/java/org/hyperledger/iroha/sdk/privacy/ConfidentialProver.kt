package org.hyperledger.iroha.sdk.privacy

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.address.AssetDefinitionIdEncoder
import org.hyperledger.iroha.sdk.client.JsonParser
import org.hyperledger.iroha.sdk.core.model.NetworkId

/** Stable native wallet failure. Messages contain no private note material. */
class ConfidentialProverException(@JvmField val code: Int) : IllegalStateException(
    when (code) {
        -1 -> "Confidential prover input or operation state is invalid"
        -2 -> "Confidential prover or job is closed or consumed"
        -3 -> "Confidential prover resource limit exceeded"
        -10 -> "Confidential spend key must not be all zero"
        -11 -> "Supply one or two input notes"
        -12 -> "Confidential tree exceeds its fixed capacity"
        -13 -> "Supply exactly one membership path per input note"
        -14 -> "Membership path shape or root is invalid"
        -15 -> "Input note index lies outside the supplied tree"
        -16 -> "Membership path directions do not match the input note index"
        -17 -> "A confidential spend cannot consume the same note twice"
        -18 -> "Supply one or two transfer output notes"
        -19 -> "Transfer requires positive, equal non-overflowing input and output totals"
        -20 -> "Input notes require positive amounts with a non-overflowing total"
        -21 -> "Public redemption must be positive and no greater than the input total"
        -22 -> "Supply one change note for a nonzero remainder and none for full redemption"
        -23 -> "Canonical confidential key preparation failed"
        -24 -> "Confidential membership or proof generation failed"
        -101 -> "The loaded native bridge does not support confidential proving"
        else -> "Confidential prover internal failure (code $code)"
    },
)

private fun checkWalletStatus(code: Int) {
    if (code != 0) throw ConfidentialProverException(code)
}
private fun walletHandle(handle: Long): Long {
    if (handle <= 0) throw ConfidentialProverException(handle.toInt())
    return handle
}
private fun validateAmount(amount: BigInteger) {
    require(amount.signum() > 0 && amount.bitLength() <= 128) { "amount must be a positive u128" }
}
private fun validateWord(value: ByteArray) {
    require(value.size == 32) { "wallet word must contain exactly 32 bytes" }
}

/** Owned input opening, consumed and closed by either proving operation. */
class ConfidentialInputNote private constructor(
    private var low: Long,
    private var high: Long,
    rho: ByteArray,
    diversifier: ByteArray,
    leafIndex: Int,
) : AutoCloseable {
    constructor(amount: BigInteger, rho: ByteArray, diversifier: ByteArray, leafIndex: Int) :
        this(amount.also(::validateAmount).toLong(), amount.shiftRight(64).toLong(), rho, diversifier, leafIndex)
    private val rhoBytes: ByteArray
    private val diversifierBytes: ByteArray
    private var index: Int = leafIndex
    private var closed = false
    init {
        require(low != 0L || high != 0L) { "amount must be a positive u128" }
        validateWord(rho); validateWord(diversifier)
        require(leafIndex in 0 until 65_536) { "leafIndex is outside the fixed tree" }
        rhoBytes = rho.copyOf(); diversifierBytes = diversifier.copyOf()
    }
    @Synchronized internal fun append(backend: ConfidentialProverBackend, job: Long) {
        if (closed) throw ConfidentialProverException(-2)
        checkWalletStatus(backend.jobInput(job, low, high, rhoBytes, diversifierBytes, index.toLong()))
    }
    @Synchronized override fun close() {
        rhoBytes.fill(0); diversifierBytes.fill(0); low = 0; high = 0; index = 0; closed = true
    }
    override fun toString(): String = "ConfidentialInputNote([REDACTED])"
    companion object {
        // Preserve the already-validated unsigned limbs without an immutable BigInteger copy.
        internal fun fromOwnedLimbs(low: Long, high: Long, rho: ByteArray, diversifier: ByteArray, leafIndex: Int) =
            ConfidentialInputNote(low, high, rho, diversifier, leafIndex)
    }
}

/** Owned transfer output, consumed and closed by [ConfidentialProver.proveTransfer]. */
class ConfidentialOutputNote(amount: BigInteger, rho: ByteArray, ownerTag: ByteArray) : AutoCloseable {
    private var low: Long
    private var high: Long
    private val rhoBytes: ByteArray
    private val ownerBytes: ByteArray
    private var closed = false
    init {
        validateAmount(amount); validateWord(rho); validateWord(ownerTag)
        low = amount.toLong(); high = amount.shiftRight(64).toLong()
        rhoBytes = rho.copyOf(); ownerBytes = ownerTag.copyOf()
    }
    @Synchronized internal fun append(backend: ConfidentialProverBackend, job: Long) {
        if (closed) throw ConfidentialProverException(-2)
        checkWalletStatus(backend.jobOutput(job, low, high, rhoBytes, ownerBytes))
    }
    @Synchronized override fun close() {
        rhoBytes.fill(0); ownerBytes.fill(0); low = 0; high = 0; closed = true
    }
    override fun toString(): String = "ConfidentialOutputNote([REDACTED])"
}

/** Owned optional redemption change; no change is supplied for full redemption. */
class ConfidentialChangeNote(amount: BigInteger, rho: ByteArray) : AutoCloseable {
    private var low: Long
    private var high: Long
    private val rhoBytes: ByteArray
    private var closed = false
    init {
        validateAmount(amount); validateWord(rho)
        low = amount.toLong(); high = amount.shiftRight(64).toLong(); rhoBytes = rho.copyOf()
    }
    /**
     * Create an independent owned input using Core's default change diversifier.
     * Persist the opening securely before proving consumes it; reconstruct it and call this
     * method once its authenticated leaf index is known. This does not authenticate membership.
     * Closing either copy leaves the other copy intact; a closed change cannot be converted.
     */
    fun toInput(leafIndex: Int): ConfidentialInputNote =
        toInputWithDefault(leafIndex) { ConfidentialOwnerTag.defaultDiversifier() }

    @Synchronized internal fun toInputWithDefault(leafIndex: Int, defaultDiversifier: () -> ByteArray): ConfidentialInputNote {
        if (closed) throw ConfidentialProverException(-2)
        require(leafIndex in 0 until 65_536) { "leafIndex is outside the fixed tree" }
        val diversifier = defaultDiversifier()
        return try { ConfidentialInputNote.fromOwnedLimbs(low, high, rhoBytes, diversifier, leafIndex) }
        finally { diversifier.fill(0) }
    }

    @Synchronized internal fun append(backend: ConfidentialProverBackend, job: Long) {
        if (closed) throw ConfidentialProverException(-2)
        checkWalletStatus(backend.jobOutput(job, low, high, rhoBytes, ByteArray(0)))
    }
    @Synchronized override fun close() { rhoBytes.fill(0); low = 0; high = 0; closed = true }
    override fun toString(): String = "ConfidentialChangeNote([REDACTED])"
}

/** Authenticated expected root and bounded tree evidence. Proving consumes this owned snapshot. */
sealed class ConfidentialTreeEvidence(root: ByteArray) : AutoCloseable {
    private val rootBytes: ByteArray
    init { validateWord(root); rootBytes = root.copyOf() }
    internal fun root(): ByteArray = rootBytes.copyOf()
    internal abstract fun append(backend: ConfidentialProverBackend, job: Long, inputs: Int)

    /** Complete commitment prefix, including a full 65,536-leaf tree. */
    class Commitments(root: ByteArray, leaves: List<ByteArray>) : ConfidentialTreeEvidence(root) {
        private val packed: ByteArray
        private var closed = false
        init {
            require(leaves.size <= 65_536) { "tree exceeds its fixed capacity" }
            leaves.forEach(::validateWord)
            packed = ByteArray(leaves.size * 32)
            leaves.forEachIndexed { index, leaf -> leaf.copyInto(packed, index * 32) }
        }
        @Synchronized override fun append(backend: ConfidentialProverBackend, job: Long, inputs: Int) {
            if (closed) throw ConfidentialProverException(-2)
            checkWalletStatus(backend.jobCommitments(job, packed))
        }
        @Synchronized override fun close() { packed.fill(0); closed = true }
        override fun toString(): String = "ConfidentialTreeEvidence.Commitments([REDACTED])"
    }

    /** One 16-level path per actual input in the same order; no absent-input path. */
    class Paths(root: ByteArray, paths: List<ZkAssetMerklePath>) : ConfidentialTreeEvidence(root) {
        private val siblings: ByteArray
        private val directions: ByteArray
        private val count: Int = paths.size
        private var closed = false
        init {
            require(paths.size in 1..2) { "supply one or two actual membership paths" }
            siblings = ByteArray(paths.size * 16 * 32)
            directions = ByteArray(paths.size * 16)
            try {
                paths.forEachIndexed { index, path ->
                    require(path.rootAtHeight.contentEquals(root)) { "path root differs from expected root" }
                    val words = path.siblings
                    val bits = path.directions
                    try {
                        require(words.size == 16 && bits.size == 16) { "membership path must have 16 levels" }
                        words.forEachIndexed { level, word -> word.copyInto(siblings, index * 512 + level * 32) }
                        bits.copyInto(directions, index * 16)
                    } finally { words.forEach { it.fill(0) }; bits.fill(0) }
                }
            } catch (error: Throwable) { siblings.fill(0); directions.fill(0); throw error }
        }
        @Synchronized override fun append(backend: ConfidentialProverBackend, job: Long, inputs: Int) {
            if (closed) throw ConfidentialProverException(-2)
            if (count != inputs) throw ConfidentialProverException(-13)
            checkWalletStatus(backend.jobPaths(job, siblings, directions))
        }
        @Synchronized override fun close() { siblings.fill(0); directions.fill(0); closed = true }
        override fun toString(): String = "ConfidentialTreeEvidence.Paths([REDACTED])"
    }
}

/** Public locally verified proof material; it neither submits nor authorizes a ledger transaction. */
class ConfidentialProof internal constructor(
    @JvmField val relation: Relation,
    @JvmField val backend: String,
    proof: ByteArray,
    root: ByteArray,
    nullifiers: List<ByteArray>,
    outputCommitments: List<ByteArray>,
) {
    enum class Relation { TRANSFER, FULL_REDEMPTION, REDEMPTION_WITH_CHANGE }
    private val proofBytes = proof.copyOf()
    private val rootBytes = root.copyOf()
    private val nullifierBytes = nullifiers.map { it.copyOf() }
    private val outputBytes = outputCommitments.map { it.copyOf() }
    val proof: ByteArray get() = proofBytes.copyOf()
    val root: ByteArray get() = rootBytes.copyOf()
    val nullifiers: List<ByteArray> get() = nullifierBytes.map { it.copyOf() }
    val outputCommitments: List<ByteArray> get() = outputBytes.map { it.copyOf() }

    companion object {
        internal fun decode(json: ByteArray): ConfidentialProof {
            require(json.size <= 16 * 1024 * 1024) { "native public proof result exceeds its limit" }
            val value = JsonParser.parse(String(json, StandardCharsets.UTF_8)) as? Map<*, *>
                ?: throw ConfidentialProverException(-100)
            require(value.keys == setOf("relation", "backend", "proof_hex", "root_hex", "nullifiers_hex", "output_commitments_hex")) { "invalid native public proof result" }
            fun bytes(value: Any?, length: Int? = null): ByteArray {
                val text = value as? String ?: throw ConfidentialProverException(-100)
                require(text.length % 2 == 0 && (length == null || text.length == length * 2)) { "invalid native public proof hex" }
                val output = ByteArray(text.length / 2)
                for (i in output.indices) {
                    val a = Character.digit(text[i * 2], 16); val b = Character.digit(text[i * 2 + 1], 16)
                    require(a >= 0 && b >= 0) { "invalid native public proof hex" }
                    output[i] = ((a shl 4) or b).toByte()
                }
                return output
            }
            fun words(key: String): List<ByteArray> {
                val items = value[key] as? List<*> ?: throw ConfidentialProverException(-100)
                require(items.size <= 2) { "invalid native public proof count" }
                return items.map { bytes(it, 32) }
            }
            val relation = when (value["relation"]) {
                "confidential_transfer" -> Relation.TRANSFER
                "confidential_full_unshield" -> Relation.FULL_REDEMPTION
                "confidential_change_unshield" -> Relation.REDEMPTION_WITH_CHANGE
                else -> throw ConfidentialProverException(-100)
            }
            val backend = value["backend"] as? String ?: throw ConfidentialProverException(-100)
            require(backend == "pipa-r/pasta") { "invalid native confidential proof backend" }
            return ConfidentialProof(relation, backend, bytes(value["proof_hex"]), bytes(value["root_hex"], 32), words("nullifiers_hex"), words("output_commitments_hex"))
        }
    }
}

/**
 * Canonical local wallet prover. The native Core owner chooses the relation and key and verifies its
 * result. Run [proveTransfer] and [proveUnshield] on an application-owned background executor; they
 * block while proving. Closing prevents new jobs and leaves already accepted work alive.
 *
 * Use `use` or explicit [close]. Input/output notes and tree snapshots are consumed and cleared on
 * success or failure. Original caller arrays and immutable BigInteger values remain caller-owned;
 * this API cannot erase copies held by the JVM. Local proofs are not ledger authorizations.
 */
class ConfidentialProver internal constructor(
    private var handle: Long,
    private val backend: ConfidentialProverBackend,
) : AutoCloseable {
    @Synchronized private fun prepare(operation: Int, root: ByteArray, amount: BigInteger): Long {
        if (handle == 0L) throw ConfidentialProverException(-2)
        return walletHandle(backend.jobCreate(handle, operation, root, amount.toLong(), amount.shiftRight(64).toLong()))
    }
    fun proveTransfer(tree: ConfidentialTreeEvidence, inputs: List<ConfidentialInputNote>, outputs: List<ConfidentialOutputNote>): ConfidentialProof {
        var job = 0L
        try {
            if (inputs.size !in 1..2) throw ConfidentialProverException(-11)
            if (outputs.size !in 1..2) throw ConfidentialProverException(-18)
            job = prepare(0, tree.root(), BigInteger.ZERO)
            inputs.forEach { it.append(backend, job) }; outputs.forEach { it.append(backend, job) }
            tree.append(backend, job, inputs.size)
            return ConfidentialProof.decode(backend.jobProve(job))
        } finally {
            try { if (job != 0L) backend.jobClose(job) }
            finally { inputs.forEach { it.close() }; outputs.forEach { it.close() }; tree.close() }
        }
    }
    fun proveUnshield(tree: ConfidentialTreeEvidence, inputs: List<ConfidentialInputNote>, publicAmount: BigInteger, change: ConfidentialChangeNote? = null): ConfidentialProof {
        var job = 0L
        try {
            if (inputs.size !in 1..2) throw ConfidentialProverException(-11)
            validateAmount(publicAmount)
            job = prepare(1, tree.root(), publicAmount)
            inputs.forEach { it.append(backend, job) }; change?.append(backend, job)
            tree.append(backend, job, inputs.size)
            return ConfidentialProof.decode(backend.jobProve(job))
        } finally {
            try { if (job != 0L) backend.jobClose(job) }
            finally { inputs.forEach { it.close() }; change?.close(); tree.close() }
        }
    }
    @Synchronized override fun close() {
        val previous = handle; handle = 0
        if (previous != 0L) checkWalletStatus(backend.close(previous))
    }
    override fun toString(): String = "ConfidentialProver([REDACTED])"
    companion object {
        /** Copy a wallet key once into the native clearing owner; callers retain their original array. */
        @JvmStatic fun create(networkId: NetworkId, assetDefinitionId: String, spendKey: ByteArray): ConfidentialProver {
            validateWord(spendKey)
            require(assetDefinitionId.length <= 512 && AssetDefinitionIdEncoder.isCanonicalAddress(assetDefinitionId)) { "assetDefinitionId must be canonical" }
            val asset = assetDefinitionId.toByteArray(StandardCharsets.UTF_8)
            require(asset.size <= 512) { "assetDefinitionId exceeds its byte limit" }
            val key = spendKey.copyOf()
            return try {
                val backend = JniConfidentialProverBackend
                backend.requireAvailable()
                ConfidentialProver(walletHandle(backend.create(networkId.bytes(), asset, key)), backend)
            } finally { key.fill(0) }
        }
    }
}

internal interface ConfidentialProverBackend {
    fun create(network: ByteArray, asset: ByteArray, key: ByteArray): Long
    fun close(handle: Long): Int
    fun jobCreate(handle: Long, operation: Int, root: ByteArray, low: Long, high: Long): Long
    fun jobInput(job: Long, low: Long, high: Long, rho: ByteArray, diversifier: ByteArray, index: Long): Int
    fun jobOutput(job: Long, low: Long, high: Long, rho: ByteArray, owner: ByteArray): Int
    fun jobCommitments(job: Long, leaves: ByteArray): Int
    fun jobPaths(job: Long, siblings: ByteArray, directions: ByteArray): Int
    fun jobProve(job: Long): ByteArray
    fun jobClose(job: Long): Int
}
internal object ConfidentialProverNative {
    @JvmStatic external fun revision(): Int
    @JvmStatic external fun create(network: ByteArray, asset: ByteArray, key: ByteArray): Long
    @JvmStatic external fun close(handle: Long): Int
    @JvmStatic external fun jobCreate(handle: Long, operation: Int, root: ByteArray, low: Long, high: Long): Long
    @JvmStatic external fun jobInput(job: Long, low: Long, high: Long, rho: ByteArray, diversifier: ByteArray, index: Long): Int
    @JvmStatic external fun jobOutput(job: Long, low: Long, high: Long, rho: ByteArray, owner: ByteArray): Int
    @JvmStatic external fun jobCommitments(job: Long, leaves: ByteArray): Int
    @JvmStatic external fun jobPaths(job: Long, siblings: ByteArray, directions: ByteArray): Int
    @JvmStatic external fun jobProve(job: Long): ByteArray
    @JvmStatic external fun jobClose(job: Long): Int
}
internal object JniConfidentialProverBackend : ConfidentialProverBackend {
    fun requireAvailable() {
        requireConfidentialNativeContract(PrivacyNativeBridge.isNativeAvailable()) { ConfidentialProverNative.revision() }
    }
    override fun create(network: ByteArray, asset: ByteArray, key: ByteArray) = ConfidentialProverNative.create(network, asset, key)
    override fun close(handle: Long) = ConfidentialProverNative.close(handle)
    override fun jobCreate(handle: Long, operation: Int, root: ByteArray, low: Long, high: Long) = ConfidentialProverNative.jobCreate(handle, operation, root, low, high)
    override fun jobInput(job: Long, low: Long, high: Long, rho: ByteArray, diversifier: ByteArray, index: Long) = ConfidentialProverNative.jobInput(job, low, high, rho, diversifier, index)
    override fun jobOutput(job: Long, low: Long, high: Long, rho: ByteArray, owner: ByteArray) = ConfidentialProverNative.jobOutput(job, low, high, rho, owner)
    override fun jobCommitments(job: Long, leaves: ByteArray) = ConfidentialProverNative.jobCommitments(job, leaves)
    override fun jobPaths(job: Long, siblings: ByteArray, directions: ByteArray) = ConfidentialProverNative.jobPaths(job, siblings, directions)
    override fun jobProve(job: Long) = ConfidentialProverNative.jobProve(job)
    override fun jobClose(job: Long) = ConfidentialProverNative.jobClose(job)
}

/** Missing or mismatched delivered native code has a stable wrapper-only error code. */
internal fun requireConfidentialNativeContract(available: Boolean, revision: () -> Int) {
    if (!available) throw ConfidentialProverException(-101)
    val observed = try { revision() }
    catch (_: LinkageError) { throw ConfidentialProverException(-101) }
    catch (_: RuntimeException) { throw ConfidentialProverException(-101) }
    if (observed != 1) throw ConfidentialProverException(-101)
}
