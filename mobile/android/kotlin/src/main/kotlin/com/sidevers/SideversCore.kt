/*
 * SideversCore.kt — Kotlin facade for the Sidevers protocol's core
 * operations, backed by the `sidevers-jni` Rust bridge.
 *
 * Loaded by Android apps as part of the Sidevers AAR. To produce the .so
 * files this depends on, run:
 *
 *   ./mobile/build-android.sh
 *
 * which uses cargo-ndk to compile sidevers-jni for each Android ABI.
 *
 * Memory ownership: the JNI bridge copies bytes across the FFI boundary,
 * so Kotlin holds ordinary JVM-owned ByteArray / String values — no manual
 * release required.
 *
 * Errors: every operation that can fail throws a RuntimeException with the
 * underlying Rust error message. Production apps should wrap these in
 * domain-specific sealed-class results.
 */

package com.sidevers

object SideversCore {
    init {
        System.loadLibrary("sidevers_jni")
    }

    /** Address kind tag — matches the protocol spec's bech32m HRPs. */
    enum class AddressKind(val code: Byte) {
        SIDE(0),
        VERSE(1),
    }

    // ---------------------------------------------------------------------
    // Key generation
    // ---------------------------------------------------------------------

    /** Generate a fresh master seed from the OS CSPRNG. Returns 32 bytes. */
    fun generateMaster(): ByteArray = nativeKeygenMaster()

    /** Derive a side seed from a master seed under a UTF-8 label. */
    fun deriveSide(masterSeed: ByteArray, label: String): ByteArray {
        require(masterSeed.size == 32) { "master seed must be 32 bytes" }
        return nativeDeriveSide(masterSeed, label)
    }

    /** Compute the public key for any seed (master, side, or verse). */
    fun pubkeyFromSeed(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "seed must be 32 bytes" }
        return nativePubkeyFromSeed(seed)
    }

    // ---------------------------------------------------------------------
    // Addresses
    // ---------------------------------------------------------------------

    /** Encode a 32-byte pubkey as a bech32m Sidevers address. */
    fun encodeAddress(pubkey: ByteArray, kind: AddressKind): String {
        require(pubkey.size == 32) { "pubkey must be 32 bytes" }
        return nativeAddressEncode(pubkey, kind.code)
    }

    // ---------------------------------------------------------------------
    // Direct messages
    // ---------------------------------------------------------------------

    /**
     * Build a signed, encrypted DirectMessage envelope addressed from
     * `senderSeed`'s side to `recipientPubkey`. Returns the wire bytes.
     */
    fun sealDirectMessage(
        senderSeed: ByteArray,
        recipientPubkey: ByteArray,
        text: String,
    ): ByteArray {
        require(senderSeed.size == 32) { "sender seed must be 32 bytes" }
        require(recipientPubkey.size == 32) { "recipient pubkey must be 32 bytes" }
        return nativeSealDirectMessage(senderSeed, recipientPubkey, text)
    }

    /**
     * Verify, decrypt, and return the plaintext text of a DirectMessage
     * envelope addressed to `recipientSeed`'s side.
     */
    fun openDirectMessageText(recipientSeed: ByteArray, wire: ByteArray): String {
        require(recipientSeed.size == 32) { "recipient seed must be 32 bytes" }
        return nativeOpenDirectMessageText(recipientSeed, wire)
    }

    // ---------------------------------------------------------------------
    // Linkage proofs
    // ---------------------------------------------------------------------

    /** Sign a fresh linkage proof binding two sides the caller owns. */
    fun signLinkage(sideA: ByteArray, sideB: ByteArray, issuedAtUnixSeconds: Long): ByteArray {
        require(sideA.size == 32 && sideB.size == 32) { "side seeds must be 32 bytes" }
        return nativeSignLinkage(sideA, sideB, issuedAtUnixSeconds)
    }

    // ---------------------------------------------------------------------
    // Raw JNI declarations — bind to functions in sidevers-jni's lib.rs.
    // ---------------------------------------------------------------------

    @JvmStatic external fun nativeKeygenMaster(): ByteArray
    @JvmStatic external fun nativeDeriveSide(masterSeed: ByteArray, label: String): ByteArray
    @JvmStatic external fun nativePubkeyFromSeed(seed: ByteArray): ByteArray
    @JvmStatic external fun nativeAddressEncode(pubkey: ByteArray, kind: Byte): String
    @JvmStatic external fun nativeSealDirectMessage(
        senderSeed: ByteArray,
        recipientPubkey: ByteArray,
        text: String,
    ): ByteArray
    @JvmStatic external fun nativeOpenDirectMessageText(
        recipientSeed: ByteArray,
        wire: ByteArray,
    ): String
    @JvmStatic external fun nativeSignLinkage(
        sideA: ByteArray,
        sideB: ByteArray,
        issuedAt: Long,
    ): ByteArray
}
