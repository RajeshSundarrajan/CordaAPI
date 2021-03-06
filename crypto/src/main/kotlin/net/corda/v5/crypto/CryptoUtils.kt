@file:JvmName("CryptoUtils")

package net.corda.v5.crypto

import net.corda.v5.base.util.toBase58
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey

private fun messageDigestSha256(): MessageDigest =
    MessageDigest.getInstance(DigestAlgorithmName.SHA2_256.name)

fun ByteArray.sha256Bytes(): ByteArray = messageDigestSha256().digest(this)

fun PublicKey.sha256Bytes(): ByteArray = messageDigestSha256().digest(encoded)

/** Render a public key to its hash (in Base58) of its serialised form using the DL prefix. */
fun PublicKey.toStringShort(): String = "DL" + this.sha256Bytes().toBase58()

/**
 * Return a [Set] of the contained leaf keys if this is a [CompositeKey].
 * Otherwise, return a [Set] with a single element (this [PublicKey]).
 * <i>Note that leaf keys cannot be of type [CompositeKey].</i>
 */
val PublicKey.keys: Set<PublicKey> get() = (this as? CompositeKey)?.leafKeys ?: setOf(this)

/** Return true if [otherKey] fulfils the requirements of this [PublicKey]. */
fun PublicKey.isFulfilledBy(otherKey: PublicKey): Boolean = isFulfilledBy(setOf(otherKey))

/** Return true if [otherKeys] fulfil the requirements of this [PublicKey]. */
fun PublicKey.isFulfilledBy(otherKeys: Iterable<PublicKey>): Boolean =
    (this as? CompositeKey)?.isFulfilledBy(otherKeys) ?: (this in otherKeys)

/**
 * Checks whether any of the given [keys] matches a leaf on the [CompositeKey] tree or a single [PublicKey].
 *
 * <i>Note that this function checks against leaves, which cannot be of type [CompositeKey]. Due to that, if any of the
 * [otherKeys] is a [CompositeKey], this function will not find a match.</i>
 */
fun PublicKey.containsAny(otherKeys: Iterable<PublicKey>): Boolean {
    return if (this is CompositeKey) keys.intersect(otherKeys).isNotEmpty()
    else this in otherKeys
}

/** Returns the set of all [PublicKey]s of the signatures. */
fun Iterable<DigitalSignature.WithKey>.byKeys() = map { it.by }.toSet()

// Allow Kotlin destructuring:
// val (private, public) = keyPair
/* The [PrivateKey] of this [KeyPair]. */
operator fun KeyPair.component1(): PrivateKey = this.private

/* The [PublicKey] of this [KeyPair]. */
operator fun KeyPair.component2(): PublicKey = this.public
