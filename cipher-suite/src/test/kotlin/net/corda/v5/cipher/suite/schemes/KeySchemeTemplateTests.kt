package net.corda.v5.cipher.suite.schemes

import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows

class KeySchemeTemplateTests {
    @Test
    @Timeout(5)
    fun `Should throw IllegalArgumentException when initializing with blank code name`() {
        assertThrows<IllegalArgumentException> {
            KeySchemeTemplate(
                codeName = "  ",
                algorithmOIDs = listOf(AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256k1)),
                algorithmName = "EC",
                algSpec = null,
                keySize = null
            )
        }
    }

    @Test
    @Timeout(5)
    fun `Should throw IllegalArgumentException when initializing with empty algorithmOIDs`() {
        assertThrows<IllegalArgumentException> {
            KeySchemeTemplate(
                codeName = ECDSA_SECP256K1_CODE_NAME,
                algorithmOIDs = emptyList(),
                algorithmName = "EC",
                algSpec = null,
                keySize = null
            )
        }
    }

    @Test
    @Timeout(5)
    fun `Should throw IllegalArgumentException when initializing with blank algorithm name`() {
        assertThrows<IllegalArgumentException> {
            KeySchemeTemplate(
                codeName = ECDSA_SECP256K1_CODE_NAME,
                algorithmOIDs = listOf(AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256k1)),
                algorithmName = "  ",
                algSpec = null,
                keySize = null
            )
        }
    }
}