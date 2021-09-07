package com.r3.identity.poc

import net.corda.impl.application.identity.PartyImpl
import net.corda.impl.application.node.EndpointInfoImpl
import net.corda.impl.application.node.MemberContextImpl
import net.corda.impl.application.node.MemberInfoExtension
import net.corda.impl.application.node.MemberInfoImpl
import net.corda.impl.application.node.DEFAULT_MEMBER_GROUP_ID
import net.corda.internal.application.node.EndpointInfo
import net.corda.v5.application.identity.CordaX500Name
import net.corda.v5.application.node.MemberInfo
import net.corda.v5.crypto.internal.Crypto
import java.security.PublicKey

interface KeyEncodingService {
    val pubKeys : Map<PublicKey,String>

    fun encodeAsString(value: PublicKey): String =
        pubKeys[value]!!


    fun decodePublicKey(value: String): PublicKey =
        pubKeys.entries.first { it.value == value }.key
}

@Suppress("EmptyDefaultConstructor")
class DummyKeyEncodingService(): KeyEncodingService {
    override val pubKeys : Map<PublicKey,String> = mapOf(
        Crypto.generateKeyPair().public to "---PEM1---",
        Crypto.generateKeyPair().public to "---PEM2---")

}

fun createExampleMemberInfo( principal : String = "O=Alice,L=London,C=GB",
                                 pubKey : PublicKey = Crypto.generateKeyPair().public) : MemberInfo =
    MemberInfoImpl(
        MemberContextImpl(
            sortedMapOf(
                MemberInfoExtension.PARTY to PartyImpl(CordaX500Name.parse(principal), pubKey),
                MemberInfoExtension.GROUP_ID to DEFAULT_MEMBER_GROUP_ID,
                MemberInfoExtension.IDENTITY_KEYS to listOf(pubKey),
                MemberInfoExtension.ENDPOINTS to listOf(
                    EndpointInfoImpl("https://localhost:10000", EndpointInfo.DEFAULT_PROTOCOL_VERSION),
                    EndpointInfoImpl("https://google.com", EndpointInfo.DEFAULT_PROTOCOL_VERSION)
                ),
                MemberInfoExtension.SOFTWARE_VERSION to "5.0.0",
                MemberInfoExtension.PLATFORM_VERSION to 10,
                MemberInfoExtension.SERIAL to 1L
            )
        ), MemberContextImpl(sortedMapOf("corda.status" to "xxx"))
    )