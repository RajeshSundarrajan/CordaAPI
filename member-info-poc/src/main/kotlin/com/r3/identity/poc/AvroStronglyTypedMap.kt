package com.r3.identity.poc

import net.corda.data.test.AvroEndpointInfo
import net.corda.data.test.AvroEndpoints
import net.corda.data.test.AvroMemberContextEntry
import net.corda.data.test.AvroMemberInfo
import net.corda.data.test.AvroParty
import net.corda.data.test.AvroPublicKeys
import net.corda.impl.application.identity.PartyImpl
import net.corda.impl.application.node.EndpointInfoImpl
import net.corda.impl.application.node.MemberContextImpl
import net.corda.impl.application.node.MemberInfoExtension
import net.corda.impl.application.node.MemberInfoImpl
import net.corda.internal.application.node.EndpointInfo
import net.corda.v5.application.identity.CordaX500Name
import net.corda.v5.application.identity.Party
import net.corda.v5.application.node.MemberInfo
import org.apache.avro.file.DataFileReader
import org.apache.avro.file.DataFileWriter
import org.apache.avro.io.DatumReader
import org.apache.avro.io.DatumWriter
import org.apache.avro.specific.SpecificDatumReader
import org.apache.avro.specific.SpecificDatumWriter
import java.io.File
import java.security.PublicKey
import java.security.cert.CertPath

@Suppress("UNCHECKED_CAST", "ComplexMethod")
internal fun MemberInfo.convertToAvroRecord(keyEncodingService: KeyEncodingService): AvroMemberInfo {
    val avroMemberProvidedContext = mutableMapOf<String, AvroMemberContextEntry>()
    this.memberProvidedContext.keys.forEach { key ->
        val value = this.memberProvidedContext[key]
        val keyAndAvroValue: Pair<String,Any> = when(key) {
            MemberInfoExtension.ENDPOINTS ->  {
                val endpoints = memberProvidedContext[MemberInfoExtension.ENDPOINTS] as List<EndpointInfo>
                MemberInfoExtension.ENDPOINTS to AvroEndpoints(endpoints.map {
                    AvroEndpointInfo(it.url, it.protocolVersion)
                })
            }
            MemberInfoExtension.PARTY ->  {
                val party = memberProvidedContext[MemberInfoExtension.PARTY] as Party
                MemberInfoExtension.PARTY to AvroParty(party.name.toString(), keyEncodingService.encodeAsString(party.owningKey))
            }
            MemberInfoExtension.IDENTITY_KEYS -> {
                val identityKeys : List<PublicKey> = memberProvidedContext[MemberInfoExtension.IDENTITY_KEYS] as List<PublicKey>
                MemberInfoExtension.IDENTITY_KEYS to AvroPublicKeys(identityKeys.map{ keyEncodingService.encodeAsString(it)})
            }
            MemberInfoExtension.CERTIFICATE -> {
                val certificate: CertPath? =  memberProvidedContext[MemberInfoExtension.CERTIFICATE] as CertPath?
                MemberInfoExtension.CERTIFICATE to certificate.toString() //TODO
            }
            MemberInfoExtension.PLATFORM_VERSION -> {
                MemberInfoExtension.PLATFORM_VERSION to memberProvidedContext[MemberInfoExtension.PLATFORM_VERSION] as Int
            }
            MemberInfoExtension.SERIAL -> {
                MemberInfoExtension.SERIAL to memberProvidedContext[MemberInfoExtension.SERIAL] as Long
            }
            MemberInfoExtension.SOFTWARE_VERSION -> {
                MemberInfoExtension.SOFTWARE_VERSION to memberProvidedContext[MemberInfoExtension.SOFTWARE_VERSION] as String
            }
            else -> {
                key to value.toString()
            }
        }
        avroMemberProvidedContext[keyAndAvroValue.first] = AvroMemberContextEntry(keyAndAvroValue.second)
    }
    val avroMgmProvidedContext = mutableMapOf<String, AvroMemberContextEntry>()
    this.mgmProvidedContext.keys.forEach { key ->
        val value = this.mgmProvidedContext[key]!!
        val x: Pair<String, Any> = when (key) {
            MemberInfoExtension.STATUS -> {
                MemberInfoExtension.STATUS to value
            }
            else -> {
                key to value
            }
        }
        avroMgmProvidedContext[x.first] = AvroMemberContextEntry(x.second)
    }
    return AvroMemberInfo(avroMemberProvidedContext, avroMgmProvidedContext)
}

@Suppress( "ComplexMethod")
fun AvroMemberInfo.convertToMemberInfo(keyEncodingService: KeyEncodingService): MemberInfo {
    val memberProvidedContext = mutableMapOf<String,Any>()
    this.memberProvidedContext.forEach { (key,value) ->
        val memberInfoValue: Any = when(val entry = value.value) {
            is AvroEndpoints -> { //MemberInfoExtension.ENDPOINTS
                entry.url.map { EndpointInfoImpl(it.url, it.protocolVersion) }
            }
            is AvroParty ->  { //MemberInfoExtension.PARTY
                PartyImpl(CordaX500Name.parse(entry.name), keyEncodingService.decodePublicKey(entry.key))
            }
            is AvroPublicKeys -> { //MemberInfoExtension.IDENTITY_KEYS
                entry.key.map{ keyEncodingService.decodePublicKey(it)}
            }
// Missing custom type for certificate to distingish from String
//            is AvroCertificate -> {
//                val certificate: CertPath? =  memberProvidedContext[MemberInfoExtension.CERTIFICATE] as CertPath?
//                MemberInfoExtension.CERTIFICATE to entry.certificate //TODO String to CertPath
//            }
            is Int -> { //MemberInfoExtension.PLATFORM_VERSION
                 entry
            }
            is Long -> { //MemberInfoExtension.SERIAL
                entry
            }
            else -> { // MemberInfoExtension.SOFTWARE_VERSION
                value.toString()
            }
        }
        memberProvidedContext[key] = memberInfoValue
    }
    val mgmProvidedContext = mutableMapOf<String,Any>()
    this.mgmProvidedContext.forEach { (key,value) ->
//        val memberInfoValue: Any = when (key) {
//            else -> {
//                value
//            }
//        }
//        mgmProvidedContext[key] = memberInfoValue
        mgmProvidedContext[key] = value
    }
    return MemberInfoImpl(
        MemberContextImpl(memberProvidedContext.toSortedMap()),
        MemberContextImpl(mgmProvidedContext.toSortedMap())
    )
}


fun main() {
    val keyEncodingService = DummyKeyEncodingService()
    val memberInfo = createExampleMemberInfo(pubKey = keyEncodingService.pubKeys.keys.first())
    println("MemberInfo to serialize:")
    println(memberInfo)

    val userDatumWriter: DatumWriter<AvroMemberInfo> = SpecificDatumWriter(AvroMemberInfo::class.java)
    val dataFileWriter: DataFileWriter<AvroMemberInfo> = DataFileWriter(userDatumWriter)

    val avroMemberInfo = memberInfo.convertToAvroRecord(keyEncodingService)

    dataFileWriter.create(avroMemberInfo.schema, File("avro-strongly-typed-map.avro"))
    dataFileWriter.append(avroMemberInfo)
    dataFileWriter.close()

    val userDatumReader: DatumReader<AvroMemberInfo> = SpecificDatumReader(AvroMemberInfo::class.java)
    val dataFileReader: DataFileReader<AvroMemberInfo> =
        DataFileReader(File("avro-strongly-typed-map.avro"), userDatumReader)
    var user: AvroMemberInfo? = null

    println("MemberInfo after deserialization:")
    while (dataFileReader.hasNext()) {
        user = dataFileReader.next(user)
        val recreatedMemberInfo = user.convertToMemberInfo(DummyKeyEncodingService())
        println(recreatedMemberInfo)
    }
}