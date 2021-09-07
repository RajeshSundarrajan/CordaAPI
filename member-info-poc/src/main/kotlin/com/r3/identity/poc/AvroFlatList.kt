package com.r3.identity.poc

import net.corda.data.test.AvroFlatMap
import net.corda.data.test.AvroKeyValuePair
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
internal fun MemberInfo.convertToFlatList(keyEncodingService: KeyEncodingService): List<Pair<String, String>> {
    val result = mutableListOf<Pair<String,String>>()
    this.memberProvidedContext.keys.forEach { key ->
        val value = this.memberProvidedContext[key]
        when(key) {
            MemberInfoExtension.ENDPOINTS ->  {
                val endpoints = memberProvidedContext[MemberInfoExtension.ENDPOINTS] as List<EndpointInfo>
                endpoints.mapIndexed { index, it ->
                    result.add(Pair("${MemberInfoExtension.ENDPOINTS}.$index.protocolVersion", it.protocolVersion.toString()))
                    result.add(Pair("${MemberInfoExtension.ENDPOINTS}.$index.url", it.url))
                }
            }
            MemberInfoExtension.PARTY ->  {
                val party = memberProvidedContext[MemberInfoExtension.PARTY] as Party
                result.add(Pair("${MemberInfoExtension.PARTY}.name", party.name.toString()))
                result.add(Pair("${MemberInfoExtension.PARTY}.owningKey", keyEncodingService.encodeAsString(party.owningKey)))
            }
            MemberInfoExtension.IDENTITY_KEYS -> {
                val identityKeys : List<PublicKey> = memberProvidedContext[MemberInfoExtension.IDENTITY_KEYS] as List<PublicKey>
                identityKeys.mapIndexed{index, it ->
                    result.add(Pair("${MemberInfoExtension.IDENTITY_KEYS}.$index",keyEncodingService.encodeAsString(it)))}
            }
            MemberInfoExtension.CERTIFICATE -> {
                val certificate: CertPath? =  memberProvidedContext[MemberInfoExtension.CERTIFICATE] as CertPath?
                result.add(Pair(MemberInfoExtension.CERTIFICATE, certificate.toString())) //TODO
            }
            MemberInfoExtension.PLATFORM_VERSION -> {
                result.add(Pair(key, (memberProvidedContext[MemberInfoExtension.PLATFORM_VERSION] as Int).toString()))
            }
            MemberInfoExtension.SERIAL -> {
                result.add(Pair(key, (memberProvidedContext[MemberInfoExtension.SERIAL] as Long).toString()))
            }
            MemberInfoExtension.SOFTWARE_VERSION -> {
                result.add(Pair(key, (memberProvidedContext[MemberInfoExtension.SOFTWARE_VERSION] as String)))
            }
            else -> {
                result.add(Pair(key, value.toString()))
            }
        }
    }
    this.mgmProvidedContext.keys.forEach { key ->
        val value = this.mgmProvidedContext[key]
        when(key) {
            MemberInfoExtension.STATUS -> {
                listOf(Pair(key, value.toString()))
            }
            else -> {
                result.add(Pair(key, value.toString()))
            }
        }
    }
    return result
}

@Suppress( "ComplexMethod")
internal fun List<Pair<String, String>>.convertToMemberInfo(keyEncodingService: KeyEncodingService) : MemberInfo{
    val endpointsProtocolVersion = mutableMapOf<Int, Int>()
    val endpointsUrl = mutableMapOf<Int, String>()
    var partyName : String? = null
    var partyOwningKey : PublicKey? = null
    val identityKeys = mutableMapOf<Int, PublicKey>()
    val memberProvidedInfo = sortedMapOf<String,Any>()
    val mgmProvidedInfo = sortedMapOf<String,Any>()
    this.forEach { (key,value) ->
        val parsedKeys = key.split(".")
        when("${parsedKeys[0]}.${parsedKeys[1]}") {
            MemberInfoExtension.ENDPOINTS ->  {
                val index = parsedKeys[2].toInt()
                val subKey = parsedKeys[3]
                when(subKey) {
                    "protocolVersion" -> endpointsProtocolVersion[index] = value.toInt()
                    "url" -> endpointsUrl[index] = value
                }
            }
            MemberInfoExtension.PARTY ->  {
                val subKey = parsedKeys[2]
                when(subKey) {
                    "name" -> partyName= value
                    "owningKey" -> partyOwningKey = keyEncodingService.decodePublicKey(value)
                }
            }
            MemberInfoExtension.IDENTITY_KEYS -> {
                val index = parsedKeys[2].toInt()
                identityKeys[index] = keyEncodingService.decodePublicKey(value)
            }
            MemberInfoExtension.CERTIFICATE -> {
                val certificate: CertPath? = null //TODO
                memberProvidedInfo[MemberInfoExtension.CERTIFICATE] = certificate
            }
            MemberInfoExtension.PLATFORM_VERSION -> {
                memberProvidedInfo[MemberInfoExtension.PLATFORM_VERSION] = value.toInt()
            }
            MemberInfoExtension.SERIAL -> {
                memberProvidedInfo[MemberInfoExtension.SERIAL] = value.toLong()
            }
            MemberInfoExtension.SOFTWARE_VERSION -> {
                memberProvidedInfo[MemberInfoExtension.SOFTWARE_VERSION] = value
            }
            MemberInfoExtension.STATUS -> {
                mgmProvidedInfo[MemberInfoExtension.STATUS] = value
            }
            else -> { //unknown member or mgm?
                memberProvidedInfo["${parsedKeys[0]}.${parsedKeys[1]}"] = value
            }
        }
    }

    if( partyName != null && partyOwningKey != null) {
        memberProvidedInfo[MemberInfoExtension.PARTY] = PartyImpl(CordaX500Name.parse(partyName!!), partyOwningKey!!)
    }

    memberProvidedInfo[MemberInfoExtension.IDENTITY_KEYS] = identityKeys.toSortedMap().values.toList()
    if(endpointsProtocolVersion.keys == endpointsUrl.keys){
        val temp = mutableListOf<EndpointInfo>()
        endpointsProtocolVersion.keys.forEach {
            temp.add(EndpointInfoImpl(endpointsUrl[it]!!, endpointsProtocolVersion[it]!!))
        }
        memberProvidedInfo[MemberInfoExtension.ENDPOINTS] = temp
    }

    return MemberInfoImpl( MemberContextImpl(memberProvidedInfo),
        MemberContextImpl(sortedMapOf())
    )
}

fun main() {
    val keyEncodingService = DummyKeyEncodingService()
    val memberInfo = createExampleMemberInfo(pubKey = keyEncodingService.pubKeys.keys.first())
    println("MemberInfo to serialize:")
    println(memberInfo)

    val userDatumWriter: DatumWriter<AvroFlatMap> = SpecificDatumWriter(AvroFlatMap::class.java)
    val dataFileWriter: DataFileWriter<AvroFlatMap> = DataFileWriter(userDatumWriter)

    val flatList = memberInfo.convertToFlatList(keyEncodingService)
    val avroMemberInfo = AvroFlatMap(flatList.map { AvroKeyValuePair(it.first, it.second) })
    dataFileWriter.create(avroMemberInfo.schema, File("avro-strongly-typed-map.avro"))
    dataFileWriter.append(avroMemberInfo)
    dataFileWriter.close()

    val userDatumReader: DatumReader<AvroFlatMap> = SpecificDatumReader(AvroFlatMap::class.java)
    val dataFileReader: DataFileReader<AvroFlatMap> =
        DataFileReader(File("avro-strongly-typed-map.avro"), userDatumReader)
    var user: AvroFlatMap? = null

    println("MemberInfo after deserialization:")
    while (dataFileReader.hasNext()) {
        user = dataFileReader.next(user)
        val recreatedMemberInfo = user.entries.map { Pair(it.key, it.value)}.convertToMemberInfo(keyEncodingService)
        println(recreatedMemberInfo)
    }
}