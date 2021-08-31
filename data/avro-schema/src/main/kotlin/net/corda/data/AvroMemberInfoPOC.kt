package net.corda.data

import net.corda.data.test.*
import org.apache.avro.file.DataFileReader
import org.apache.avro.file.DataFileWriter
import org.apache.avro.io.DatumReader
import org.apache.avro.io.DatumWriter
import org.apache.avro.specific.SpecificDatumReader
import org.apache.avro.specific.SpecificDatumWriter
import java.io.File

fun main() {

    val userDatumWriter: DatumWriter<AvroMemberInfo> = SpecificDatumWriter(AvroMemberInfo::class.java)

    val dataFileWriter: DataFileWriter<AvroMemberInfo> = DataFileWriter(userDatumWriter)
    val user1 = AvroMemberInfo(mapOf("key1" to AvroMemberContextEntry("1234567")), emptyMap())
    val user2 = AvroMemberInfo(mapOf("key2" to AvroMemberContextEntry(AvroParty("1234567", "alice"))), emptyMap())
    val user3 = AvroMemberInfo(
        mapOf(
            "key3" to AvroMemberContextEntry(
                AvroEndpoints(
                    listOf(
                        AvroEndpointInfo("www.r3.com", 12),
                        AvroEndpointInfo("www.corda.com", 11)
                    )
                )
            )
        ), emptyMap()
    )
    val user4 = AvroMemberInfo(
        mapOf(
            "endpoits" to AvroMemberContextEntry(
                AvroEndpoints(
                    listOf(
                        AvroEndpointInfo("www.r3.com", 12),
                        AvroEndpointInfo("www.corda.com", 11)
                    )
                )
            ),
            "keys" to AvroMemberContextEntry(AvroPublicKeys(listOf("---PEM1----", "-----PEM2-----"))),
            "serial" to AvroMemberContextEntry(123)
        ), emptyMap()
    )

    dataFileWriter.create(user1.schema, File("user.avro"))
    dataFileWriter.append(user1)
    dataFileWriter.append(user2)
    dataFileWriter.append(user3)
    dataFileWriter.append(user4)
    dataFileWriter.close()

    //val schema: Schema = Schema.Parser().parse(user1.schema)
    val userDatumReader: DatumReader<AvroMemberInfo> = SpecificDatumReader(AvroMemberInfo::class.java)
    val dataFileReader: DataFileReader<AvroMemberInfo> = DataFileReader(File("user.avro"), userDatumReader)
    var user: AvroMemberInfo? = null
    while (dataFileReader.hasNext()) {
        user = dataFileReader.next(user)
        user.memberProvidedContext.forEach {
            println(it.key + ": " + it.value)
            //for further processing
//            when (it.value.value) {
//                is AvroParty -> {
//                    println("  party type " + it.value.value::class.java)
//                }
//                is AvroEndpoints -> {
//                    println(" endpoints type  " + it.value.value::class.java)
//                }
//                else -> {
//                    println("else type " + it.value.value::class.java )
//                }
//            }
        }
    }
}