package net.corda.v5.membership.identity

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import javax.security.auth.x500.X500Principal
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MemberX500Name_NoUse_Tests {
    companion object {
        private val commonName = "Service Name"
        private val organisationUnit = "Org Unit"
        private val organisation = "Bank A"
        private val locality = "New York"
        private val country = "US"
    }

    @Test
    fun `service name with organisational unit`() {
        val name = MemberX500Name_NoUse.parse("O=Bank A, L=New York, C=US, OU=Org Unit, CN=Service Name")
        Assertions.assertEquals(commonName, name.commonName)
        Assertions.assertEquals(organisationUnit, name.organisationUnit)
        Assertions.assertEquals(organisation, name.organisation)
        Assertions.assertEquals(locality, name.locality)
        Assertions.assertEquals(MemberX500Name_NoUse.parse(name.toString()), name)
        Assertions.assertEquals(MemberX500Name_NoUse.build(name.x500Principal), name)
    }

    @Test
    fun `service name`() {
        val name = MemberX500Name_NoUse.parse("O=Bank A, L=New York, C=US, CN=Service Name")
        Assertions.assertEquals(commonName, name.commonName)
        Assertions.assertNull(name.organisationUnit)
        Assertions.assertEquals(organisation, name.organisation)
        Assertions.assertEquals(locality, name.locality)
        Assertions.assertEquals(MemberX500Name_NoUse.parse(name.toString()), name)
        Assertions.assertEquals(MemberX500Name_NoUse.build(name.x500Principal), name)
    }

    @Test
    fun `legal entity name is required`() {
        assertFailsWith<IllegalArgumentException> {
            MemberX500Name_NoUse.parse("O=Bank A, L=New York, C=US")
        }
    }

    @Test
    fun `rejects name with no organisation`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("L=New York, C=US, OU=Org Unit, CN=Service Name")
        }
    }

    @Test
    fun `rejects name with no locality`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=Bank A, C=US, OU=Org Unit, CN=Service Name")
        }
    }

    @Test
    fun `rejects name with no country`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=Bank A, L=New York, OU=Org Unit, CN=Service Name")
        }
    }

    @Test
    fun `rejects name with unsupported attribute`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=Bank A, L=New York, C=US, SN=blah")
        }
    }

    @Test
    fun `rejects organisation (but not other attributes) with non-latin letters`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=Bཛྷa, L=New York, C=DE, OU=Org Unit, CN=Service Name")
        }
        // doesn't throw
        validateLocalityAndOrganisationalUnitAndCommonName("Bཛྷa")
    }

    @Test
    fun `organisation (but not other attributes) must have at least two letters`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=B, L=New York, C=DE, OU=Org Unit, CN=Service Name")
        }
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=, L=New York, C=DE, OU=Org Unit, CN=Service Name")
        }
        // doesn't throw
        validateLocalityAndOrganisationalUnitAndCommonName("B")
        validateLocalityAndOrganisationalUnitAndCommonName("")
    }

    @Test
    fun `accepts attributes starting with lower case letter`() {
        MemberX500Name_NoUse.parse("O=bank A, L=New York, C=DE, OU=Org Unit, CN=Service Name")
        validateLocalityAndOrganisationalUnitAndCommonName("bank")
    }

    @Test
    fun `accepts attributes starting with numeric character`() {
        MemberX500Name_NoUse.parse("O=8Bank A, L=New York, C=DE, OU=Org Unit, CN=Service Name")
        validateLocalityAndOrganisationalUnitAndCommonName("8bank")
    }

    @Test
    fun `accepts attributes with leading whitespace`() {
        MemberX500Name_NoUse.parse("O= VALID, L=VALID, C=DE, OU=VALID, CN=VALID")
        validateLocalityAndOrganisationalUnitAndCommonName(" VALID")
    }

    @Test
    fun `accepts attributes with trailing whitespace`() {
        MemberX500Name_NoUse.parse("O=VALID , L=VALID, C=DE, OU=VALID, CN=VALID")
        validateLocalityAndOrganisationalUnitAndCommonName("VALID ")
    }

    @Test
    fun `rejects attributes with comma`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=IN,VALID, L=VALID, C=DE, OU=VALID, CN=VALID")
        }
        checkLocalityAndOrganisationalUnitAndCommonNameReject("IN,VALID")
    }

    @Test
    fun `accepts org with equals sign`() {
        MemberX500Name_NoUse.parse("O=IN=VALID, L=VALID, C=DE, OU=VALID, CN=VALID")
    }

    @Test
    fun `accepts organisation with dollar sign`() {
        MemberX500Name_NoUse.parse("O=VA\$LID, L=VALID, C=DE, OU=VALID, CN=VALID")
        validateLocalityAndOrganisationalUnitAndCommonName("VA\$LID")
    }

    @Test
    fun `rejects attributes with double quotation mark`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=IN\"VALID, L=VALID, C=DE, OU=VALID, CN=VALID")
        }
        checkLocalityAndOrganisationalUnitAndCommonNameReject("IN\"VALID")
    }

    @Test
    fun `accepts organisation with single quotation mark`() {
        MemberX500Name_NoUse.parse("O=VA'LID, L=VALID, C=DE, OU=VALID, CN=VALID")
        validateLocalityAndOrganisationalUnitAndCommonName("VA'LID")
    }

    @Test
    fun `rejects organisation with backslash`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=IN\\VALID, L=VALID, C=DE, OU=VALID, CN=VALID")
        }
        checkLocalityAndOrganisationalUnitAndCommonNameReject("IN\\VALID")
    }

    @Test
    fun `rejects double spacing only in the organisation attribute`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=IN  VALID , L=VALID, C=DE, OU=VALID, CN=VALID")
        }
        validateLocalityAndOrganisationalUnitAndCommonName("VA  LID")
    }

    @Test
    fun `rejects organisation (but not other attributes) containing the null character`() {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=IN${Character.MIN_VALUE}VALID , L=VALID, C=DE, OU=VALID, CN=VALID")
        }
        validateLocalityAndOrganisationalUnitAndCommonName("VA${Character.MIN_VALUE}LID")
    }

    @Test
    fun `create MemberX500Name_NoUse without organisationUnit and state`() {
        val member = MemberX500Name_NoUse(commonName, organisation, locality, country)
        Assertions.assertEquals(commonName, member.commonName)
        Assertions.assertNull(member.organisationUnit)
        Assertions.assertEquals(organisation, member.organisation)
        Assertions.assertEquals(locality, member.locality)
        Assertions.assertNull(member.state)
        Assertions.assertEquals(country, member.country)
    }

    @Test
    fun orderedAvas() {
        val name = X500Principal("O=Bank A, L=New York, C=US, OU=Org Unit, CN=Service Name")
        val encoded = name.encoded
        assertTrue(encoded.isNotEmpty())
    }

    private fun checkLocalityAndOrganisationalUnitAndCommonNameReject(invalid: String) {
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=VALID, L=${invalid}, C=DE, OU=VALID, CN=VALID")
        }
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=VALID, L=VALID, C=DE, OU=${invalid}, CN=VALID")
        }
        assertFailsWith(IllegalArgumentException::class) {
            MemberX500Name_NoUse.parse("O=VALID, L=VALID, C=DE, OU=VALID, CN=${invalid}")
        }
    }

    private fun validateLocalityAndOrganisationalUnitAndCommonName(valid: String) {
        MemberX500Name_NoUse.parse("O=VALID, L=${valid}, C=DE, OU=VALID, CN=VALID")
        MemberX500Name_NoUse.parse("O=VALID, L=VALID, C=DE, OU=${valid}, CN=VALID")
        MemberX500Name_NoUse.parse("O=VALID, L=VALID, C=DE, OU=VALID, CN=${valid}")
    }
}