package net.corda.v5.membership.identity

import net.corda.v5.base.annotations.CordaSerializable
import net.corda.v5.membership.identity.internal.LegalNameValidator
import java.util.Locale
import javax.naming.directory.BasicAttributes
import javax.naming.ldap.LdapName
import javax.naming.ldap.Rdn
import javax.security.auth.x500.X500Principal

/**
 * X.500 distinguished name data type customised to how Corda uses names. This restricts the attributes to those Corda
 * supports, and requires that organisation, locality and country attributes are specified. See also RFC 4519 for
 * the underlying attribute type definitions.
 *
 * This is the base class for CordaX500Name. Should be used for modules which are below application.
 *
 * @property commonName optional name by the which the entity is usually known. Used only for services (for
 * organisations, the [organisation] property is the name). Corresponds to the "CN" attribute type.
 * @property organisationUnit optional name of a unit within the [organisation]. Corresponds to the "OU" attribute type.
 * @property organisation name of the organisation. Corresponds to the "O" attribute type.
 * @property locality locality of the organisation, typically nearest major city. For distributed services this would be
 * where one of the organisations is based. Corresponds to the "L" attribute type.
 * @property state the full name of the state or province the organisation is based in. Corresponds to the "ST"
 * attribute type.
 * @property country country the organisation is in, as an ISO 3166-1 2-letter country code. Corresponds to the "C"
 * attribute type.
 */
@Suppress("LongParameterList")
@CordaSerializable
open class MemberX500Name(
    val commonName: String?,
    val organisationUnit: String?,
    val organisation: String,
    val locality: String,
    val state: String?,
    val country: String
) {
    constructor(commonName: String, organisation: String, locality: String, country: String) :
            this(
                commonName = commonName,
                organisationUnit = null,
                organisation = organisation,
                locality = locality,
                state = null,
                country = country
            )
    /**
     * @param organisation name of the organisation.
     * @param locality locality of the organisation, typically nearest major city.
     * @param country country the organisation is in, as an ISO 3166-1 2-letter country code.
     */
    constructor(organisation: String, locality: String, country: String) :
            this(null, null, organisation, locality, null, country)

    init {
        // Legal name checks.
        LegalNameValidator.validateOrganization(organisation)
        require(organisation.length < MAX_LENGTH_ORGANISATION) {
            "Organisation attribute (O) must contain less then $MAX_LENGTH_ORGANISATION characters."
        }

        require(country in countryCodes) { "Invalid country code $country" }

//        require(locality.isNotBlank()) {
//            "Locality attribute (L) must not be blank."
//        }
        require(locality.length < MAX_LENGTH_LOCALITY) { "Locality attribute (L) must contain less then $MAX_LENGTH_LOCALITY characters." }

        state?.let {
            require(it.isNotBlank()) {
                "State attribute (ST) if specified then it must be not blank."
            }
            require(it.length < MAX_LENGTH_STATE) { "State attribute (ST) must contain less then $MAX_LENGTH_STATE characters." }
        }

        organisationUnit?.let {
//            require(it.isNotBlank()) {
//                "Organisation unit attribute (OU) if specified then it must be not blank."
//            }
            require(it.length < MAX_LENGTH_ORGANISATION_UNIT) {
                "Organisation Unit attribute (OU) must contain less then $MAX_LENGTH_ORGANISATION_UNIT characters."
            }
        }

        commonName?.let {
//            require(it.isNotBlank()) {
//                "Common name attribute (CN) must not be blank."
//            }
            require(it.length < MAX_LENGTH_COMMON_NAME) {
                "Common Name attribute (CN) must contain less then $MAX_LENGTH_COMMON_NAME characters."
            }
        }
    }

    companion object {
        const val MAX_LENGTH_ORGANISATION = 128
        const val MAX_LENGTH_LOCALITY = 64
        const val MAX_LENGTH_STATE = 64
        const val MAX_LENGTH_ORGANISATION_UNIT = 64
        const val MAX_LENGTH_COMMON_NAME = 64

        const val ATTRIBUTE_COMMON_NAME = "CN"
        const val ATTRIBUTE_ORGANISATION_UNIT = "OU"
        const val ATTRIBUTE_ORGANISATION = "O"
        const val ATTRIBUTE_LOCALITY = "L"
        const val ATTRIBUTE_STATE = "STATE"
        const val ATTRIBUTE_COUNTRY = "C"

        val supportedAttributes = setOf(
            ATTRIBUTE_COMMON_NAME,
            ATTRIBUTE_ORGANISATION_UNIT,
            ATTRIBUTE_ORGANISATION,
            ATTRIBUTE_LOCALITY,
            ATTRIBUTE_STATE,
            ATTRIBUTE_COUNTRY
        )

        private const val unspecifiedCountry = "ZZ"

        @Suppress("SpreadOperator")
        private val countryCodes: Set<String> = setOf(*Locale.getISOCountries(), unspecifiedCountry)

        @JvmStatic
        fun build(principal: X500Principal): MemberX500Name = parse(principal.toString())

        @JvmStatic
        fun parse(name: String): MemberX500Name {
            // X500Principal is used to sanitise the syntax as the LdapName will let through such string as
            // "O=VALID, L=IN,VALID, C=DE, OU=VALID, CN=VALID" where the (L) have to be escaped
            val attrsMap = LdapName(X500Principal(name).toString()).toAttributesMap(supportedAttributes)
            val CN = attrsMap[ATTRIBUTE_COMMON_NAME]
            val OU = attrsMap[ATTRIBUTE_ORGANISATION_UNIT]
            val O = requireNotNull(attrsMap[ATTRIBUTE_ORGANISATION]) { "Corda X.500 names must include an O attribute" }
            val L = requireNotNull(attrsMap[ATTRIBUTE_LOCALITY]) { "Corda X.500 names must include an L attribute" }
            val ST = attrsMap[ATTRIBUTE_STATE]
            val C = requireNotNull(attrsMap[ATTRIBUTE_COUNTRY]) { "Corda X.500 names must include an C attribute" }
            return MemberX500Name(CN, OU, O, L, ST, C)
        }

        /**
         * Transforms the X500Principal to the attributes map.
         *
         * @param supportedAttributes list of supported attributes. If empty, it accepts all the attributes.
         *
         * @return attributes map for this principal
         * @throws IllegalArgumentException if this principal consists of duplicated attributes or the attribute is not supported.
         *
         */
        private fun LdapName.toAttributesMap(supportedAttributes: Set<String> = emptySet()): Map<String, String> {
            val result = mutableMapOf<String, String>()
            rdns.forEach { rdn ->
                rdn.toAttributes().all.asSequence().forEach {
                    require(it.size() == 1) {
                        "Attributes ${it.id} have to contain only single value."
                    }
                    val value = it.get(0)
                    require(value is String) {
                        "Attribute's ${it.id} value must be a string"
                    }
                    require(!result.containsKey(it.id)) {
                        "Duplicate attribute ${it.id}"
                    }
                    result[it.id] = value
                }
            }
            if (supportedAttributes.isNotEmpty()) {
                (result.keys - supportedAttributes).let { unsupported ->
                    require(unsupported.isEmpty()) {
                        "The following attribute${if (unsupported.size > 1) "s are" else " is"} not supported in Corda: " +
                                unsupported.map { it }
                    }
                }
            }
            return result
        }
    }

    /** Return the [X500Principal] equivalent of this name. */
    val x500Principal: X500Principal by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val rdns = mutableListOf<Rdn>().apply {
            add(Rdn(BasicAttributes(ATTRIBUTE_COUNTRY, country)))
            state?.let { add(Rdn(BasicAttributes(ATTRIBUTE_STATE, it)))
            }
            add(Rdn(BasicAttributes(ATTRIBUTE_LOCALITY, locality)))
            add(Rdn(BasicAttributes(ATTRIBUTE_ORGANISATION, organisation)))
            organisationUnit?.let {
                add(Rdn(BasicAttributes(ATTRIBUTE_ORGANISATION_UNIT, it)))
            }
            commonName?.let {
                add(Rdn(BasicAttributes(ATTRIBUTE_COMMON_NAME, it)))
            }
        }
        X500Principal(LdapName(rdns).toString())
    }

    override fun toString(): String = x500Principal.toString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as MemberX500Name

        if (commonName != other.commonName) return false
        if (organisationUnit != other.organisationUnit) return false
        if (organisation != other.organisation) return false
        if (locality != other.locality) return false
        if (state != other.state) return false
        if (country != other.country) return false

        return true
    }

    override fun hashCode(): Int {
        var result = commonName?.hashCode() ?: 0
        result = 31 * result + (organisationUnit?.hashCode() ?: 0)
        result = 31 * result + organisation.hashCode()
        result = 31 * result + locality.hashCode()
        result = 31 * result + (state?.hashCode() ?: 0)
        result = 31 * result + country.hashCode()
        return result
    }
}
