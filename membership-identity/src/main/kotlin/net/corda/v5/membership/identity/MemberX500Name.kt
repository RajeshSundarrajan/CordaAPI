@file:Suppress("JAVA_MODULE_DOES_NOT_EXPORT_PACKAGE")

/**
 * We are not allowing escape characters due how the LegalNameValidator is done
 */

package net.corda.v5.membership.identity

import net.corda.v5.base.annotations.CordaSerializable
import net.corda.v5.membership.identity.internal.LegalNameValidator
import sun.security.x509.X500Name
import java.io.IOException
import java.util.Locale
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
    val commonName: String,
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

    init {
        // Legal name checks.
        LegalNameValidator.validateOrganization(organisation)

        require(country in countryCodes) { "Invalid country code $country" }

        require(organisation.length < MAX_LENGTH_ORGANISATION) {
            "Organisation attribute (O) must contain less then $MAX_LENGTH_ORGANISATION characters."
        }
        require(locality.length < MAX_LENGTH_LOCALITY) { "Locality attribute (L) must contain less then $MAX_LENGTH_LOCALITY characters." }

        state?.let { require(it.length < MAX_LENGTH_STATE) { "State attribute (ST) must contain less then $MAX_LENGTH_STATE characters." } }
        organisationUnit?.let {
            require(it.length < MAX_LENGTH_ORGANISATION_UNIT) {
                "Organisation Unit attribute (OU) must contain less then $MAX_LENGTH_ORGANISATION_UNIT characters."
            }
        }
        require(commonName.length < MAX_LENGTH_COMMON_NAME) {
            "Common Name attribute (CN) must contain less then $MAX_LENGTH_COMMON_NAME characters."
        }
    }

    companion object {
        const val MAX_LENGTH_ORGANISATION = 128
        const val MAX_LENGTH_LOCALITY = 64
        const val MAX_LENGTH_STATE = 64
        const val MAX_LENGTH_ORGANISATION_UNIT = 64
        const val MAX_LENGTH_COMMON_NAME = 64

        private const val unspecifiedCountry = "ZZ"
        @Suppress("SpreadOperator")
        private val countryCodes: Set<String> = setOf(*Locale.getISOCountries(), unspecifiedCountry)

        @JvmStatic
        fun build(principal: X500Principal): MemberX500Name {
            val x500Name = X500Name(principal.encoded)
            val CN = requireNotNull(x500Name.commonName) { "Corda X.500 names must include an CN attribute" }
            val OU = x500Name.organizationalUnit
            val O = requireNotNull(x500Name.organization) { "Corda X.500 names must include an O attribute" }
            val L = requireNotNull(x500Name.locality) { "Corda X.500 names must include an L attribute" }
            val ST = x500Name.state
            val C = requireNotNull(x500Name.country) { "Corda X.500 names must include an C attribute" }
            return MemberX500Name(CN, OU, O, L, ST, C)
        }

        @JvmStatic
        fun parse(name: String): MemberX500Name = build(X500Principal(name))
    }

    /** Return the [X500Principal] equivalent of this name. */
    val x500Principal: X500Principal by lazy(LazyThreadSafetyMode.PUBLICATION) {
        X500Principal(toString())
    }

    override fun toString(): String {
        val result = StringBuilder()
        commonName.let {
            result.append("CN=")
            append(result, it)
        }
        organisationUnit?.let {
            result.append(", OU=")
            append(result, it)
        }
        organisation.let {
            result.append(", O=")
            append(result, it)
        }
        locality.let {
            result.append(", L=")
            append(result, it)
        }
        state?.let {
            result.append(", ST=")
            append(result, it)
        }
        country.let {
            result.append(", C=")
            append(result, it)
        }
        return result.toString()
    }

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
        var result = commonName.hashCode()
        result = 31 * result + (organisationUnit?.hashCode() ?: 0)
        result = 31 * result + organisation.hashCode()
        result = 31 * result + locality.hashCode()
        result = 31 * result + (state?.hashCode() ?: 0)
        result = 31 * result + country.hashCode()
        return result
    }

    private fun append(builder: StringBuilder, valStr: String): StringBuilder {
        try {
                var quoteNeeded = false
                val sbuffer = StringBuilder()
                var previousWhite = false
                val escapees = ",+=\n<>#;\\\""

                /*
                 * Special characters (e.g. AVA list separators) cause strings
                 * to need quoting, or at least escaping.  So do leading or
                 * trailing spaces, and multiple internal spaces.
                 */
                val length = valStr.length
                val alreadyQuoted = length > 1 && valStr[0] == '\"' && valStr[length - 1] == '\"'
                for (i in 0 until length) {
                    val c = valStr[i]
                    if (alreadyQuoted && (i == 0 || i == length - 1)) {
                        sbuffer.append(c)
                        continue
                    }
                    if (isPrintableStringChar(c) || escapees.indexOf(c) >= 0) {
                        // quote if leading whitespace or special chars
                        if (!quoteNeeded && (i == 0 && (c == ' ' || c == '\n') || escapees.indexOf(c) >= 0)) {
                            quoteNeeded = true
                        }

                        // quote if multiple internal whitespace
                        if (!(c == ' ' || c == '\n')) {
                            // escape '"' and '\'
                            if (c == '"' || c == '\\') {
                                sbuffer.append('\\')
                            }
                            previousWhite = false
                        } else {
                            if (!quoteNeeded && previousWhite) {
                                quoteNeeded = true
                            }
                            previousWhite = true
                        }
                        sbuffer.append(c)
                    } else {
                        // append non-printable/non-escaped char
                        previousWhite = false
                        sbuffer.append(c)
                    }
                }

                // quote if trailing whitespace
                if (sbuffer.isNotEmpty()) {
                    val trailChar = sbuffer[sbuffer.length - 1]
                    if (trailChar == ' ' || trailChar == '\n') {
                        quoteNeeded = true
                    }
                }
                // Emit the string ... quote it if needed
                // if string is already quoted, don't re-quote
                if (!alreadyQuoted && quoteNeeded) {
                    builder.append('\"')
                        .append(sbuffer)
                        .append('\"')
                } else {
                    builder.append(sbuffer)
                }
        } catch (e: IOException) {
            throw IllegalArgumentException("AVA string conversion")
        }
        return builder
    }

    /**
     * Determine if a character is one of the permissible characters for
     * PrintableString:
     * A-Z, a-z, 0-9, space, apostrophe (39), left and right parentheses,
     * plus sign, comma, hyphen, period, slash, colon, equals sign,
     * and question mark.
     *
     * Characters that are *not* allowed in PrintableString include
     * exclamation point, quotation mark, number sign, dollar sign,
     * percent sign, ampersand, asterisk, semicolon, less than sign,
     * greater than sign, at sign, left and right square brackets,
     * backslash, circumflex (94), underscore, back quote (96),
     * left and right curly brackets, vertical line, tilde,
     * and the control codes (0-31 and 127).
     *
     * This list is based on X.680 (the ASN.1 spec).
     */
    open fun isPrintableStringChar(ch: Char): Boolean {
        return if (ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9') {
            true
        } else {
            when (ch) {
                ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?' -> true
                else -> false
            }
        }
    }
}
