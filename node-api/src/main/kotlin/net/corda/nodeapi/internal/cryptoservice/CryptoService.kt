
package net.corda.nodeapi.internal.cryptoservice

import net.corda.core.DoNotImplement
import net.corda.core.crypto.SignatureScheme
import net.corda.nodeapi.internal.crypto.X509Utilities
import org.bouncycastle.operator.ContentSigner
import java.security.KeyPair
import java.security.PublicKey
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

@DoNotImplement
abstract class CryptoService(private val timeout: Long?) {

    companion object {
        private val executor = Executors.newCachedThreadPool()
    }

    /**
     * Adds a timeout for the given [func].
     * @param timeout The time to wait on the function completing (in milliseconds)
     * @param func The call that we're waiting on
     * @return the return value of the function call
     * @throws TimedCryptoServiceException if we reach the timeout
     */
    private fun <A> withTimeout(timeout: Long?, func: () -> A) : A {
        return if (timeout != null) {
            try {
                executor.invokeAny(listOf(Callable { func.invoke() }), timeout, TimeUnit.MILLISECONDS)
            } catch (e: TimeoutException) {
                throw TimedCryptoServiceException("Timed-out while waiting for $timeout milliseconds")
            }
        } else {
            func.invoke()
        }
    }

    /**
     * Generate and store a new [KeyPair].
     * Note that schemeNumberID is Corda specific. Cross-check with the network operator for supported schemeNumberID
     * and their corresponding signature schemes. The main reason for using schemeNumberID and not algorithm OIDs is
     * because some schemes might not be standardised and thus an official OID might for this scheme not exist yet.
     *
     * Returns the [PublicKey] of the generated [KeyPair].
     */
    fun generateKeyPair(alias: String, scheme: SignatureScheme): PublicKey =
            withTimeout(timeout) { _generateKeyPair(alias, scheme) }
    abstract fun _generateKeyPair(alias: String, scheme: SignatureScheme): PublicKey

    /** Check if this [CryptoService] has a private key entry for the input alias. */
    fun containsKey(alias: String): Boolean =
            withTimeout(timeout) { _containsKey(alias) }
    abstract fun _containsKey(alias: String): Boolean

    /**
     * Returns the [PublicKey] of the input alias or null if it doesn't exist.
     */
    fun getPublicKey(alias: String): PublicKey =
            withTimeout(timeout) { _getPublicKey(alias) }
    abstract fun _getPublicKey(alias: String): PublicKey

    /**
     * Sign a [ByteArray] using the private key identified by the input alias.
     * Returns the signature bytes formatted according to the signature scheme.
     * The signAlgorithm if specified determines the signature scheme used for signing, if
     * not specified then the signature scheme is based on the private key scheme.
     */
    fun sign(alias: String, data: ByteArray, signAlgorithm: String? = null): ByteArray =
            withTimeout(timeout) { _sign(alias, data, signAlgorithm) }
    abstract fun _sign(alias: String, data: ByteArray, signAlgorithm: String? = null): ByteArray

    /**
     * Returns [ContentSigner] for the key identified by the input alias.
     */
    fun getSigner(alias: String): ContentSigner =
            withTimeout(timeout) { _getSigner(alias) }
    abstract fun _getSigner(alias: String): ContentSigner

    /**
     * Returns the [SignatureScheme] that should be used for generating key pairs for the node's legal identity with this [CryptoService].
     */
    open fun defaultIdentitySignatureScheme(): SignatureScheme = X509Utilities.DEFAULT_IDENTITY_SIGNATURE_SCHEME

    /**
     * Returns the [SignatureScheme] that should be used with this [CryptoService] when generating TLS-compatible key pairs.
     */
    open fun defaultTLSSignatureScheme(): SignatureScheme = X509Utilities.DEFAULT_TLS_SIGNATURE_SCHEME
}

open class CryptoServiceException(message: String?, cause: Throwable? = null) : Exception(message, cause)
class TimedCryptoServiceException(message: String?, cause: Throwable? = null) : CryptoServiceException(message, cause)
