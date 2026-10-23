package app.privacynotes.biometrickey

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

@InvokeArg
class KeyArgs {
    var handle: String? = null
    var reason: String = ""
    var cancelTitle: String? = null
}

@InvokeArg
class DeleteArgs {
    var handle: String = ""
}

/**
 * The bound biometric key on Android.
 *
 * An RSA-2048 key in the Android Keystore whose private half needs a strong
 * biometric for every use (`setUserAuthenticationRequired`, biometric-strong,
 * per use) and survives a finger added or removed while at least one stays
 * (`setInvalidatedByBiometricEnrollment(false)`). Removing the screen lock
 * destroys it. A random 32-byte secret is sealed to the public half, which
 * needs no prompt, and opened through a `BiometricPrompt.CryptoObject`, so the
 * prompt the person passes is what lets the Keystore decrypt: enrollment and
 * unlock each show one prompt. Every enrollment gets a fresh alias, so making
 * a new key never touches a working one.
 *
 * Rejections carry one code, which the web side reads: `unsupported` (said
 * before any prompt: no strong biometric, or the Keystore refused the key),
 * `cancelled`, `gone` (the key is destroyed and never comes back) and `failed`.
 * Spec: ops/docs/plans/biometric-key-binding.md (section 8.2)
 */
@TauriPlugin
class BiometricKeyPlugin(private val activity: Activity) : Plugin(activity) {
    private val worker = Executors.newSingleThreadExecutor()
    // One prompt at a time: a second call while one is up is refused. The
    // value is when the prompt started, so a prompt whose callback never came
    // (its activity torn down) stops blocking the next one after a while.
    private val busy = AtomicLong(0)

    private fun claim(): Boolean {
        val now = System.currentTimeMillis()
        val since = busy.get()
        return (since == 0L || now - since > STALE_PROMPT_MS) && busy.compareAndSet(since, now)
    }

    private fun release() = busy.set(0)

    @Command
    fun create(invoke: Invoke) {
        val args = invoke.parseArgs(KeyArgs::class.java)
        val host = activity as? FragmentActivity ?: return invoke.reject("No activity", UNSUPPORTED)
        if (BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) {
            return invoke.reject("No strong biometric", UNSUPPORTED)
        }
        if (!claim()) return invoke.reject("A prompt is open", CANCELLED)
        worker.execute {
            val alias = ALIAS_PREFIX + hex(random(16))
            val sealed: ByteArray
            val secret = random(SECRET_BYTES)
            val cipher: Cipher
            try {
                generateKey(alias)
                sealed = seal(alias, secret)
                cipher = decryptCipher(privateKey(alias) ?: throw IllegalStateException("no key"))
            } catch (e: Exception) {
                deleteAlias(alias)
                release()
                return@execute invoke.reject("The Keystore refused the key", UNSUPPORTED)
            }
            prompt(host, args, cipher) { result, code ->
                val opened = result?.let { runCatching { it.doFinal(sealed) }.getOrNull() }
                if (opened != null && opened.contentEquals(secret)) {
                    val ret = JSObject()
                    ret.put("handle", "$HANDLE_PREFIX$alias.${hex(sealed)}")
                    ret.put("secret", hex(secret))
                    invoke.resolve(ret)
                } else {
                    deleteAlias(alias)
                    invoke.reject("Not created", if (code == CANCELLED) CANCELLED else FAILED)
                }
            }
        }
    }

    @Command
    fun open(invoke: Invoke) {
        val args = invoke.parseArgs(KeyArgs::class.java)
        val host = activity as? FragmentActivity ?: return invoke.reject("No activity", FAILED)
        val (alias, sealed) = parseHandle(args.handle) ?: return invoke.reject("Bad handle", FAILED)
        // No screen lock: its removal invalidated every key that needs the
        // user, for good. No strong biometric but a screen lock: the key
        // survives (setInvalidatedByBiometricEnrollment(false)) and opens
        // again once a finger is enrolled.
        val keyguard = activity.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        if (keyguard?.isDeviceSecure == false) return invoke.reject("No screen lock", GONE)
        when (BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {}
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> return invoke.reject("No biometric", UNENROLLED)
            else -> return invoke.reject("Biometric unavailable", FAILED)
        }
        if (!claim()) return invoke.reject("A prompt is open", CANCELLED)
        worker.execute {
            val cipher = try {
                val key = privateKey(alias)
                if (key == null) {
                    release()
                    return@execute invoke.reject("No key", GONE)
                }
                decryptCipher(key)
            } catch (e: KeyPermanentlyInvalidatedException) {
                deleteAlias(alias)
                release()
                return@execute invoke.reject("Key invalidated", GONE)
            } catch (e: Exception) {
                // UnrecoverableKeyException included: the Keystore also uses it
                // for a passing service failure, and `gone` removes a door, so
                // only a missing key or KeyPermanentlyInvalidatedException says
                // `gone`.
                release()
                return@execute invoke.reject("Key unusable", FAILED)
            }
            prompt(host, args, cipher) { result, code ->
                val opened = result?.let { runCatching { it.doFinal(sealed) }.getOrNull() }
                if (opened != null && opened.size == SECRET_BYTES) {
                    val ret = JSObject()
                    ret.put("secret", hex(opened))
                    invoke.resolve(ret)
                } else {
                    invoke.reject("Not opened", code ?: FAILED)
                }
            }
        }
    }

    @Command
    fun delete(invoke: Invoke) {
        val args = invoke.parseArgs(DeleteArgs::class.java)
        parseHandle(args.handle)?.let { deleteAlias(it.first) }
        invoke.resolve()
    }

    /**
     * Shows the prompt on the UI thread and hands back the authenticated
     * cipher, or null with the code of the failure. The busy flag is released
     * once the prompt has answered.
     */
    private fun prompt(host: FragmentActivity, args: KeyArgs, cipher: Cipher, done: (Cipher?, String?) -> Unit) {
        val finish = { result: Cipher?, code: String? ->
            release()
            done(result, code)
        }
        host.runOnUiThread {
            // androidx refuses a prompt in an activity that is not in front
            // ("Called after onSaveInstanceState") and then never calls back,
            // which left the lock screen waiting for good. The lock screen
            // mounts while the app is still in the background, so the prompt
            // waits for the activity to come to the front.
            val lifecycle = host.lifecycle
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) && !host.supportFragmentManager.isStateSaved) {
                show(host, args, cipher, finish)
            } else if (lifecycle.currentState == Lifecycle.State.DESTROYED) {
                finish(null, CANCELLED)
            } else {
                lifecycle.addObserver(object : LifecycleEventObserver {
                    override fun onStateChanged(source: androidx.lifecycle.LifecycleOwner, event: Lifecycle.Event) {
                        if (event == Lifecycle.Event.ON_RESUME) {
                            lifecycle.removeObserver(this)
                            show(host, args, cipher, finish)
                        } else if (event == Lifecycle.Event.ON_DESTROY) {
                            lifecycle.removeObserver(this)
                            finish(null, CANCELLED)
                        }
                    }
                })
            }
        }
    }

    private fun show(host: FragmentActivity, args: KeyArgs, cipher: Cipher, finish: (Cipher?, String?) -> Unit) {
        try {
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(args.reason.ifEmpty { " " })
                .setNegativeButtonText(args.cancelTitle?.ifEmpty { null } ?: "Cancel")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(false)
                .build()
            BiometricPrompt(host, ContextCompat.getMainExecutor(host), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authed = result.cryptoObject?.cipher
                    finish(authed, if (authed == null) FAILED else null)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    finish(null, codeFor(errorCode))
                }
                // onAuthenticationFailed (a finger not recognised) keeps the
                // prompt up; the system counts the tries.
            }).authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            finish(null, FAILED)
        }
    }

    private fun codeFor(errorCode: Int): String = when (errorCode) {
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_CANCELED,
        BiometricPrompt.ERROR_TIMEOUT,
        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> CANCELLED
        BiometricPrompt.ERROR_NO_BIOMETRICS -> UNENROLLED
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> GONE
        else -> FAILED
    }

    private fun generateKey(alias: String) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // 0 seconds: every use needs its own prompt. Biometric only, never
            // the device PIN: the app's own PIN and phrase are the fallback.
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        // Below API 30 the default validity of -1 is the same rule: per use,
        // by biometric only.
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE).apply {
            initialize(builder.build())
            generateKeyPair()
        }
    }

    /** Seals with the public half, outside the Keystore, so no prompt is needed. */
    private fun seal(alias: String, secret: ByteArray): ByteArray {
        val certificate = keyStore().getCertificate(alias) ?: throw IllegalStateException("no certificate")
        val public = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(certificate.publicKey.encoded))
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.ENCRYPT_MODE, public, OAEP)
        return cipher.doFinal(secret)
    }

    private fun decryptCipher(key: PrivateKey): Cipher {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, key, OAEP)
        return cipher
    }

    private fun privateKey(alias: String): PrivateKey? = keyStore().getKey(alias, null) as? PrivateKey

    private fun deleteAlias(alias: String) {
        if (!alias.startsWith(ALIAS_PREFIX)) return
        runCatching { keyStore().deleteEntry(alias) }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    /** `ks1.<alias>.<hex ciphertext>`; anything else, or another app's alias, is no handle. */
    private fun parseHandle(handle: String?): Pair<String, ByteArray>? {
        val rest = handle?.removePrefix(HANDLE_PREFIX)?.takeIf { it != handle } ?: return null
        val dot = rest.indexOf('.')
        if (dot <= 0) return null
        val alias = rest.substring(0, dot)
        if (!alias.startsWith(ALIAS_PREFIX)) return null
        val sealed = unhex(rest.substring(dot + 1)) ?: return null
        return if (sealed.isEmpty()) null else alias to sealed
    }

    private fun random(n: Int): ByteArray = ByteArray(n).also { SecureRandom().nextBytes(it) }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun unhex(text: String): ByteArray? {
        if (text.length % 2 != 0) return null
        return try {
            ByteArray(text.length / 2) { i -> text.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        } catch (e: NumberFormatException) {
            null
        }
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PREFIX = "pn-bio-"
        const val HANDLE_PREFIX = "ks1."
        const val SECRET_BYTES = 32
        const val STALE_PROMPT_MS = 180_000L
        const val UNSUPPORTED = "unsupported"
        const val CANCELLED = "cancelled"
        const val GONE = "gone"
        const val UNENROLLED = "unenrolled"
        const val FAILED = "failed"
        // MGF1 with SHA-1: the Keystore takes no other MGF1 digest before API 34.
        val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
    }
}
