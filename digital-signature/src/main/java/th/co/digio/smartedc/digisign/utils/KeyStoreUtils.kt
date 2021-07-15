package th.co.digio.smartedc.digisign.utils

import com.blankj.utilcode.util.FileUtils
import com.blankj.utilcode.util.PathUtils
import com.blankj.utilcode.util.TimeUtils
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.RFC4519Style
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.CertIOException
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.*

internal object KeyStoreUtils {
    /**
     * Generates a PKCS12 keystore including both a symmetric and asymmetric key entry.
     *
     * @param password The password to be set on the keystore and each key entry.
     *
     * @return new keystore
     */
    @Throws(
        KeyStoreException::class,
        NoSuchAlgorithmException::class,
        IOException::class,
        CertificateException::class,
        OperatorCreationException::class
    )
    fun generatePKCS12KeyStore(alias:String, password: String) {
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, password.toCharArray())

        // Create Asymmetric key pair
        val asymmetricKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        val x509Certificate = generateX509Certificate(asymmetricKeys, 10, "CN=Supitsara Prathan")
        val privateKey = KeyStore.PrivateKeyEntry(
            asymmetricKeys.private, arrayOf(x509Certificate)
        )
        val privateKeyPassword: KeyStore.ProtectionParameter =
            KeyStore.PasswordProtection(password.toCharArray())
        // Add asymmetric key to keystore
        keyStore.setEntry(alias, privateKey, privateKeyPassword)
        FileUtils.createFileByDeleteOldFile(PathUtils.getInternalAppDataPath() + "/$alias.p12")
        val fos =
            FileUtils.getFileByPath(PathUtils.getInternalAppDataPath() + "/$alias.p12")
                .outputStream()
        keyStore.store(fos, "changeit".toCharArray())
    }

    /**
     * Generates a self signed certificate.
     *
     * @param keyPair used for signing the certificate
     *
     * @return self-signed X509Certificate
     */
    @Throws(OperatorCreationException::class, CertificateException::class, CertIOException::class)
    private fun generateX509Certificate(keyPair: KeyPair, validity: Int, dn: String): X509Certificate {
        val notBefore = TimeUtils.getNowDate()
        val calendar = Calendar.getInstance()
        calendar.time = notBefore
        calendar.add(Calendar.YEAR, validity)
        val notAfter = TimeUtils.millis2Date(calendar.timeInMillis)
        val contentSigner = JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.private)
        val x500Name = X500Name(RFC4519Style.INSTANCE, dn)
        val certificateBuilder = JcaX509v3CertificateBuilder(
            x500Name,
            BigInteger.valueOf(TimeUtils.getNowDate().time),
            notBefore,
            notAfter,
            x500Name,
            keyPair.public
        ).addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        return JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider())
            .getCertificate(certificateBuilder.build(contentSigner))
    }

    fun loadKeyStore(alias: String, password: String): KeyStore {
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(FileUtils.getFileByPath(PathUtils.getInternalAppDataPath() + "/$alias.p12").inputStream(), password.toCharArray())
        return keyStore
    }

    fun getPrivateKey(keyStore: KeyStore): PrivateKey {
        val alias = keyStore.aliases().nextElement()
        return keyStore.getKey(alias, "changeit".toCharArray()) as PrivateKey
    }

    fun getCertificate(keyStore: KeyStore): Certificate {
        return keyStore.getCertificate("senderKeyPair")
    }
}