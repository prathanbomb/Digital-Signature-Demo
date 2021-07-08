package th.co.digio.smartedc.digitalsignaturedemo

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.blankj.utilcode.util.ConvertUtils
import com.blankj.utilcode.util.ToastUtils
import com.itextpdf.kernel.pdf.PdfReader
import com.itextpdf.kernel.pdf.StampingProperties
import com.itextpdf.signatures.*
import com.itextpdf.signatures.PdfSigner.CryptoStandard
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.FileOutputStream
import java.io.IOException
import java.security.*
import java.security.cert.Certificate


class MainActivity : AppCompatActivity() {

    private lateinit var textView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val pdf = ConvertUtils.inputStream2Bytes(resources.assets.open("a00001.pdf"))
        val digitalSignature = sign(getPrivateKey(loadKeyStore()), pdf)
        val hex = ConvertUtils.bytes2HexString(digitalSignature, true)
        textView = findViewById(R.id.tv)
        textView.text = hex
        ToastUtils.showShort(verify(getPublicKey(loadKeyStore()), digitalSignature, pdf).toString())

        val provider = BouncyCastleProvider()
        Security.addProvider(provider)
        val ks = loadKeyStore()
        val alias = ks.aliases().nextElement()
        val pk = getPrivateKey(ks)
        val chain = ks.getCertificateChain(alias)

        sign("", "", chain, pk, DigestAlgorithms.SHA256, provider.name, CryptoStandard.CADES)
    }

    private fun loadKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(resources.openRawResource(R.raw.sender_keystore), "changeit".toCharArray())
        return keyStore
    }

    private fun getPrivateKey(keyStore: KeyStore): PrivateKey {
        return keyStore.getKey("senderKeyPair", "changeit".toCharArray()) as PrivateKey
    }

    private fun getPublicKey(keyStore: KeyStore): PublicKey {
        return keyStore.getCertificate("senderKeyPair").publicKey
    }

    private fun getSignature(): Signature {
        return Signature.getInstance("SHA256withRSA")
    }

    private fun sign(privateKey: PrivateKey, messageByteArray: ByteArray): ByteArray {
        val signature = getSignature()
        signature.initSign(privateKey)
        signature.update(messageByteArray)
        return signature.sign()
    }

    private fun verify(publicKey: PublicKey, signatureByteArray: ByteArray, messageByteArray: ByteArray): Boolean {
        val signature = getSignature()
        signature.initVerify(publicKey)
        signature.update(messageByteArray)
        return signature.verify(signatureByteArray)
    }

    @Throws(GeneralSecurityException::class, IOException::class)
    fun sign(
        src: String?,
        dest: String?,
        chain: Array<Certificate?>?,
        pk: PrivateKey?,
        digestAlgorithm: String?,
        provider: String?,
        signatureType: CryptoStandard?
    ) {
        val reader = PdfReader(src)
        val signer = PdfSigner(reader, FileOutputStream(dest), StampingProperties())
        signer.fieldName = "sig"
        val pks: IExternalSignature = PrivateKeySignature(pk, digestAlgorithm, provider)
        val digest: IExternalDigest = BouncyCastleDigest()

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, signatureType)
    }

}