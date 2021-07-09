package th.co.digio.smartedc.digitalsignaturedemo

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatButton
import com.blankj.utilcode.util.FileUtils
import com.blankj.utilcode.util.PathUtils
import com.blankj.utilcode.util.TimeUtils
import com.itextpdf.kernel.geom.Rectangle
import com.itextpdf.kernel.pdf.PdfReader
import com.itextpdf.kernel.pdf.StampingProperties
import com.itextpdf.signatures.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.*
import java.security.cert.Certificate
import java.util.*


class MainActivity : AppCompatActivity() {

    private lateinit var signButton: AppCompatButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        signButton = findViewById(R.id.sign)
        signButton.setOnClickListener {
            val pdfInputStream = resources.assets.open("nhom1.pdf")
            FileUtils.createFileByDeleteOldFile(PathUtils.getInternalAppDataPath() + "/nhom1_signed.pdf")
            val pdfOutputStream = FileUtils.getFileByPath(PathUtils.getInternalAppDataPath() + "/form1_signed.pdf").outputStream()

            val provider = BouncyCastleProvider()
            Security.addProvider(provider)
            val ks = loadKeyStore()
            val alias = ks.aliases().nextElement()
            val pk = getPrivateKey(ks)
            val chain = ks.getCertificateChain(alias)

            sign(
                pdfInputStream,
                pdfOutputStream,
                chain,
                pk,
                DigestAlgorithms.SHA256,
                PdfSigner.CryptoStandard.CADES
            )
        }
    }

    private fun loadKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance("PKCS12")
        val keyPair = KeyPairGenerator.getInstance("PKCS12").genKeyPair()
        keyStore.load(resources.openRawResource(R.raw.sender_keystore), "changeit".toCharArray())
        return keyStore
    }

    private fun getPrivateKey(keyStore: KeyStore): PrivateKey {
        return keyStore.getKey("senderKeyPair", "changeit".toCharArray()) as PrivateKey
    }

    private fun getCertificate(keyStore: KeyStore): Certificate {
        return keyStore.getCertificate("senderKeyPair")
    }

    @Throws(GeneralSecurityException::class, IOException::class)
    fun sign(
        src: InputStream,
        dest: FileOutputStream,
        chain: Array<Certificate>,
        privateKey: PrivateKey,
        digestAlgorithm: String,
        signatureType: PdfSigner.CryptoStandard?
    ) {
        val reader = PdfReader(src)
        val signer = PdfSigner(
            reader,
            dest,
            StampingProperties()
        )
        signer.signDate = dateToCalendar(TimeUtils.millis2Date(1625072400000))

        // Create the signature appearance
        val rect = Rectangle(36F, 648F, 200F, 100F)
        val appearance = signer.signatureAppearance
        appearance
            .setReason("reason")
            .setLocation("location")
            .setPageRect(rect).pageNumber = 1
        signer.fieldName = "sig"

        val pks: IExternalSignature = PrivateKeySignature(privateKey, digestAlgorithm, null)
        val digest: IExternalDigest = BouncyCastleDigest()

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, signatureType)
    }

    private fun dateToCalendar(date: Date): Calendar {
        val calendar = Calendar.getInstance()
        calendar.time = date
        return calendar
    }

}