package th.co.digio.smartedc.digisign.utils

import com.blankj.utilcode.util.TimeUtils
import com.itextpdf.kernel.geom.Rectangle
import com.itextpdf.kernel.pdf.PdfReader
import com.itextpdf.kernel.pdf.StampingProperties
import com.itextpdf.signatures.*
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.*

internal object SignUtils {

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