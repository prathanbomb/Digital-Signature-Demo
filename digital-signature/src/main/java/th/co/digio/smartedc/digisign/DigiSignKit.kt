package th.co.digio.smartedc.digisign

import android.os.AsyncTask
import com.blankj.utilcode.util.FileUtils
import com.blankj.utilcode.util.PathUtils
import com.itextpdf.signatures.DigestAlgorithms
import com.itextpdf.signatures.PdfSigner
import org.bouncycastle.jce.provider.BouncyCastleProvider
import th.co.digio.smartedc.digisign.listener.OnKeyGenListener
import th.co.digio.smartedc.digisign.listener.OnSignatureListener
import th.co.digio.smartedc.digisign.utils.KeyStoreUtils
import th.co.digio.smartedc.digisign.utils.SignUtils
import java.io.*
import java.security.Security

object DigiSignKit {

    fun generateKey(alias: String, keyGenListener: OnKeyGenListener) {
        val task = object : AsyncTask<Void, Void, OperationResult>() {
            override fun doInBackground(vararg params: Void): OperationResult {
                return try {
                    KeyStoreUtils.generatePKCS12KeyStore(alias, "changeit")
                    OperationResult(Result.SUCCESS, null)
                } catch (e: Exception) {
                    OperationResult(Result.FAILED, e)
                }
            }

            override fun onPreExecute() {
                keyGenListener.onPreGen()
            }

            override fun onPostExecute(result: OperationResult) {
                when(result.ret) {
                    Result.SUCCESS -> {
                        keyGenListener.onGenSuccess()
                    }
                    else -> {
                        keyGenListener.onGenFailed(result.exception!!)
                    }
                }
            }
        }
        task.execute()
    }

    fun sign(filePath: String, outputPath: String, keyStoreInfo: KeyStoreInfo, signatureListener: OnSignatureListener) {
        try {
            val fileInputStream = FileInputStream(File(filePath))
            val outputStream =
                FileUtils.getFileByPath(PathUtils.getInternalAppDataPath() + "/nhom1_signed.pdf")
                    .outputStream()
            sign(fileInputStream, outputStream, keyStoreInfo, signatureListener)
        } catch (e: Exception) {
            signatureListener.onSignatureFailed(e)
        }
    }

    fun sign(inputStream: InputStream, outputStream: FileOutputStream, keyStoreInfo: KeyStoreInfo, signatureListener: OnSignatureListener) {
        val task = object : AsyncTask<Void, Void, OperationResult>() {
            override fun doInBackground(vararg params: Void): OperationResult {
                return try {
                    val provider = BouncyCastleProvider()
                    Security.addProvider(provider)
                    val ks = KeyStoreUtils.loadKeyStore(keyStoreInfo.alias, keyStoreInfo.password)
                    val alias = ks.aliases().nextElement()
                    val pk = KeyStoreUtils.getPrivateKey(ks)
                    val chain = ks.getCertificateChain(alias)

                    SignUtils.sign(
                        inputStream,
                        outputStream,
                        chain,
                        pk,
                        DigestAlgorithms.SHA256,
                        PdfSigner.CryptoStandard.CADES
                    )
                    OperationResult(Result.SUCCESS, null)
                } catch (e: Exception) {
                    OperationResult(Result.FAILED, e)
                }
            }

            override fun onPreExecute() {
                signatureListener.onPreSign()
            }

            override fun onPostExecute(result: OperationResult) {
                when(result.ret) {
                    Result.SUCCESS -> {
                        signatureListener.onSignSuccess()
                    }
                    else -> {
                        signatureListener.onSignatureFailed(result.exception!!)
                    }
                }
            }
        }
        task.execute()
    }
}