package th.co.digio.smartedc.digitalsignaturedemo

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.blankj.utilcode.util.ConvertUtils
import com.blankj.utilcode.util.ToastUtils
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature


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

}