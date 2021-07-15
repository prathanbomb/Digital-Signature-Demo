package th.co.digio.smartedc.digitalsignaturedemo

import android.app.ProgressDialog
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatButton
import com.blankj.utilcode.util.*
import th.co.digio.smartedc.digisign.DigiSignKit
import th.co.digio.smartedc.digisign.KeyStoreInfo
import th.co.digio.smartedc.digisign.listener.OnKeyGenListener
import th.co.digio.smartedc.digisign.listener.OnSignatureListener
import java.security.*
import java.util.*


class MainActivity : AppCompatActivity() {

    private lateinit var genButton: AppCompatButton
    private lateinit var signButton: AppCompatButton
    private lateinit var loadingDialog: ProgressDialog

    private val alias = "1820500103012"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        loadingDialog = ProgressDialog(this)

        genButton = findViewById(R.id.genkey_btn)
        genButton.setOnClickListener {
            DigiSignKit.generateKey(alias, object: OnKeyGenListener {
                override fun onPreGen() {
                    loadingDialog = ProgressDialog.show(this@MainActivity, "Generate Key", "Generating...", true, false)
                }

                override fun onGenSuccess() {
                    loadingDialog.dismiss()
                    ToastUtils.showShort("Success")
                }

                override fun onGenFailed(exception: Exception) {
                    loadingDialog.dismiss()
                    ToastUtils.showShort("Failed")
                }

            })
        }

        signButton = findViewById(R.id.sign_btn)
        signButton.setOnClickListener {
            val inputStream = resources.assets.open("nhom1.pdf")
            FileUtils.createFileByDeleteOldFile(PathUtils.getInternalAppDataPath() + "/nhom1_signed.pdf")
            val outputStream = FileUtils.getFileByPath(PathUtils.getInternalAppDataPath() + "/nhom1_signed.pdf").outputStream()
            val keyStoreInfo = KeyStoreInfo(
                alias,
                "changeit"
            )
            DigiSignKit.sign(inputStream, outputStream, keyStoreInfo, object: OnSignatureListener {
                override fun onPreSign() {
                    loadingDialog = ProgressDialog.show(this@MainActivity, "Sign Document", "Signing...", true, false)
                }

                override fun onSignSuccess() {
                    loadingDialog.dismiss()
                    ToastUtils.showShort("Success")
                }

                override fun onSignatureFailed(exception: Exception) {
                    loadingDialog.dismiss()
                    ToastUtils.showShort("Failed")
                }

            })
        }
    }

}