package th.co.digio.smartedc.digisign.listener


interface OnSignatureListener {
    fun onPreSign()
    fun onSignSuccess()
    fun onSignatureFailed(exception: Exception)
}