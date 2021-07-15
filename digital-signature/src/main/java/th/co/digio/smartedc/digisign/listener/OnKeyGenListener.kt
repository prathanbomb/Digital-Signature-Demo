package th.co.digio.smartedc.digisign.listener

interface OnKeyGenListener {
    fun onPreGen()
    fun onGenSuccess()
    fun onGenFailed(exception: Exception)
}