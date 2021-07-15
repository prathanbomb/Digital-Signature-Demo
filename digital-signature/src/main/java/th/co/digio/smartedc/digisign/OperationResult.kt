package th.co.digio.smartedc.digisign

import java.lang.Exception

internal data class OperationResult(
    var ret: Result,
    var exception: Exception?,
)

internal enum class Result {
    SUCCESS,
    FAILED
}
