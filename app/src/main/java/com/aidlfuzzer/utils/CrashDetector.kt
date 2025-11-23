package com.aidlfuzzer.utils

import android.os.RemoteException

/**
 * Detects and classifies crashes and anomalies
 */
class CrashDetector {

    fun detectCrash(exception: Exception): CrashType {
        return when (exception) {
            is RemoteException -> CrashType.REMOTE_EXCEPTION
            is SecurityException -> CrashType.SECURITY_EXCEPTION
            is NullPointerException -> CrashType.NULL_POINTER
            is IllegalArgumentException -> CrashType.ILLEGAL_ARGUMENT
            else -> CrashType.UNKNOWN
        }
    }

    enum class CrashType {
        REMOTE_EXCEPTION,
        SECURITY_EXCEPTION,
        NULL_POINTER,
        ILLEGAL_ARGUMENT,
        UNKNOWN
    }
}
