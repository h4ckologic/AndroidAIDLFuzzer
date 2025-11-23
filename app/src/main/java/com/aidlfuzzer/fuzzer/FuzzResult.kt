package com.aidlfuzzer.fuzzer

data class FuzzResult(
    val serviceName: String,
    val transactionCode: Int,
    val inputDescription: String,
    val resultDescription: String,
    val type: ResultType,
    val timestamp: Long
)

enum class ResultType {
    CRASH,
    EXCEPTION,
    TIMEOUT,
    ANOMALY
}
