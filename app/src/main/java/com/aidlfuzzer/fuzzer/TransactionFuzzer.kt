package com.aidlfuzzer.fuzzer

/**
 * Helper class for generating fuzz inputs
 */
class TransactionFuzzer {

    fun generateIntegerInputs(): List<Int> {
        return listOf(
            0, 1, -1,
            127, 128, 255, 256,
            32767, 32768, 65535, 65536,
            0x7FFFFFFF,
            0x80000000.toInt(),
            0xFFFFFFFF.toInt(),
            0xFFFFFFFE.toInt()
        )
    }

    fun generateStringInputs(): List<String> {
        return listOf(
            "",
            "A",
            "Test",
            "%s", "%x", "%n", "%s%s%s",
            "A".repeat(10),
            "A".repeat(100),
            "A".repeat(1000),
            "\u0000",
            "\uffff"
        )
    }

    fun generateByteArraySizes(): List<Int> {
        return listOf(0, 1, 10, 100, 1000, 10000)
    }
}
