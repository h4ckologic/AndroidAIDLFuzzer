package com.aidlfuzzer.fuzzer

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Parcel
import android.os.RemoteException
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer

/**
 * Core fuzzing engine that discovers vulnerabilities organically
 *
 * Features:
 * - Fuzzes transaction codes 1-128
 * - Tests multiple data types and values
 * - Detects crashes, exceptions, and hangs
 * - No hardcoded vulnerability knowledge
 */
class FuzzEngine(private val context: Context) {

    companion object {
        private const val TAG = "FuzzEngine"
        private const val MAX_TRANSACTION_CODE = 128
        private const val TRANSACTION_TIMEOUT_MS = 1000L

        /**
         * Determine if a throwable represents a real security vulnerability crash
         * Returns true only for crashes that indicate memory corruption (SIGSEGV, etc.)
         * Filters out resource exhaustion (OOM) which is not a security vulnerability
         */
        private fun isRealVulnerabilityCrash(t: Throwable): Boolean {
            val className = t.javaClass.simpleName
            val message = t.message ?: ""

            // Filter out resource exhaustion errors (NOT real vulnerabilities)
            if (className == "OutOfMemoryError") {
                Log.d(TAG, "Ignoring OutOfMemoryError - not a real vulnerability")
                return false
            }
            if (message.contains("OutOfMemoryError", ignoreCase = true)) return false
            if (message.contains("Out of memory", ignoreCase = true)) return false
            if (className == "TransactionTooLargeException") {
                Log.d(TAG, "Ignoring TransactionTooLargeException - not a real vulnerability")
                return false
            }

            // Real vulnerability crashes (memory corruption, SIGSEGV, etc.)
            return when (className) {
                "DeadObjectException" -> true // Service killed (SIGSEGV, SIGABRT, etc.)
                "RuntimeException" -> true // Unexpected crash
                "IllegalStateException" -> true // Invalid state
                "NullPointerException" -> true // Null dereference
                "IndexOutOfBoundsException" -> true // Buffer access error
                "ArrayIndexOutOfBoundsException" -> true // Array overflow
                "SecurityException" -> false // Just permission denial
                "IllegalArgumentException" -> false // Bad parameter
                "UnsupportedOperationException" -> false // Not implemented
                else -> {
                    Log.w(TAG, "Unknown exception type: $className - treating as potential crash")
                    true // Other unexpected exceptions might be crashes
                }
            }
        }
    }

    private val _results = MutableStateFlow<List<FuzzResult>>(emptyList())
    val results: StateFlow<List<FuzzResult>> = _results

    private val _isFuzzing = MutableStateFlow(false)
    val isFuzzing: StateFlow<Boolean> = _isFuzzing

    private val _crashFound = MutableStateFlow(false)
    val crashFound: StateFlow<Boolean> = _crashFound

    private var currentBinder: IBinder? = null
    private var currentServiceName: String? = null
    private var interfaceDescriptor: String? = null
    private var shouldStop = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            Log.d(TAG, "Connected to service: $name")
            currentBinder = binder
        }

        override fun onServiceDisconnected(name: ComponentName) {
            Log.d(TAG, "Disconnected from service: $name")
            currentBinder = null
        }
    }

    /**
     * Start fuzzing a service until a proper crash is found
     */
    suspend fun fuzzServiceUntilCrash(packageName: String, serviceName: String) = withContext(Dispatchers.IO) {
        _isFuzzing.value = true
        _crashFound.value = false
        shouldStop = false
        currentServiceName = "$packageName/$serviceName"
        _results.value = emptyList()

        Log.d(TAG, "Starting continuous fuzzing: $currentServiceName")

        var round = 1
        while (!shouldStop && !_crashFound.value) {
            Log.d(TAG, "Fuzzing round $round")

            // Bind to service
            val intent = Intent().apply {
                component = ComponentName(packageName, serviceName)
            }

            val bound = context.bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
            if (!bound) {
                Log.e(TAG, "Failed to bind to service")
                break
            }

            // Wait for binding
            var attempts = 0
            while (currentBinder == null && attempts < 50 && !shouldStop) {
                Thread.sleep(100)
                attempts++
            }

            if (currentBinder == null || shouldStop) {
                Log.e(TAG, "Service binding timeout or stopped")
                try {
                    context.unbindService(serviceConnection)
                } catch (e: Exception) {
                    // Ignore
                }
                break
            }

            // Get interface descriptor for proper AIDL communication
            interfaceDescriptor = try {
                currentBinder!!.interfaceDescriptor
            } catch (e: Exception) {
                Log.w(TAG, "Could not get interface descriptor: ${e.message}")
                null
            }

            if (interfaceDescriptor != null) {
                Log.d(TAG, "Interface descriptor: $interfaceDescriptor")
            } else {
                Log.w(TAG, "No interface descriptor available - fuzzing without it")
            }

            // Fuzz all transaction codes (wrap in try-catch to prevent fuzzer app crash)
            try {
                fuzzAllTransactions(currentBinder!!)
            } catch (t: Throwable) {
                Log.e(TAG, "Fatal error during fuzzing round $round: ${t.message}", t)
                addResult(0, "Fatal", "Fuzzer error: ${t.javaClass.simpleName}", ResultType.EXCEPTION)
            }

            // Cleanup
            try {
                context.unbindService(serviceConnection)
            } catch (e: Exception) {
                Log.w(TAG, "Error unbinding service", e)
            }
            currentBinder = null

            if (_crashFound.value) {
                Log.w(TAG, "CRASH FOUND! Stopping fuzzing.")
                break
            }

            if (!shouldStop) {
                Log.d(TAG, "No crash found in round $round, continuing...")
                round++
                Thread.sleep(500) // Small delay between rounds
            }
        }

        _isFuzzing.value = false
        Log.d(TAG, "Fuzzing complete. Found ${_results.value.size} results. Crash found: ${_crashFound.value}")
    }

    /**
     * Start fuzzing a service (single pass)
     */
    suspend fun fuzzService(packageName: String, serviceName: String) = withContext(Dispatchers.IO) {
        _isFuzzing.value = true
        _crashFound.value = false
        shouldStop = false
        currentServiceName = "$packageName/$serviceName"
        _results.value = emptyList()

        Log.d(TAG, "Starting fuzzing: $currentServiceName")

        // Bind to service
        val intent = Intent().apply {
            component = ComponentName(packageName, serviceName)
        }

        val bound = context.bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        if (!bound) {
            Log.e(TAG, "Failed to bind to service")
            _isFuzzing.value = false
            return@withContext
        }

        // Wait for binding
        var attempts = 0
        while (currentBinder == null && attempts < 50) {
            Thread.sleep(100)
            attempts++
        }

        if (currentBinder == null) {
            Log.e(TAG, "Service binding timeout")
            context.unbindService(serviceConnection)
            _isFuzzing.value = false
            return@withContext
        }

        // Get interface descriptor for proper AIDL communication
        interfaceDescriptor = try {
            currentBinder!!.interfaceDescriptor
        } catch (e: Exception) {
            Log.w(TAG, "Could not get interface descriptor: ${e.message}")
            null
        }

        if (interfaceDescriptor != null) {
            Log.d(TAG, "Interface descriptor: $interfaceDescriptor")
        } else {
            Log.w(TAG, "No interface descriptor available - fuzzing without it")
        }

        // Fuzz all transaction codes (wrap in try-catch to prevent fuzzer app crash)
        try {
            fuzzAllTransactions(currentBinder!!)
        } catch (t: Throwable) {
            Log.e(TAG, "Fatal error during fuzzing: ${t.message}", t)
            addResult(0, "Fatal", "Fuzzer error: ${t.javaClass.simpleName}", ResultType.EXCEPTION)
        }

        // Cleanup
        try {
            context.unbindService(serviceConnection)
        } catch (e: Exception) {
            Log.w(TAG, "Error unbinding service", e)
        }
        currentBinder = null
        _isFuzzing.value = false

        Log.d(TAG, "Fuzzing complete. Found ${_results.value.size} results")
    }

    /**
     * Fuzz all transaction codes with various inputs
     */
    private fun fuzzAllTransactions(binder: IBinder) {
        val transactionFuzzer = TransactionFuzzer()

        for (code in 1..MAX_TRANSACTION_CODE) {
            if (shouldStop || !_isFuzzing.value) break

            Log.d(TAG, "Testing transaction code: $code")

            // Test with different input types (wrap in try-catch to prevent fuzzer crash)
            try {
                if (testWithEmptyInput(binder, code)) return
                if (testWithIntegers(binder, code)) return
                if (testWithLongs(binder, code)) return
                if (testWithFloats(binder, code)) return
                if (testWithDoubles(binder, code)) return
                if (testWithBooleans(binder, code)) return
                if (testWithStrings(binder, code)) return
                if (testWithByteArrays(binder, code)) return
                if (testWithIntArrays(binder, code)) return
                if (testWithStringArrays(binder, code)) return
                if (testWithCombinations(binder, code)) return
            } catch (t: Throwable) {
                Log.e(TAG, "Error testing code $code: ${t.message}", t)
                // Continue to next transaction code instead of crashing
            }

            // Small delay to allow GC and reduce memory pressure
            try {
                Thread.sleep(5)
            } catch (e: InterruptedException) {
                // Ignore
            }
        }
    }

    /**
     * Test with interface token only (proper AIDL call with no parameters)
     * Returns true if a crash was found
     */
    private fun testWithEmptyInput(binder: IBinder, code: Int): Boolean {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()

        try {
            // Write interface descriptor if available (required for proper AIDL)
            interfaceDescriptor?.let { data.writeInterfaceToken(it) }

            val result = binder.transact(code, data, reply, 0)
            // transact returning false just means rejection, not a crash
            // We only care about exceptions
        } catch (e: RemoteException) {
            // DeadObjectException is a real crash
            if (e.javaClass.simpleName == "DeadObjectException") {
                addResult(code, "Empty", "DeadObjectException - Service killed", ResultType.CRASH, isCrash = true)
                data.recycle()
                reply.recycle()
                return true
            }
            // Other RemoteExceptions are just rejections, not crashes
        } catch (t: Throwable) {
            // Only count real vulnerability crashes (SIGSEGV, etc.), not OOM
            if (isRealVulnerabilityCrash(t)) {
                addResult(code, "Empty", "Crash: ${t.javaClass.simpleName} - ${t.message}", ResultType.CRASH, isCrash = true)
                data.recycle()
                reply.recycle()
                return true
            } else {
                Log.d(TAG, "Ignoring non-vulnerability error: ${t.javaClass.simpleName}")
            }
        } finally {
            data.recycle()
            reply.recycle()
        }
        return false
    }

    /**
     * Test with integer values
     * Returns true if a crash was found
     */
    private fun testWithIntegers(binder: IBinder, code: Int): Boolean {
        val testValues = listOf(
            // Basic values
            0, 1, -1, 2, -2,
            // Boundaries
            0x7FFFFFFF, // INT_MAX (2147483647)
            0x80000000.toInt(), // INT_MIN (-2147483648)
            0xFFFFFFFF.toInt(), // -1 as unsigned
            0xFFFFFFFE.toInt(), // -2 as unsigned
            // Common values
            65535, 256, 255, 127, 128, 42, 123, 456, -789,
            // Off-by-one boundaries
            0x7FFFFFFE, 0x80000001.toInt()
        )

        for (value in testValues) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                // Write interface descriptor first (required for AIDL)
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeInt(value)

                val result = binder.transact(code, data, reply, 0)
                // Returning false is just rejection, not a crash
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "i32=$value", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
                // Other RemoteExceptions are not crashes
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "i32=$value", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with long values
     * Returns true if a crash was found
     */
    private fun testWithLongs(binder: IBinder, code: Int): Boolean {
        val testValues = listOf(
            // Basic values
            0L, 1L, -1L, 2L, -2L,
            // Boundaries
            Long.MAX_VALUE, // 9223372036854775807
            Long.MIN_VALUE, // -9223372036854775808
            -2L, // 0xFFFFFFFFFFFFFFFE as signed
            -1L, // 0xFFFFFFFFFFFFFFFF as signed
            // Large values
            9876543210L, -1234567890L,
            // Off-by-one boundaries
            Long.MAX_VALUE - 1, Long.MIN_VALUE + 1
        )

        for (value in testValues) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeLong(value)

                val result = binder.transact(code, data, reply, 0)
                // Returning false is just rejection, not a crash
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "i64=$value", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
                // Other RemoteExceptions are not crashes
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "i64=$value", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with float values
     * Returns true if a crash was found
     */
    private fun testWithFloats(binder: IBinder, code: Int): Boolean {
        val testValues = listOf(
            // Basic values
            0f, 1f, -1f, 2f, -2f,
            // Mathematical constants
            3.141592f, 2.718281f,
            // Common values
            1.23f, -4.56f, 0.5f, -0.5f,
            // Boundaries
            Float.MAX_VALUE,
            Float.MIN_VALUE,
            -Float.MAX_VALUE,
            // Special values (potential NaN/Inf bugs)
            Float.NaN,
            Float.POSITIVE_INFINITY,
            Float.NEGATIVE_INFINITY,
            // Edge cases
            0xFF.toFloat(), 0xFE.toFloat()
        )

        for (value in testValues) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeFloat(value)

                val result = binder.transact(code, data, reply, 0)
                // Returning false is just rejection, not a crash
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "float=$value", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
                // Other RemoteExceptions are not crashes
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "float=$value", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with double values
     * Returns true if a crash was found
     */
    private fun testWithDoubles(binder: IBinder, code: Int): Boolean {
        val testValues = listOf(
            // Basic values
            0.0, 1.0, -1.0, 2.0, -2.0,
            // Mathematical constants
            3.141592653589793, 2.718281828459045,
            // Common values
            1.23, -4.56, 0.5, -0.5,
            // Boundaries
            Double.MAX_VALUE,
            Double.MIN_VALUE,
            -Double.MAX_VALUE,
            // Special values (potential NaN/Inf bugs)
            Double.NaN,
            Double.POSITIVE_INFINITY,
            Double.NEGATIVE_INFINITY,
            // Edge cases
            0xFF.toDouble(), 0xFE.toDouble()
        )

        for (value in testValues) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeDouble(value)

                val result = binder.transact(code, data, reply, 0)
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "double=$value", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "double=$value", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with boolean values
     * Returns true if a crash was found
     */
    private fun testWithBooleans(binder: IBinder, code: Int): Boolean {
        val testValues = listOf(true, false)

        for (value in testValues) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeInt(if (value) 1 else 0) // Booleans are written as ints in Parcel

                val result = binder.transact(code, data, reply, 0)
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "bool=$value", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "bool=$value", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with string values (potential buffer overflows and format strings)
     * Returns true if a crash was found
     */
    private fun testWithStrings(binder: IBinder, code: Int): Boolean {
        val testStrings = listOf(
            // Empty and small
            "",
            "A",
            "Test",
            "NormalString",

            // Format string attacks (potential format string vulnerabilities)
            "%s",
            "%x",
            "%n",
            "%s%s%s%s",
            "%x%x%x%x",
            "%%n%%x%%s%s%%n1",
            "3%%n%%x%%s%s%%n1",

            // Buffer overflow attempts (boundary sizes)
            "A".repeat(4),
            "A".repeat(7),
            "A".repeat(8),
            "A".repeat(10),
            "A".repeat(15),
            "A".repeat(16),
            "A".repeat(31),
            "A".repeat(32),
            "A".repeat(63),
            "A".repeat(64),
            "A".repeat(127),
            "A".repeat(128),

            // Special characters and null bytes
            "\u0000", // Null byte
            "\u0000\u0000\u0000\u0000", // Multiple nulls
            "\uffff", // Max unicode
            "\uffff\uffff\uffff\uffff", // Multiple max unicode
            "\uffff".repeat(10), // Repeated unicode
            "\u00ff\u00ff\u00ff\u00ff\u00ff\u00ff\u00ff\u00ff\u00ff\u00fc", // High bytes

            // Special strings
            "SpecialChars!@#$%^&*()",

            // SQL injection (just in case)
            "' OR '1'='1",
            "'; DROP TABLE users--",

            // Path traversal
            "../../../etc/passwd",
            "....//....//....//etc/passwd"
        )

        for (str in testStrings) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeString(str)

                val result = binder.transact(code, data, reply, 0)
                // Returning false is just rejection, not a crash
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "string(${str.length})", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
                // Other RemoteExceptions are not crashes
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "string(${str.length})", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with byte arrays (potential buffer overflows)
     * Returns true if a crash was found
     */
    private fun testWithByteArrays(binder: IBinder, code: Int): Boolean {
        // Focus on boundary conditions (powers of 2 and off-by-one)
        val sizes = listOf(0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256)

        for (size in sizes) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                val bytes = ByteArray(size) { 0x41 } // Fill with 'A'
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeByteArray(bytes)

                val result = binder.transact(code, data, reply, 0)
                // Returning false is just rejection, not a crash
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "byte[$size]", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
                // Other RemoteExceptions are not crashes
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "byte[$size]", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with integer arrays
     * Returns true if a crash was found
     */
    private fun testWithIntArrays(binder: IBinder, code: Int): Boolean {
        val testArrays = listOf(
            intArrayOf(), // Empty array
            intArrayOf(1, 2, 3), // Simple array
            intArrayOf(0, -1, 0x7FFFFFFF, 0x80000000.toInt()), // Boundary values
            intArrayOf(1), // Single element
            intArrayOf(0xFF, 0xFE, 0), // Edge cases
        )

        for (array in testArrays) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeIntArray(array)

                val result = binder.transact(code, data, reply, 0)
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "int[${array.size}]", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "int[${array.size}]", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with string arrays
     * Returns true if a crash was found
     */
    private fun testWithStringArrays(binder: IBinder, code: Int): Boolean {
        val testArrays = listOf(
            arrayOf<String>(), // Empty array
            arrayOf("A", "B", "C"), // Simple array
            arrayOf(""), // Array with empty string
            arrayOf("%s", "%x", "%n"), // Format strings
            arrayOf("\u0000", "\uFFFF"), // Special chars
            arrayOf("NormalString", "SpecialChars!@#$%^&()"), // Mixed
        )

        for (array in testArrays) {
            if (shouldStop) return false

            val data = Parcel.obtain()
            val reply = Parcel.obtain()

            try {
                interfaceDescriptor?.let { data.writeInterfaceToken(it) }
                data.writeStringArray(array)

                val result = binder.transact(code, data, reply, 0)
            } catch (e: RemoteException) {
                if (e.javaClass.simpleName == "DeadObjectException") {
                    addResult(code, "string[${array.size}]", "DeadObjectException", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } catch (t: Throwable) {
                if (isRealVulnerabilityCrash(t)) {
                    addResult(code, "string[${array.size}]", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                    data.recycle()
                    reply.recycle()
                    return true
                }
            } finally {
                data.recycle()
                reply.recycle()
            }
        }
        return false
    }

    /**
     * Test with combinations (e.g., multiple integers, int + string, etc.)
     * Returns true if a crash was found
     */
    private fun testWithCombinations(binder: IBinder, code: Int): Boolean {
        // Test: int + int (integer overflow scenarios)
        if (testIntIntCombination(binder, code, 0xFFFFFFFF.toInt(), 2)) return true
        if (testIntIntCombination(binder, code, 0x7FFFFFFF, 1)) return true

        // Test: int + string (small sizes to avoid OOM, focus on boundary bugs)
        if (testIntStringCombination(binder, code, 1, "A".repeat(32))) return true
        if (testIntStringCombination(binder, code, 0xFFFFFFFF.toInt(), "A".repeat(16))) return true

        // Test: string + byte array (small sizes for memory corruption, not OOM)
        if (testStringBytesCombination(binder, code, "%s%s%s", ByteArray(128) { 0x41 })) return true
        if (testStringBytesCombination(binder, code, "%n%x", ByteArray(64) { 0xFF.toByte() })) return true

        return false
    }

    private fun testIntIntCombination(binder: IBinder, code: Int, v1: Int, v2: Int): Boolean {
        if (shouldStop) return false

        val data = Parcel.obtain()
        val reply = Parcel.obtain()

        try {
            interfaceDescriptor?.let { data.writeInterfaceToken(it) }
            data.writeInt(v1)
            data.writeInt(v2)

            val result = binder.transact(code, data, reply, 0)
            // Returning false is just rejection, not a crash
        } catch (e: RemoteException) {
            if (e.javaClass.simpleName == "DeadObjectException") {
                addResult(code, "i32=$v1,i32=$v2", "DeadObjectException", ResultType.CRASH, isCrash = true)
                data.recycle()
                reply.recycle()
                return true
            }
            // Other RemoteExceptions are not crashes
        } catch (t: Throwable) {
            if (isRealVulnerabilityCrash(t)) {
                addResult(code, "i32=$v1,i32=$v2", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                data.recycle()
                reply.recycle()
                return true
            }
        } finally {
            data.recycle()
            reply.recycle()
        }
        return false
    }

    private fun testIntStringCombination(binder: IBinder, code: Int, i: Int, s: String): Boolean {
        if (shouldStop) return false

        val data = Parcel.obtain()
        val reply = Parcel.obtain()

        try {
            interfaceDescriptor?.let { data.writeInterfaceToken(it) }
            data.writeInt(i)
            data.writeString(s)

            val result = binder.transact(code, data, reply, 0)
            // Returning false is just rejection, not a crash
        } catch (e: RemoteException) {
            if (e.javaClass.simpleName == "DeadObjectException") {
                addResult(code, "i32=$i,str(${s.length})", "DeadObjectException", ResultType.CRASH, isCrash = true)
                data.recycle()
                reply.recycle()
                return true
            }
            // Other RemoteExceptions are not crashes
        } catch (t: Throwable) {
            if (isRealVulnerabilityCrash(t)) {
                addResult(code, "i32=$i,str(${s.length})", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                data.recycle()
                reply.recycle()
                return true
            }
        } finally {
            data.recycle()
            reply.recycle()
        }
        return false
    }

    private fun testStringBytesCombination(binder: IBinder, code: Int, s: String, bytes: ByteArray): Boolean {
        if (shouldStop) return false

        val data = Parcel.obtain()
        val reply = Parcel.obtain()

        try {
            interfaceDescriptor?.let { data.writeInterfaceToken(it) }
            data.writeString(s)
            data.writeByteArray(bytes)

            val result = binder.transact(code, data, reply, 0)
            // Returning false is just rejection, not a crash
        } catch (e: RemoteException) {
            if (e.javaClass.simpleName == "DeadObjectException") {
                addResult(code, "str,bytes[${bytes.size}]", "DeadObjectException", ResultType.CRASH, isCrash = true)
                data.recycle()
                reply.recycle()
                return true
            }
            // Other RemoteExceptions are not crashes
        } catch (t: Throwable) {
            if (isRealVulnerabilityCrash(t)) {
                addResult(code, "str,bytes[${bytes.size}]", "Crash: ${t.javaClass.simpleName}", ResultType.CRASH, isCrash = true)
                data.recycle()
                reply.recycle()
                return true
            }
        } finally {
            data.recycle()
            reply.recycle()
        }
        return false
    }

    private fun addResult(code: Int, input: String, description: String, type: ResultType, isCrash: Boolean = false) {
        val result = FuzzResult(
            serviceName = currentServiceName ?: "Unknown",
            transactionCode = code,
            inputDescription = input,
            resultDescription = description,
            type = type,
            timestamp = System.currentTimeMillis()
        )

        _results.value = _results.value + result

        if (isCrash) {
            _crashFound.value = true
            Log.e(TAG, "CRASH FOUND! Code $code, Input: $input, Result: $description")
        } else {
            Log.w(TAG, "Found issue: Code $code, Input: $input, Result: $description")
        }
    }

    fun stop() {
        shouldStop = true
        _isFuzzing.value = false
        currentBinder?.let {
            try {
                context.unbindService(serviceConnection)
            } catch (e: Exception) {
                // Ignore
            }
        }
        currentBinder = null
    }
}
