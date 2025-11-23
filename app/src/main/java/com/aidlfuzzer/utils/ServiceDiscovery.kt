package com.aidlfuzzer.utils

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.util.Log

/**
 * Discovers exported services in installed packages
 */
class ServiceDiscovery(private val context: Context) {

    companion object {
        private const val TAG = "ServiceDiscovery"
    }

    data class ExportedService(
        val packageName: String,
        val serviceName: String,
        val fullName: String
    )

    /**
     * Find all exported services across all installed packages
     */
    fun discoverAllExportedServices(): List<ExportedService> {
        val pm = context.packageManager
        val services = mutableListOf<ExportedService>()

        try {
            val packages = pm.getInstalledPackages(PackageManager.GET_SERVICES)

            for (packageInfo in packages) {
                packageInfo.services?.forEach { serviceInfo ->
                    if (serviceInfo.exported) {
                        services.add(
                            ExportedService(
                                packageName = serviceInfo.packageName,
                                serviceName = serviceInfo.name,
                                fullName = "${serviceInfo.packageName}/${serviceInfo.name}"
                            )
                        )
                    }
                }
            }

            Log.d(TAG, "Found ${services.size} exported services")
        } catch (e: Exception) {
            Log.e(TAG, "Error discovering services", e)
        }

        return services
    }

    /**
     * Find exported services in a specific package
     */
    fun discoverServicesInPackage(packageName: String): List<ExportedService> {
        return discoverAllExportedServices().filter { it.packageName == packageName }
    }
}
