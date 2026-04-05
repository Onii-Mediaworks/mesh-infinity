package com.oniimediaworks.meshinfinity

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

class AndroidAppCatalogChannel(
    private val activity: FlutterActivity,
    messenger: BinaryMessenger
) : MethodChannel.MethodCallHandler {
    companion object {
        private const val METHOD_CHANNEL = "mesh_infinity/android_app_catalog"
    }

    private val methodChannel = MethodChannel(messenger, METHOD_CHANNEL)

    init {
        methodChannel.setMethodCallHandler(this)
    }

    fun dispose() {
        methodChannel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "list_installed_apps" -> result.success(list_installed_apps())
            else -> result.notImplemented()
        }
    }

    private fun list_installed_apps(): List<Map<String, Any?>> {
        val package_manager = activity.packageManager
        val launcher_intent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
        }
        val resolve_flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PackageManager.ResolveInfoFlags.of(0)
        } else {
            null
        }
        val resolved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            package_manager.queryIntentActivities(launcher_intent, resolve_flags!!)
        } else {
            @Suppress("DEPRECATION")
            package_manager.queryIntentActivities(launcher_intent, 0)
        }
        val seen = linkedSetOf<String>()
        return resolved
            .mapNotNull { info ->
                val activity_info = info.activityInfo ?: return@mapNotNull null
                val package_name = activity_info.packageName ?: return@mapNotNull null
                if (package_name == activity.packageName || !seen.add(package_name)) {
                    return@mapNotNull null
                }
                val app_info = activity_info.applicationInfo ?: return@mapNotNull null
                if (!is_user_facing_app(app_info)) {
                    return@mapNotNull null
                }
                val label = package_manager.getApplicationLabel(app_info)?.toString()?.trim()
                mapOf(
                    "app_id" to package_name,
                    "label" to if (label.isNullOrEmpty()) package_name else label,
                    "is_system_app" to app_info.is_system_app(),
                )
            }
            .sortedWith(
                compareBy<Map<String, Any?>>(
                    { (it["label"] as String?)?.lowercase() ?: "" },
                    { (it["app_id"] as String?)?.lowercase() ?: "" },
                )
            )
    }

    private fun is_user_facing_app(app_info: ApplicationInfo): Boolean {
        val launch_intent = activity.packageManager.getLaunchIntentForPackage(app_info.packageName)
        return launch_intent != null
    }

    private fun ApplicationInfo.is_system_app(): Boolean {
        return (flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
            (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    }
}
