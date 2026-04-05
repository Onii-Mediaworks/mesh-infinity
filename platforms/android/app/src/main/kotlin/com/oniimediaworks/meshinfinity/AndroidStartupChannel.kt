package com.oniimediaworks.meshinfinity

import android.content.Context
import android.os.UserManager
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

class AndroidStartupChannel(
    private val context: Context,
    messenger: BinaryMessenger
) : MethodChannel.MethodCallHandler {
    companion object {
        private const val METHOD_CHANNEL = "mesh_infinity/android_startup"
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
            "getStartupState" -> {
                val snapshot = AndroidStartupStateStore.snapshot(context).toMutableMap()
                val userManager = context.getSystemService(UserManager::class.java)
                snapshot["userUnlocked"] = userManager?.isUserUnlocked ?: true
                result.success(snapshot)
            }
            "ensureStartupService" -> {
                AndroidStartupService.start(context)
                result.success(true)
            }
            else -> result.notImplemented()
        }
    }
}
