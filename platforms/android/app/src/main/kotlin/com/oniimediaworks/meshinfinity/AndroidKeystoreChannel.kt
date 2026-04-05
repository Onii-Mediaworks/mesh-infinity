package com.oniimediaworks.meshinfinity

import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

class AndroidKeystoreChannel(
    messenger: BinaryMessenger
) : MethodChannel.MethodCallHandler {
    companion object {
        private const val METHOD_CHANNEL = "mesh_infinity/android_keystore"
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
            "isAvailable" -> result.success(true)
            "wrapKey" -> {
                val input = call.arguments as? ByteArray
                if (input == null) {
                    result.error("invalid_args", "wrapKey expects raw bytes", null)
                    return
                }
                runCatching {
                    KeystoreBridge.wrapKey(input)
                }.onSuccess(result::success)
                    .onFailure { error ->
                        result.error("wrap_failed", error.message, null)
                    }
            }

            "unwrapKey" -> {
                val input = call.arguments as? ByteArray
                if (input == null) {
                    result.error("invalid_args", "unwrapKey expects raw bytes", null)
                    return
                }
                runCatching {
                    KeystoreBridge.unwrapKey(input)
                }.onSuccess(result::success)
                    .onFailure { error ->
                        result.error("unwrap_failed", error.message, null)
                    }
            }

            "deleteKey" -> {
                runCatching {
                    KeystoreBridge.deleteKey()
                }.onSuccess(result::success)
                    .onFailure { error ->
                        result.error("delete_failed", error.message, null)
                    }
            }

            else -> result.notImplemented()
        }
    }
}
