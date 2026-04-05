package com.oniimediaworks.meshinfinity

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.contract.ActivityResultContracts
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject

class AndroidVpnChannel(
    private val activity: FlutterActivity,
    messenger: BinaryMessenger
) : MethodChannel.MethodCallHandler {
    companion object {
        private const val METHOD_CHANNEL = "mesh_infinity/android_vpn"
    }

    private val methodChannel = MethodChannel(messenger, METHOD_CHANNEL)
    private var pendingPermissionResult: MethodChannel.Result? = null
    private val vpnPermissionLauncher =
        activity.registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            val granted = result.resultCode == Activity.RESULT_OK
            pendingPermissionResult?.success(granted)
            pendingPermissionResult = null
        }

    init {
        methodChannel.setMethodCallHandler(this)
    }

    fun dispose() {
        methodChannel.setMethodCallHandler(null)
        pendingPermissionResult = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isPermissionGranted" -> result.success(isPermissionGranted())
            "requestPermission" -> requestPermission(result)
            "applyPolicy" -> applyPolicy(call, result)
            "getState" -> result.success(AndroidVpnPolicyStore.snapshot(activity))
            else -> result.notImplemented()
        }
    }

    private fun isPermissionGranted(): Boolean {
        return VpnService.prepare(activity) == null
    }

    private fun requestPermission(result: MethodChannel.Result) {
        if (isPermissionGranted()) {
            result.success(true)
            return
        }
        if (pendingPermissionResult != null) {
            result.error("busy", "VPN permission request already in progress", null)
            return
        }
        val intent: Intent = VpnService.prepare(activity)
            ?: run {
                result.success(true)
                return
            }
        pendingPermissionResult = result
        vpnPermissionLauncher.launch(intent)
    }

    private fun applyPolicy(call: MethodCall, result: MethodChannel.Result) {
        val policyJson = call.argument<String>("policy_json")
        if (policyJson.isNullOrBlank()) {
            result.error("invalid_policy", "Missing policy_json", null)
            return
        }
        if (!isPermissionGranted()) {
            val enabled = JSONObject(policyJson).optBoolean("enabled", false)
            if (enabled) {
                result.error("permission_required", "VPN permission has not been granted", null)
                return
            }
        }
        val applied = AndroidAppConnectorVpnService.applyPolicy(activity, policyJson)
        result.success(applied)
    }
}
