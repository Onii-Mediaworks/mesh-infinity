package com.oniimediaworks.meshinfinity

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import org.json.JSONObject

class AndroidAppConnectorVpnService : VpnService() {
    companion object {
        private const val CHANNEL_ID = "mesh_infinity_app_connector_vpn"
        private const val NOTIFICATION_ID = 4102

        fun applyPolicy(context: Context, policyJson: String): Boolean {
            AndroidVpnPolicyStore.savePolicy(context, policyJson)
            val policy = JSONObject(policyJson)
            return if (policy.optBoolean("enabled", false)) {
                val intent = Intent(context, AndroidAppConnectorVpnService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
                true
            } else {
                stop(context)
                true
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, AndroidAppConnectorVpnService::class.java))
            AndroidVpnPolicyStore.updateRuntimeState(
                context = context,
                active = false,
                lastError = null,
                allowedCount = 0,
                disallowedCount = 0,
            )
        }
    }

    private var tunnelInterface: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        applyStoredPolicy()
        return START_STICKY
    }

    override fun onDestroy() {
        tunnelInterface?.close()
        tunnelInterface = null
        AndroidVpnPolicyStore.updateRuntimeState(
            context = this,
            active = false,
            lastError = null,
            allowedCount = 0,
            disallowedCount = 0,
        )
        super.onDestroy()
    }

    override fun onRevoke() {
        AndroidVpnPolicyStore.updateRuntimeState(
            context = this,
            active = false,
            lastError = "VPN permission revoked",
            allowedCount = 0,
            disallowedCount = 0,
        )
        stopSelf()
        super.onRevoke()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun applyStoredPolicy() {
        val policyJson = AndroidVpnPolicyStore.loadPolicy(this)
        if (policyJson.isNullOrBlank()) {
            AndroidVpnPolicyStore.updateRuntimeState(
                context = this,
                active = false,
                lastError = "No Android VPN policy available",
                allowedCount = 0,
                disallowedCount = 0,
            )
            stopSelf()
            return
        }

        val policy = JSONObject(policyJson)
        if (!policy.optBoolean("enabled", false)) {
            tunnelInterface?.close()
            tunnelInterface = null
            AndroidVpnPolicyStore.updateRuntimeState(
                context = this,
                active = false,
                lastError = null,
                allowedCount = 0,
                disallowedCount = 0,
            )
            stopSelf()
            return
        }

        if (VpnService.prepare(this) != null) {
            AndroidVpnPolicyStore.updateRuntimeState(
                context = this,
                active = false,
                lastError = "VPN permission not granted",
                allowedCount = 0,
                disallowedCount = 0,
            )
            stopSelf()
            return
        }

        val builder = Builder()
            .setSession(policy.optString("sessionName", "Mesh Infinity"))
            .setMtu(policy.optInt("mtu", 1280))

        builder.addAddress("198.18.0.1", 32)
        builder.addAddress("fd00:6d65:7368::1", 128)

        if (policy.optBoolean("requiresFullTunnel", true)) {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        }

        val allowedApps = policy.optJSONArray("allowedApps")
        val disallowedApps = policy.optJSONArray("disallowedApps")
        val appliedAllowed = applyAllowedApps(builder, allowedApps)
        val appliedDisallowed = applyDisallowedApps(builder, disallowedApps)

        tunnelInterface?.close()
        tunnelInterface = builder.establish()

        AndroidVpnPolicyStore.updateRuntimeState(
            context = this,
            active = tunnelInterface != null,
            lastError = if (tunnelInterface == null) {
                "Android VpnService failed to establish the interface"
            } else {
                null
            },
            allowedCount = appliedAllowed,
            disallowedCount = appliedDisallowed,
        )

        if (tunnelInterface == null) {
            stopSelf()
        }
    }

    private fun applyAllowedApps(builder: Builder, apps: org.json.JSONArray?): Int {
        if (apps == null) {
            return 0
        }
        var applied = 0
        for (index in 0 until apps.length()) {
            val appId = apps.optString(index).trim()
            if (appId.isEmpty()) {
                continue
            }
            try {
                builder.addAllowedApplication(appId)
                applied += 1
            } catch (_: Exception) {
            }
        }
        return applied
    }

    private fun applyDisallowedApps(builder: Builder, apps: org.json.JSONArray?): Int {
        if (apps == null) {
            return 0
        }
        var applied = 0
        for (index in 0 until apps.length()) {
            val appId = apps.optString(index).trim()
            if (appId.isEmpty()) {
                continue
            }
            try {
                builder.addDisallowedApplication(appId)
                applied += 1
            } catch (_: Exception) {
            }
        }
        return applied
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Mesh Infinity App Connector",
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.description = "Keeps Android per-app VPN enforcement active."
        channel.setShowBadge(false)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val builder =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(this, CHANNEL_ID)
            } else {
                Notification.Builder(this)
            }
        return builder
            .setContentTitle("Mesh Infinity")
            .setContentText("Applying App Connector routing on Android")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }
}
