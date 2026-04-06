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
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.net.UnknownHostException

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

        // Apply selector-based routing rules (§13.15).
        //
        // IP range rules are enforced via addRoute() — packets destined for
        // those ranges are routed through the VPN tunnel.
        //
        // Domain pattern rules are resolved to IPs at policy apply time and
        // handled as IP routes.  Note: this is best-effort; IPs for a domain
        // can change after the policy is applied.
        //
        // Port-based rules are NOT enforceable via the Android VPN API —
        // VpnService.Builder has no per-port routing API.  These rules are
        // tracked as unresolved in the runtime state so the UI can warn the
        // user that port selectors require a userspace proxy (future work).
        val selectorRules = policy.optJSONArray("selectorRules")
            ?: policy.optJSONArray("rules")
        val selectorCounts = applySelectorRules(builder, selectorRules)

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
            ipRouteCount = selectorCounts.first,
            unresolvedSelectorCount = selectorCounts.second,
        )

        if (tunnelInterface == null) {
            stopSelf()
        }
    }

    // Apply selector-based routing rules to the VPN builder.
    //
    // Returns a pair (ipRoutesApplied, unresolvedCount) where:
    //   ipRoutesApplied  — number of addRoute() calls that succeeded
    //   unresolvedCount  — number of rules that could not be enforced
    //                      (domain resolution failures, port-only rules)
    private fun applySelectorRules(
        builder: Builder,
        rules: JSONArray?,
    ): Pair<Int, Int> {
        if (rules == null) return Pair(0, 0)
        var applied = 0
        var unresolved = 0

        for (i in 0 until rules.length()) {
            val rule = rules.optJSONObject(i) ?: continue
            if (!rule.optBoolean("enabled", true)) continue

            val selector = rule.optJSONObject("app_selector") ?: continue

            // --- IP range rules -----------------------------------------------
            // Selector: { "ip_range": "10.0.0.0/8" }
            // Enforcement: addRoute() to send those packets through the tunnel.
            val ipRange = selector.optString("ip_range", "").trim()
            if (ipRange.isNotEmpty()) {
                val applied1 = applyIpRangeRoute(builder, ipRange)
                if (applied1) applied++ else unresolved++
                continue
            }

            // --- Domain pattern rules -----------------------------------------
            // Selector: { "domain_pattern": "*.example.com" }
            // Enforcement: resolve domain to IPs and add routes.
            // Limitations: wildcard patterns are collapsed to the base domain;
            // IP addresses returned here may change later (no DNS TTL tracking).
            val domain = selector.optString("domain_pattern", "").trim()
            if (domain.isNotEmpty()) {
                val resolved = resolveDomainToRoutes(builder, domain)
                if (resolved > 0) applied += resolved else unresolved++
                continue
            }

            // --- Port-only rules -----------------------------------------------
            // Android VPN API has no port-based routing; mark as unresolved.
            val port = selector.optInt("port", -1)
            if (port > 0) {
                unresolved++
                android.util.Log.d(
                    "AppConnectorVpn",
                    "Port selector ($port) cannot be enforced via Android VPN API " +
                        "— requires userspace proxy (future work, §13.15)"
                )
            }
        }

        return Pair(applied, unresolved)
    }

    // Parse a CIDR string (e.g. "10.0.0.0/8" or "fd00::/8") and call addRoute.
    // Returns true if the route was added, false on any parse error.
    private fun applyIpRangeRoute(builder: Builder, cidr: String): Boolean {
        return try {
            val slash = cidr.indexOf('/')
            val addrStr = if (slash >= 0) cidr.substring(0, slash) else cidr
            val prefix = if (slash >= 0) cidr.substring(slash + 1).toInt() else {
                // No prefix length: derive from address family.
                if (addrStr.contains(':')) 128 else 32
            }
            val addr = InetAddress.getByName(addrStr)
            builder.addRoute(addr, prefix)
            true
        } catch (e: Exception) {
            android.util.Log.w("AppConnectorVpn", "Could not apply IP route $cidr: ${e.message}")
            false
        }
    }

    // Resolve a domain pattern to IPs and add routes for each resolved address.
    // Wildcard patterns (e.g. "*.example.com") are stripped to the base domain.
    // Returns the number of routes added (0 on resolution failure).
    private fun resolveDomainToRoutes(builder: Builder, pattern: String): Int {
        // Strip wildcard prefix: "*.example.com" → "example.com"
        val domain = pattern.trimStart('*', '.')
        if (domain.isEmpty()) return 0

        return try {
            val addresses = InetAddress.getAllByName(domain)
            var count = 0
            for (addr in addresses) {
                try {
                    val prefixLen = if (addr is java.net.Inet6Address) 128 else 32
                    builder.addRoute(addr, prefixLen)
                    count++
                } catch (_: Exception) {
                }
            }
            count
        } catch (_: UnknownHostException) {
            android.util.Log.d("AppConnectorVpn", "Could not resolve domain: $domain")
            0
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
