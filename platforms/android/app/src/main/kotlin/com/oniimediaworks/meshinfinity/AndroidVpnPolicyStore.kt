package com.oniimediaworks.meshinfinity

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object AndroidVpnPolicyStore {

    // -----------------------------------------------------------------------
    // App Connector selector evaluation — JNI bridge to the Rust engine
    // -----------------------------------------------------------------------
    //
    // `mi_connector_evaluate` (backend/ffi/lib.rs) walks all active
    // AppConnectorRules in priority order and returns an integer decision:
    //
    //   0 — BLOCK       drop the packet; denylist rule matched
    //   1 — ALLOW_DIRECT bypass the mesh; use the normal IP path
    //   2 — ROUTE_VIA_MESH forward through the active mesh tunnel
    //  -1 — ERROR        invalid arguments (should not happen in production)
    //
    // The `ctxPtr` is the opaque MeshContext pointer kept by NativeLayer1Bridge
    // (see NativeLayer1Bridge.contextPointer).  It is stable for the lifetime
    // of the backend and must not be freed here.

    /** Return value: packet must be dropped. */
    const val ACTION_BLOCK: Int = 0

    /** Return value: packet bypasses the mesh tunnel. */
    const val ACTION_ALLOW_DIRECT: Int = 1

    /** Return value: packet must be forwarded through the mesh tunnel. */
    const val ACTION_ROUTE_VIA_MESH: Int = 2

    /**
     * Evaluate the App Connector selector rules for one connection.
     *
     * @param ctxPtr    Opaque MeshContext pointer (Long) from the Rust backend.
     * @param pkg       Android package name of the originating application,
     *                  e.g. `"com.example.browser"`.
     * @param dstIp     Destination IP address as a dotted-decimal (IPv4) or
     *                  colon-hex (IPv6) string.  Must not be empty.
     * @param dstPort   Destination port (0–65535).
     * @param dstDomain Resolved domain name if available (e.g. from a DNS
     *                  question), or `null` when not available.  Pass `null`
     *                  for all non-DNS packets — the Rust side treats an
     *                  empty/null string as "no domain" and skips
     *                  domain_pattern rules accordingly.
     * @return One of [ACTION_BLOCK], [ACTION_ALLOW_DIRECT], or
     *         [ACTION_ROUTE_VIA_MESH].  Returns [ACTION_ALLOW_DIRECT] on
     *         error so that a bad call never silently blocks traffic.
     */
    fun evaluateConnection(
        ctxPtr: Long,
        pkg: String,
        dstIp: String,
        dstPort: Int,
        dstDomain: String?,
    ): Int {
        // Null/zero pointer means the backend is not yet initialised.
        // Fail open (allow direct) to avoid blocking traffic during startup.
        if (ctxPtr == 0L) return ACTION_ALLOW_DIRECT
        val result = nativeEvaluateConnection(ctxPtr, pkg, dstIp, dstPort, dstDomain ?: "")
        // Treat the error sentinel (-1) as allow-direct to avoid silent drops.
        return if (result < 0) ACTION_ALLOW_DIRECT else result
    }

    /**
     * JNI entry point: maps directly to `mi_connector_evaluate` in
     * `backend/ffi/lib.rs`.
     *
     * The Rust function signature is:
     * ```
     * pub unsafe extern "C" fn mi_connector_evaluate(
     *     ctx:           *mut MeshContext,
     *     package_ptr:   *const c_char,
     *     dst_ip_ptr:    *const c_char,
     *     dst_port:      c_int,
     *     dst_domain_ptr:*const c_char,
     * ) -> c_int
     * ```
     *
     * An empty string for `domain` is treated by the Rust side as "no domain
     * available" — callers should always pass `""` rather than null here
     * because JNI cannot pass nullable primitives to `*const c_char`.
     */
    private external fun nativeEvaluateConnection(
        ctx: Long,
        pkg: String,
        ip: String,
        port: Int,
        domain: String,
    ): Int
    private const val PREFS_NAME = "mesh_infinity_android_vpn"
    private const val KEY_POLICY_JSON = "policy_json"
    private const val KEY_ACTIVE = "active"
    private const val KEY_LAST_ERROR = "last_error"
    private const val KEY_ALLOWED_COUNT = "allowed_count"
    private const val KEY_DISALLOWED_COUNT = "disallowed_count"
    private const val KEY_IP_ROUTE_COUNT = "ip_route_count"
    private const val KEY_UNRESOLVED_SELECTOR_COUNT = "unresolved_selector_count"

    fun savePolicy(context: Context, policyJson: String) {
        prefs(context)
            .edit()
            .putString(KEY_POLICY_JSON, policyJson)
            .apply()
    }

    fun loadPolicy(context: Context): String? = prefs(context).getString(KEY_POLICY_JSON, null)

    fun updateRuntimeState(
        context: Context,
        active: Boolean,
        lastError: String?,
        allowedCount: Int,
        disallowedCount: Int,
        ipRouteCount: Int = 0,
        unresolvedSelectorCount: Int = 0,
    ) {
        prefs(context)
            .edit()
            .putBoolean(KEY_ACTIVE, active)
            .putString(KEY_LAST_ERROR, lastError)
            .putInt(KEY_ALLOWED_COUNT, allowedCount)
            .putInt(KEY_DISALLOWED_COUNT, disallowedCount)
            .putInt(KEY_IP_ROUTE_COUNT, ipRouteCount)
            .putInt(KEY_UNRESOLVED_SELECTOR_COUNT, unresolvedSelectorCount)
            .apply()
    }

    fun snapshot(context: Context): Map<String, Any?> {
        val prefs = prefs(context)
        val policyJson = prefs.getString(KEY_POLICY_JSON, null)
        val policy = if (policyJson.isNullOrBlank()) JSONObject() else JSONObject(policyJson)
        return mapOf(
            "active" to prefs.getBoolean(KEY_ACTIVE, false),
            "last_error" to prefs.getString(KEY_LAST_ERROR, null),
            "allowed_app_count" to prefs.getInt(KEY_ALLOWED_COUNT, 0),
            "disallowed_app_count" to prefs.getInt(KEY_DISALLOWED_COUNT, 0),
            "enabled" to policy.optBoolean("enabled", false),
            "mode" to policy.optString("mode", "off"),
            "ip_route_count" to prefs.getInt(KEY_IP_ROUTE_COUNT, 0),
            "unresolved_selector_count" to prefs.getInt(KEY_UNRESOLVED_SELECTOR_COUNT, 0),
            "allowed_apps" to jsonArrayToList(policy.optJSONArray("allowedApps")),
            "disallowed_apps" to jsonArrayToList(policy.optJSONArray("disallowedApps")),
        )
    }

    private fun jsonArrayToList(array: JSONArray?): List<String> {
        if (array == null) {
            return emptyList()
        }
        val values = mutableListOf<String>()
        for (index in 0 until array.length()) {
            values.add(array.optString(index))
        }
        return values
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}
