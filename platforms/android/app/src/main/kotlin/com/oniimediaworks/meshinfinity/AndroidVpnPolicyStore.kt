package com.oniimediaworks.meshinfinity

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object AndroidVpnPolicyStore {
    private const val PREFS_NAME = "mesh_infinity_android_vpn"
    private const val KEY_POLICY_JSON = "policy_json"
    private const val KEY_ACTIVE = "active"
    private const val KEY_LAST_ERROR = "last_error"
    private const val KEY_ALLOWED_COUNT = "allowed_count"
    private const val KEY_DISALLOWED_COUNT = "disallowed_count"

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
    ) {
        prefs(context)
            .edit()
            .putBoolean(KEY_ACTIVE, active)
            .putString(KEY_LAST_ERROR, lastError)
            .putInt(KEY_ALLOWED_COUNT, allowedCount)
            .putInt(KEY_DISALLOWED_COUNT, disallowedCount)
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
            "unresolved_selector_rule_count" to policy.optInt("unresolvedSelectorRuleCount", 0),
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
