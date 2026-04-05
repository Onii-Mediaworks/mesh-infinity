package com.oniimediaworks.meshinfinity

import android.content.Context
import android.content.Intent

object AndroidStartupStateStore {
    private const val PREFS_NAME = "mesh_infinity_android_startup"
    private const val KEY_LOCKED_BOOT_COMPLETED = "locked_boot_completed"
    private const val KEY_BOOT_COMPLETED = "boot_completed"
    private const val KEY_USER_UNLOCKED = "user_unlocked"
    private const val KEY_LAST_EVENT = "last_event"
    private const val KEY_LAST_EVENT_AT_MS = "last_event_at_ms"
    private const val KEY_STARTUP_SERVICE_STARTED = "startup_service_started"
    private const val KEY_STARTUP_SERVICE_FOREGROUND = "startup_service_foreground"
    private const val KEY_STARTUP_SERVICE_LAST_START_AT_MS = "startup_service_last_start_at_ms"
    private const val KEY_STARTUP_SERVICE_LAST_STOP_AT_MS = "startup_service_last_stop_at_ms"

    private fun deviceProtectedContext(context: Context): Context {
        return context.createDeviceProtectedStorageContext() ?: context
    }

    private fun prefs(context: Context) =
        deviceProtectedContext(context).getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun recordEvent(context: Context, action: String?) {
        val event = action ?: return
        val nowMs = System.currentTimeMillis()
        val editor = prefs(context).edit()
        when (event) {
            Intent.ACTION_LOCKED_BOOT_COMPLETED -> editor.putBoolean(KEY_LOCKED_BOOT_COMPLETED, true)
            Intent.ACTION_BOOT_COMPLETED -> editor.putBoolean(KEY_BOOT_COMPLETED, true)
            Intent.ACTION_USER_UNLOCKED -> editor.putBoolean(KEY_USER_UNLOCKED, true)
        }
        editor.putString(KEY_LAST_EVENT, event)
        editor.putLong(KEY_LAST_EVENT_AT_MS, nowMs)
        editor.apply()
    }

    fun markStartupServiceStarted(context: Context) {
        val nowMs = System.currentTimeMillis()
        prefs(context)
            .edit()
            .putBoolean(KEY_STARTUP_SERVICE_STARTED, true)
            .putBoolean(KEY_STARTUP_SERVICE_FOREGROUND, true)
            .putLong(KEY_STARTUP_SERVICE_LAST_START_AT_MS, nowMs)
            .apply()
    }

    fun markStartupServiceStopped(context: Context) {
        val nowMs = System.currentTimeMillis()
        prefs(context)
            .edit()
            .putBoolean(KEY_STARTUP_SERVICE_FOREGROUND, false)
            .putLong(KEY_STARTUP_SERVICE_LAST_STOP_AT_MS, nowMs)
            .apply()
    }

    fun snapshot(context: Context): Map<String, Any?> {
        val prefs = prefs(context)
        val lastEventAtMs =
            if (prefs.contains(KEY_LAST_EVENT_AT_MS)) prefs.getLong(KEY_LAST_EVENT_AT_MS, 0L) else null
        val startupServiceLastStartAtMs =
            if (prefs.contains(KEY_STARTUP_SERVICE_LAST_START_AT_MS)) {
                prefs.getLong(KEY_STARTUP_SERVICE_LAST_START_AT_MS, 0L)
            } else {
                null
            }
        val startupServiceLastStopAtMs =
            if (prefs.contains(KEY_STARTUP_SERVICE_LAST_STOP_AT_MS)) {
                prefs.getLong(KEY_STARTUP_SERVICE_LAST_STOP_AT_MS, 0L)
            } else {
                null
            }
        return mapOf(
            "isAndroid" to true,
            "lockedBootCompleted" to prefs.getBoolean(KEY_LOCKED_BOOT_COMPLETED, false),
            "bootCompleted" to prefs.getBoolean(KEY_BOOT_COMPLETED, false),
            "userUnlocked" to prefs.getBoolean(KEY_USER_UNLOCKED, false),
            "directBootAware" to true,
            "lastEvent" to prefs.getString(KEY_LAST_EVENT, null),
            "lastEventAtMs" to lastEventAtMs,
            "startupServiceStarted" to prefs.getBoolean(KEY_STARTUP_SERVICE_STARTED, false),
            "startupServiceForeground" to prefs.getBoolean(KEY_STARTUP_SERVICE_FOREGROUND, false),
            "startupServiceLastStartAtMs" to startupServiceLastStartAtMs,
            "startupServiceLastStopAtMs" to startupServiceLastStopAtMs,
        )
    }
}
