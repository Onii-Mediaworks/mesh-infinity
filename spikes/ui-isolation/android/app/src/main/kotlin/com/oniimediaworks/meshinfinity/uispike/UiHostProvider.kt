package com.oniimediaworks.meshinfinity.uispike

import android.app.ActivityManager
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.core.os.BundleCompat
import java.io.File

/**
 * The stand-in core's door, in the main process. It runs no Fibrewall code:
 * the broker lives in the warden ([WardenProvider]). Two methods:
 * - [METHOD_ATTACH], from the `:ui` worker: takes the worker's end of the
 *   app channel (served by [CoreStub]) and answers the run's mode and the
 *   core's pid;
 * - [METHOD_GRANT], from the warden: the policy (mode and rules) for one
 *   attached worker. The core is the only authority over grants.
 *
 * Not exported, and each method also checks which of this app's processes
 * is calling.
 */
class UiHostProvider : ContentProvider() {
    /** Workers that attached, by pid; each attaches once and is granted once. */
    private val attached = HashSet<Int>()
    private val granted = HashSet<Int>()

    override fun onCreate(): Boolean {
        // The file the escape probe tries to read: stands in for the vault.
        File(context!!.filesDir, SECRET_NAME).writeText("core secret: never readable from :ui\n")
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val context = context!!
        return when (method) {
            METHOD_ATTACH -> attach(context, extras ?: return null)
            METHOD_GRANT -> grant(context, arg?.toIntOrNull() ?: return null)
            else -> null
        }
    }

    /** The `:ui` worker's attach: serve its app channel. */
    private fun attach(context: Context, extras: Bundle): Bundle? {
        val pid = check_caller(context, ":ui")
        synchronized(attached) { if (!attached.add(pid)) throw SecurityException("process $pid already attached") }
        val protocol = BundleCompat.getParcelable(extras, KEY_PROTOCOL, ParcelFileDescriptor::class.java) ?: return null
        CoreStub.serve(protocol)
        return Bundle().apply {
            putString(KEY_MODE, SpikeMode.read(context))
            putInt(KEY_CORE_PID, Process.myPid())
            putString(KEY_SECRET, File(context.filesDir, SECRET_NAME).absolutePath)
        }
    }

    /** The warden asks for [worker]'s policy: only for an attached worker, and only once. */
    private fun grant(context: Context, worker: Int): Bundle? {
        check_caller(context, ":warden")
        synchronized(attached) { if (worker !in attached) return null }
        synchronized(granted) { if (!granted.add(worker)) throw SecurityException("worker $worker already granted") }
        val rules = UiPolicy.rules(context)
        return Bundle().apply {
            putString(KEY_MODE, SpikeMode.read(context))
            putStringArray(KEY_RULE_PATHS, rules.keys.toTypedArray())
            putIntArray(KEY_RULE_MODES, rules.values.toIntArray())
        }
    }

    /** Refuses anyone but this app's process named [suffix]; returns its pid. */
    private fun check_caller(context: Context, suffix: String): Int {
        if (Binder.getCallingUid() != Process.myUid()) throw SecurityException("not this app")
        val pid = Binder.getCallingPid()
        val manager = context.getSystemService(ActivityManager::class.java)
        val name = manager.runningAppProcesses?.firstOrNull { it.pid == pid }?.processName
        if (name != context.packageName + suffix) throw SecurityException("caller $pid is $name, not $suffix")
        return pid
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    companion object {
        const val AUTHORITY = "com.oniimediaworks.meshinfinity.uispike.host"
        const val METHOD_ATTACH = "attach"
        const val METHOD_GRANT = "grant"
        const val KEY_PROTOCOL = "protocol"
        const val KEY_MODE = "mode"
        const val KEY_CORE_PID = "core_pid"
        const val KEY_SECRET = "secret"
        const val KEY_RULE_PATHS = "rule_paths"
        const val KEY_RULE_MODES = "rule_modes"
        const val SECRET_NAME = "core_secret.txt"
    }
}
