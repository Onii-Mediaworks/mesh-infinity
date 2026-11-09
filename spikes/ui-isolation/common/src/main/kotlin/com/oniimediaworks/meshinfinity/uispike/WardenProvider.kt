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
import android.util.Log
import androidx.core.os.BundleCompat

/**
 * The warden (plans/ui-isolation-and-compose.md §3.0), in its own `:warden`
 * process: it runs the Fibrewall broker for each worker, so no broker code
 * runs in the core. It holds no secrets and decides nothing itself: the
 * worker's policy comes from the core ([UiHostProvider.METHOD_GRANT]).
 *
 * The `:ui` worker calls [METHOD_BROKER] once, before it locks itself down,
 * with the broker end of its socket pair.
 */
class WardenProvider : ContentProvider() {
    /** Workers that already have a broker; a second request is refused. */
    private val served = HashSet<Int>()

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != METHOD_BROKER || extras == null) return null
        val context = context!!
        val worker = check_caller(context)
        val broker = BundleCompat.getParcelable(extras, KEY_BROKER, ParcelFileDescriptor::class.java) ?: return null

        // The core decides the worker's mode and rules; the warden only enforces them.
        val grant = context.contentResolver.call(
            Uri.parse("content://" + UiHostProvider.authority(context)), UiHostProvider.METHOD_GRANT, worker.toString(), null,
        )
        val mode = grant?.getString(UiHostProvider.KEY_MODE)
        if (grant == null || mode == null) {
            broker.close()
            return null
        }
        if (mode != SpikeMode.OFF) {
            val paths = grant.getStringArray(UiHostProvider.KEY_RULE_PATHS) ?: emptyArray()
            val modes = grant.getIntArray(UiHostProvider.KEY_RULE_MODES) ?: IntArray(0)
            val started = NativeSandbox.serve0(broker.detachFd(), paths, modes, mode == SpikeMode.LEARN)
            if (started != 0) {
                Log.e(TAG, "broker did not start: $started")
                return null
            }
        } else {
            broker.close()
        }
        return Bundle().apply {
            putString(UiHostProvider.KEY_MODE, mode)
            putInt(KEY_WARDEN_PID, Process.myPid())
        }
    }

    /** Only this app's `:ui` process, once; returns its pid. */
    private fun check_caller(context: Context): Int {
        if (Binder.getCallingUid() != Process.myUid()) throw SecurityException("not this app")
        val pid = Binder.getCallingPid()
        val manager = context.getSystemService(ActivityManager::class.java)
        val name = manager.runningAppProcesses?.firstOrNull { it.pid == pid }?.processName
        if (name != context.packageName + ":ui") throw SecurityException("caller $pid is $name, not :ui")
        synchronized(served) { if (!served.add(pid)) throw SecurityException("process $pid already has a broker") }
        return pid
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    companion object {
        /** The authority, from the app's id (the manifest uses ${applicationId}.warden). */
        fun authority(context: Context) = context.packageName + ".warden"
        const val METHOD_BROKER = "broker"
        const val KEY_BROKER = "broker"
        const val KEY_WARDEN_PID = "warden_pid"
        private const val TAG = "MeshUiSpike"
    }
}
