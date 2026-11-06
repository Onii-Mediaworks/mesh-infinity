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
import java.io.File

/**
 * The stand-in core's door, in the main process. The `:ui` process calls
 * [METHOD_ATTACH] once, before it locks itself down, handing over two
 * sockets it created: the broker end (served here by Fibrewall under the
 * UI policy) and the protocol end (served by [CoreStub]).
 *
 * A provider rather than a service because the call is synchronous, as in
 * Enginehost. It is not exported, and it also checks that the caller is
 * this app's `:ui` process and has not attached before.
 */
class UiHostProvider : ContentProvider() {
    /** Processes that already attached; a second attach is refused. */
    private val attached = HashSet<Int>()

    override fun onCreate(): Boolean {
        // The file the escape probe tries to read: stands in for the vault.
        File(context!!.filesDir, SECRET_NAME).writeText("core secret: never readable from :ui\n")
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != METHOD_ATTACH || extras == null) return null
        val context = context!!
        check_caller(context)

        // The two sockets the UI process created and handed over.
        val broker = BundleCompat.getParcelable(extras, KEY_BROKER, ParcelFileDescriptor::class.java) ?: return null
        val protocol = BundleCompat.getParcelable(extras, KEY_PROTOCOL, ParcelFileDescriptor::class.java)
            ?: return null.also { broker.close() }

        // The run's mode: "off" (no lockdown, the baseline), "learn" or "enforce".
        val mode = SpikeMode.read(context)
        if (mode != SpikeMode.OFF) {
            val rules = UiPolicy.rules(context)
            val served = NativeSandbox.serve0(
                broker.detachFd(), rules.keys.toTypedArray(), rules.values.toIntArray(), mode == SpikeMode.LEARN,
            )
            if (served != 0) {
                Log.e(TAG, "broker did not start: $served")
                protocol.close()
                return null
            }
        } else {
            broker.close()
        }
        CoreStub.serve(protocol)

        return Bundle().apply {
            putString(KEY_MODE, mode)
            putInt(KEY_CORE_PID, Process.myPid())
            putString(KEY_SECRET, File(context.filesDir, SECRET_NAME).absolutePath)
        }
    }

    /** Refuses anyone but this app's `:ui` process, and any second attach. */
    private fun check_caller(context: Context) {
        if (Binder.getCallingUid() != Process.myUid()) throw SecurityException("not this app")
        val pid = Binder.getCallingPid()
        val manager = context.getSystemService(ActivityManager::class.java)
        val name = manager.runningAppProcesses?.firstOrNull { it.pid == pid }?.processName
        if (name != context.packageName + ":ui") throw SecurityException("caller $pid is $name, not :ui")
        synchronized(attached) { if (!attached.add(pid)) throw SecurityException("process $pid already attached") }
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    companion object {
        const val AUTHORITY = "com.oniimediaworks.meshinfinity.uispike.host"
        const val METHOD_ATTACH = "attach"
        const val KEY_BROKER = "broker"
        const val KEY_PROTOCOL = "protocol"
        const val KEY_MODE = "mode"
        const val KEY_CORE_PID = "core_pid"
        const val KEY_SECRET = "secret"
        const val SECRET_NAME = "core_secret.txt"
        private const val TAG = "MeshUiSpike"
    }
}
