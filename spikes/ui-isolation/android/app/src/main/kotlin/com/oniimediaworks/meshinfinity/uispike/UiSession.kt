package com.oniimediaworks.meshinfinity.uispike

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * The UI process's side of the split, started from Application.onCreate in
 * `:ui` before any Activity exists:
 * 1. create the broker and protocol socket pairs;
 * 2. hand one end of each to the core ([UiHostProvider]);
 * 3. lock the process down on the broker socket (unless the run is the baseline);
 * 4. run the escape probes and report them to the core.
 */
object UiSession {
    private const val TAG = "MeshUiSpike"

    /** This run's mode, as the core chose it. */
    var mode: String = "none"
        private set

    /** The lockdown's result: 0 confined, a negative errno, or null when not attempted. */
    var confined: Int? = null
        private set

    /** Each probe's result: 0 = the call succeeded, negative = refused (errno). */
    var probes: Map<String, Int> = emptyMap()
        private set

    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null

    fun start(context: Context) {
        // Both pairs are SOCK_SEQPACKET, which Fibrewall's broker requires.
        val broker = ParcelFileDescriptor.createReliableSocketPair()
        val protocol = ParcelFileDescriptor.createReliableSocketPair()
        val reply = try {
            context.contentResolver.call(
                Uri.parse("content://" + UiHostProvider.AUTHORITY), UiHostProvider.METHOD_ATTACH, null,
                Bundle().apply {
                    putParcelable(UiHostProvider.KEY_BROKER, broker[0])
                    putParcelable(UiHostProvider.KEY_PROTOCOL, protocol[0])
                },
            )
        } finally {
            // The core holds its own copies now.
            broker[0].close()
            protocol[0].close()
        }
        if (reply == null) {
            // No core: the UI must not run unconfined by accident.
            Log.e(TAG, "core refused the attach; stopping the UI process")
            Process.killProcess(Process.myPid())
            return
        }
        mode = reply.getString(UiHostProvider.KEY_MODE) ?: SpikeMode.ENFORCE

        // Lock down before anything else runs in this process.
        if (mode == SpikeMode.OFF) {
            broker[1].close()
        } else {
            confined = NativeSandbox.lockdown0(broker[1].detachFd(), UiPolicy.OWN_OPENS, mode == SpikeMode.LEARN)
            if (confined != 0 && mode == SpikeMode.ENFORCE) {
                Log.e(TAG, "lockdown failed ($confined); stopping the UI process")
                Process.killProcess(Process.myPid())
                return
            }
        }
        input = FileInputStream(protocol[1].fileDescriptor)
        output = FileOutputStream(protocol[1].fileDescriptor)

        // What a compromised UI would try: the core's files, network, the core's memory.
        val core_pid = reply.getInt(UiHostProvider.KEY_CORE_PID)
        val secret = reply.getString(UiHostProvider.KEY_SECRET) ?: ""
        probes = linkedMapOf(
            "open_core_secret" to NativeSandbox.probeOpen(secret),
            "open_core_proc_mem" to NativeSandbox.probeOpen("/proc/$core_pid/mem"),
            "open_core_proc_maps" to NativeSandbox.probeOpen("/proc/$core_pid/maps"),
            "open_app_data_dir" to NativeSandbox.probeOpen(context.applicationInfo.dataDir),
            "inet_socket" to NativeSandbox.probeInetSocket(),
            "ptrace_core" to NativeSandbox.probePtrace(core_pid),
            "signal_core" to NativeSandbox.probeSignal(core_pid),
            "exec" to NativeSandbox.probeExec(),
            "ping_core" to if (request("ping") == "pong") 0 else -1,
        )
        send("report " + report(core_pid))
    }

    /** One request and its reply over the protocol socket. */
    @Synchronized
    fun request(message: String): String? {
        send(message)
        val buffer = ByteArray(64 * 1024)
        val length = input?.read(buffer) ?: return null
        return if (length > 0) String(buffer, 0, length, Charsets.UTF_8) else null
    }

    private fun send(message: String) {
        output?.write(message.toByteArray(Charsets.UTF_8))
    }

    private fun report(core_pid: Int): String = JSONObject().apply {
        put("mode", mode)
        put("confined", confined ?: JSONObject.NULL)
        put("sdk", Build.VERSION.SDK_INT)
        put("ui_pid", Process.myPid())
        put("core_pid", core_pid)
        put("probes", JSONObject(probes as Map<*, *>))
    }.toString()
}
